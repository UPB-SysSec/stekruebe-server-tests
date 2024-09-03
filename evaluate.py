import itertools
import logging
import os
import ssl
import tempfile
import time
from collections import namedtuple
from contextlib import ExitStack
from dataclasses import dataclass
from enum import Enum, IntEnum
from pathlib import Path
from typing import Any, Optional, TypeVar, Union

import docker as docker_lib
from docker.models.containers import Container
from docker.types import Mount
from pydantic import BaseModel

from util import config
from util.request import HttpsResponse, Remote, request

docker = docker_lib.from_env()

TESTCASES_DIR = Path("testcases")
CERTS_DIR = TESTCASES_DIR / "certs"
SITES_DIR = TESTCASES_DIR / "sites"

TEMP_DIR = None
STARTED_CONTAINER_IDS = set()

T = TypeVar("T")


@dataclass
class DeployedServer:
    ip: str
    container: Container
    temp_files: list[str]

    def teardown(self, exc_type=None, exc_value=None, traceback=None):
        logging.debug(
            "removing container id=%s name=%s (exc_type=%r)", self.container.id, self.container.name, exc_type
        )
        if exc_type is not None:
            # get logs
            logs = self.container.logs(stream=False)
            logging.error(logs)
        self.container.remove(force=True)
        STARTED_CONTAINER_IDS.remove(self.container.id)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.teardown(exc_type, exc_value, traceback)


@dataclass
class vhostTestData:
    remote: Remote
    initial_result: HttpsResponse
    requires_sni: bool
    resumption_working: bool


class RemoteName(Enum):
    UNKNOWN = "unknown"
    TICKET_ISSUER = "ticket issuer"
    RESUMPTION = "resumption"

    @staticmethod
    def from_bodies(received, ticket_issuer_body, resumption_body):
        assert (
            ticket_issuer_body != resumption_body
        ), "Same body for ticket and resumption; should've been caught earlier"
        if received == ticket_issuer_body:
            return RemoteName.TICKET_ISSUER
        elif received == resumption_body:
            return RemoteName.RESUMPTION
        else:
            return RemoteName.UNKNOWN


class ResultSummary(IntEnum):
    GOOD = 0
    LOOK_INTO_THIS = 1
    WARN = 2
    BAD = 3

    def __or__(self, other):
        # bitwise OR should give the worst result
        assert isinstance(other, ResultSummary)
        return max(self, other)


class SingleResult(BaseModel):
    summary: ResultSummary
    ticket_resumed: bool
    body: RemoteName
    response_status_code: int
    response_body: bytes

    @staticmethod
    def from_response(response: HttpsResponse, ticket_issuer: vhostTestData, resumption: vhostTestData):
        summary = None
        body_remote = RemoteName.from_bodies(
            response.body, ticket_issuer.initial_result.body, resumption.initial_result.body
        )

        if not response.session_reused:
            summary = ResultSummary.GOOD
        else:
            # session was reused
            if body_remote == RemoteName.TICKET_ISSUER:
                summary = ResultSummary.GOOD
            elif body_remote == RemoteName.RESUMPTION:
                summary = ResultSummary.BAD
            else:
                summary = ResultSummary.LOOK_INTO_THIS

        return SingleResult(
            ticket_resumed=response.session_reused,
            body=body_remote,
            summary=summary,
            response_status_code=response.response.status,
            response_body=response.body,
        )


class GroupedResult(BaseModel):
    summary: ResultSummary
    details: dict[Any, Union["GroupedResult", SingleResult]]

    @staticmethod
    def from_results(results: dict[Any, Union["GroupedResult", SingleResult]]):
        summary = ResultSummary.GOOD
        for result in results.values():
            summary |= result.summary
        return GroupedResult(summary=summary, details=results)


def setup_server(software_name, testcase_name, software_cfg: config.SoftwareConfig, server_cfg: config.ServerConfig):
    name = f"stekruebe_{software_name}_{testcase_name}_" + "_".join(v.hostname for v in server_cfg.vHosts)

    stek_file = tempfile.NamedTemporaryFile(delete=False, dir=TEMP_DIR, suffix=".stek.key")
    stek_file.write(os.urandom(software_cfg.stek_length))
    stek_file.close()

    config_file = tempfile.NamedTemporaryFile("w", delete=False, dir=TEMP_DIR, suffix=".nginx.conf")
    config_file.write(software_cfg.render_config(server_cfg, "/stek.key"))
    config_file.close()

    mounts = [
        Mount(source=str(CERTS_DIR.absolute()), target="/certs", read_only=True, type="bind"),
        Mount(source=str(SITES_DIR.absolute()), target="/sites", read_only=True, type="bind"),
        Mount(source=stek_file.name, target="/stek.key", read_only=True, type="bind"),
        Mount(source=config_file.name, target=software_cfg.config_path, read_only=True, type="bind"),
    ]
    container = docker.containers.run(software_cfg.image, detach=True, name=name, auto_remove=False, mounts=mounts)
    # except:
    STARTED_CONTAINER_IDS.add(container.id)

    container.reload()
    ip = container.attrs["NetworkSettings"]["IPAddress"]
    assert ip is not None
    logging.debug("started container id=%s name=%s", container.id, name)

    return DeployedServer(ip, container, [stek_file.name, config_file.name])


def precheck_remote(remote: Remote):
    try:
        for _ in range(15):
            try:
                initial_result = request(remote, remote, remote)
                break
            except ConnectionRefusedError:
                time.sleep(0.1)
    except:
        logging.exception("Failed to connect to %s", remote)
        raise

    try:
        request(remote, None, remote)
        requires_sni = False
    except ssl.SSLError:
        requires_sni = True

    resumption_working = True
    r = request(remote, remote, remote, initial_result.session)
    resumption_working = resumption_working and r.session_reused
    # resume twice to ensure we do not have single use tickets
    r = request(remote, remote, remote, initial_result.session)
    resumption_working = resumption_working and r.session_reused
    assert resumption_working, "Resumption did not work"

    return vhostTestData(remote, initial_result, requires_sni, resumption_working)


def _select(remote: Optional[RemoteName], issuer: T, resumption: T) -> T:
    if remote is None:
        return None
    if remote == RemoteName.TICKET_ISSUER:
        return issuer
    elif remote == RemoteName.RESUMPTION:
        return resumption
    else:
        raise ValueError("Unknown remote name")


def _yield_results_group(f):
    def wrapper(*args, **kwargs):
        return GroupedResult.from_results(dict(f(*args, **kwargs)))

    return wrapper


@_yield_results_group
def evaluate_request(domains: dict[str, vhostTestData], sni_name: RemoteName, host_header_name: RemoteName):
    for ticket_issuer_host, resumption_host in itertools.permutations(domains.values(), 2):
        assert ticket_issuer_host != resumption_host, "Same host; should not happen"
        sni = _select(sni_name, ticket_issuer_host.remote, resumption_host.remote)
        host_header = _select(host_header_name, ticket_issuer_host.remote, resumption_host.remote)

        response = request(resumption_host.remote, sni, host_header, ticket_issuer_host.initial_result.session)
        result = SingleResult.from_response(response, ticket_issuer_host, resumption_host)
        yield f"issuer={ticket_issuer_host.remote.hostname}, resumption={resumption_host.remote.hostname}", result


@_yield_results_group
def evaluate_vhosts(domains: dict[str, vhostTestData]):
    for sni_name, host_header_name in itertools.product(
        [RemoteName.TICKET_ISSUER, RemoteName.RESUMPTION, None],
        [RemoteName.TICKET_ISSUER, RemoteName.RESUMPTION],
    ):
        yield f"sni={sni_name}, host={host_header_name}", evaluate_request(domains, sni_name, host_header_name)


def evaluate_test_case(
    software_name: str, software_cfg: config.SoftwareConfig, case_name: str, case_cfg: config.TestcaseConfig
):
    server_instances = []
    domains: dict[str, vhostTestData] = {}
    with ExitStack() as stack:
        for server_cfg in case_cfg.servers:
            instance = setup_server(software_name, case_name, software_cfg, server_cfg)
            stack.enter_context(instance)
            server_instances.append(instance)
            for vhost in server_cfg.vHosts:
                assert vhost.hostname not in domains, "Duplicate domain - we do not handle this"
                remote = Remote(vhost.hostname, ip=instance.ip, port=vhost.port)
                domains[vhost.hostname] = precheck_remote(remote)

        print("#", software_name, case_name)

        bodies = {}
        # check for duplicate bodies
        for vhost, data in domains.items():
            body = data.initial_result.body
            if body in bodies:
                logging.error("Duplicate body for %s and %s", vhost, bodies[body])
            bodies[body] = vhost
        if len(bodies) != len(domains):
            logging.error("Duplicate bodies found")
            return

        return evaluate_vhosts(domains)


def main():
    global TEMP_DIR
    testconfig = config.parse_config_file(TESTCASES_DIR / "config.yml")
    with tempfile.TemporaryDirectory(delete=True) as temp_dir:
        TEMP_DIR = Path(temp_dir)
        software_results = {}
        for software_name, software_cfg in testconfig.software_config.items():
            case_results = {}
            for case_name, case_cfg in testconfig.test_cases.items():
                case_results[case_name] = evaluate_test_case(software_name, software_cfg, case_name, case_cfg)
            software_results[software_name] = GroupedResult.from_results(case_results)
        all_results = GroupedResult.from_results(software_results)
    with open("results.json", "w") as f:
        f.write(all_results.model_dump_json(indent=2))
    TEMP_DIR = None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("urllib3").setLevel(logging.INFO)
    main()
