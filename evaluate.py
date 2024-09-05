import base64
import itertools
import logging as _logging
import os
import ssl
import tempfile
import time
from collections import namedtuple
from contextlib import ExitStack
from dataclasses import dataclass
from enum import Enum, IntEnum, StrEnum
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

CERTS = {}
for cert in CERTS_DIR.glob("*.crt"):
    with cert.open("r") as f:
        cert_pem = f.readlines()
        assert cert_pem[0] == "-----BEGIN CERTIFICATE-----\n"
        assert cert_pem[-1] == "-----END CERTIFICATE-----\n"
        cert_pem = "".join(cert_pem[1:-1])
        CERTS[cert.stem] = base64.b64decode(cert_pem)

TEMP_DIR = None
STARTED_CONTAINER_IDS = set()

T = TypeVar("T")

logging = _logging.getLogger(__name__)


@dataclass
class DeployedServer:
    ip: str
    container: Container
    temp_files: list[str]

    def teardown(self, exc_type=None, exc_value=None, traceback=None):
        logging.debug(
            "removing container id=%s name=%s (exc_type=%r)", self.container.id, self.container.name, exc_type
        )
        if exc_type is not None and not isinstance(exc_value, (KeyboardInterrupt, AssertionError)):
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


class RemoteAlias(StrEnum):
    UNKNOWN = "unknown"
    TICKET_ISSUER = "ticket issuer"
    RESUMPTION = "resumption"


_RemoteName_MULTIPLE = "<multiple values>"


class RemoteName(BaseModel):
    alias: RemoteAlias
    domain: str

    @staticmethod
    def from_body(received, ticket_issuer_host: vhostTestData, resumption_host: vhostTestData):
        assert (
            ticket_issuer_host.initial_result.body != resumption_host.initial_result.body
        ), "Same body for ticket and resumption; should've been caught earlier"
        if received == ticket_issuer_host.initial_result.body:
            return RemoteName(domain=ticket_issuer_host.remote.hostname, alias=RemoteAlias.TICKET_ISSUER)
        elif received == resumption_host.initial_result.body:
            return RemoteName(domain=resumption_host.remote.hostname, alias=RemoteAlias.RESUMPTION)
        else:
            return RemoteName(domain="<unknown>", alias=RemoteAlias.UNKNOWN)

    @staticmethod
    def summarize(*remote_names):
        summary = None
        for r in remote_names:
            if r is None:
                continue
            if summary is None:
                summary = r
                continue

            r_domain = None
            if isinstance(r, RemoteName):
                r_domain = r.domain
            elif isinstance(r, str):
                r_domain = r

            r_alias = None
            if isinstance(r, RemoteName):
                r_alias = r.alias
            elif isinstance(r, RemoteAlias):
                r_alias = r

            if isinstance(summary, RemoteName):
                if r_domain == summary.domain and r_alias == summary.alias:
                    continue
                elif r_domain == summary.domain:
                    summary = r_domain
                elif r_alias == summary.alias:
                    summary = r_alias
                else:
                    return _RemoteName_MULTIPLE
            elif isinstance(summary, RemoteAlias):
                if r_alias == summary:
                    continue
                else:
                    return _RemoteName_MULTIPLE
            elif isinstance(summary, str):
                if r_domain == summary:
                    continue
                else:
                    return _RemoteName_MULTIPLE

        return summary


RemoteNameSummary = Union[RemoteName, RemoteAlias, str]


assert RemoteName.summarize("a", "a") == "a"
assert RemoteName.summarize("a", "b") == _RemoteName_MULTIPLE
assert RemoteName.summarize(RemoteAlias.RESUMPTION, RemoteAlias.RESUMPTION) == RemoteAlias.RESUMPTION
assert RemoteName.summarize(RemoteAlias.RESUMPTION, RemoteAlias.TICKET_ISSUER) == _RemoteName_MULTIPLE
_A_ISS = RemoteName(alias=RemoteAlias.TICKET_ISSUER, domain="a")
_A_RES = RemoteName(alias=RemoteAlias.RESUMPTION, domain="a")
_B_ISS = RemoteName(alias=RemoteAlias.TICKET_ISSUER, domain="b")
_B_RES = RemoteName(alias=RemoteAlias.RESUMPTION, domain="b")
assert RemoteName.summarize(_A_ISS, _A_ISS) == RemoteName(alias=RemoteAlias.TICKET_ISSUER, domain="a")
assert RemoteName.summarize(_A_ISS, _A_RES) == "a"
assert RemoteName.summarize(_A_ISS, _B_ISS) == RemoteAlias.TICKET_ISSUER
assert RemoteName.summarize(_A_ISS, _B_RES) == _RemoteName_MULTIPLE
del _A_ISS, _A_RES, _B_ISS, _B_RES


class ResultSummary(IntEnum):
    GOOD = 0
    LOOK_INTO_THIS = 1
    WARN = 2
    BAD = 3

    def __or__(self, other):
        # bitwise OR should give the worst result
        assert isinstance(other, ResultSummary)
        return max(self, other)


class BoolSummary(StrEnum):
    ALL = "all"
    SOME = "some"
    NONE = "none"

    @staticmethod
    def summarize(*bools):
        if isinstance(bools[0], bool):
            assert all(isinstance(b, bool) for b in bools)
            if all(bools):
                return BoolSummary.ALL
            elif any(bools):
                return BoolSummary.SOME
            else:
                return BoolSummary.NONE
        elif isinstance(bools[0], BoolSummary):
            assert all(isinstance(b, BoolSummary) for b in bools)
            seen_values = set(bools)
            if len(seen_values) == 1:
                return bools[0]
            # multiple values: i.e. it cannot be all or none -> some
            return BoolSummary.SOME
        else:
            raise ValueError("Unknown type")


class SingleResult(BaseModel):
    summary: ResultSummary
    ticket_resumed: bool
    body: RemoteName
    response_status_code: int
    response_body: bytes
    full_response_cert: RemoteNameSummary
    full_response_body: RemoteName
    full_body_equals_resumption_body: bool
    full_body_equals_cert: bool

    @staticmethod
    def from_response(
        resumption_response: HttpsResponse,
        full_response: HttpsResponse,
        ticket_issuer: vhostTestData,
        resumption: vhostTestData,
    ):
        body_remote = RemoteName.from_body(resumption_response.body, ticket_issuer, resumption)
        full_response_body_remote = RemoteName.from_body(full_response.body, ticket_issuer, resumption)

        if full_response.cert == CERTS[ticket_issuer.remote.hostname]:
            full_response_cert = RemoteName(alias=RemoteAlias.TICKET_ISSUER, domain=ticket_issuer.remote.hostname)
        elif full_response.cert == CERTS[resumption.remote.hostname]:
            full_response_cert = RemoteName(alias=RemoteAlias.RESUMPTION, domain=resumption.remote.hostname)
        else:
            for name, cert in CERTS.items():
                if full_response.cert == cert:
                    full_response_cert = name
                    break
            else:
                full_response_cert = RemoteAlias.UNKNOWN

        summary = None
        if not resumption_response.session_reused:
            summary = ResultSummary.GOOD
        else:
            # session was reused
            if body_remote.alias == RemoteAlias.TICKET_ISSUER:
                summary = ResultSummary.GOOD
            elif body_remote.alias == RemoteAlias.RESUMPTION:
                summary = ResultSummary.BAD
            else:
                summary = ResultSummary.LOOK_INTO_THIS

        return SingleResult(
            ticket_resumed=resumption_response.session_reused,
            body=body_remote,
            summary=summary,
            response_status_code=resumption_response.response.status,
            response_body=resumption_response.body,
            full_response_cert=full_response_cert,
            full_response_body=full_response_body_remote,
            full_body_equals_resumption_body=full_response.body == resumption_response.body,
            full_body_equals_cert=full_response_cert == full_response_body_remote,
        )


class GroupedResult(BaseModel):
    summary: ResultSummary
    ticket_resumed: BoolSummary
    body: RemoteNameSummary

    full_response_cert: RemoteNameSummary
    full_response_body: RemoteNameSummary
    full_body_equals_resumption_body: BoolSummary
    full_body_equals_cert: BoolSummary
    details: dict[Any, Union["GroupedResult", SingleResult]]

    @staticmethod
    def from_results(results: dict[Any, Union["GroupedResult", SingleResult]]):
        result_values = list(results.values())
        while None in result_values:
            result_values.remove(None)
        if not result_values:
            return None
        assert all(isinstance(r, (SingleResult, GroupedResult)) for r in result_values)

        summary = ResultSummary.GOOD
        for result in result_values:
            summary |= result.summary
        return GroupedResult(
            summary=summary,
            ticket_resumed=BoolSummary.summarize(*(r.ticket_resumed for r in result_values)),
            body=RemoteName.summarize(*(r.body for r in result_values)),
            full_response_cert=RemoteName.summarize(*(r.full_response_cert for r in result_values)),
            full_response_body=RemoteName.summarize(*(r.full_response_body for r in result_values)),
            full_body_equals_resumption_body=BoolSummary.summarize(
                *(r.full_body_equals_resumption_body for r in result_values)
            ),
            full_body_equals_cert=BoolSummary.summarize(*(r.full_body_equals_cert for r in result_values)),
            details=results,
        )


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
    logging.debug("Checking %s", remote)
    try:
        for _ in range(15):
            try:
                initial_result = request(remote, remote, remote, timeout=1)
                break
            except (ConnectionRefusedError, TimeoutError):
                time.sleep(0.1)
        else:
            # last attempt; will probably fail and raise the exception outwards
            initial_result = request(remote, remote, remote)
    except:
        logging.exception("Failed to connect to %s", remote)
        raise

    if initial_result.cert != CERTS[remote.hostname]:
        logging.error("Certificate mismatch for %s", remote)
        logging.error("Received: %s", initial_result.cert.hex())
        logging.error("Expected: %s", CERTS[remote.hostname].hex())
        raise AssertionError("Certificate mismatch")

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


def _select(remote: Optional[RemoteAlias], issuer: T, resumption: T) -> T:
    if remote is None:
        return None
    if remote == RemoteAlias.TICKET_ISSUER:
        return issuer
    elif remote == RemoteAlias.RESUMPTION:
        return resumption
    else:
        raise ValueError("Unknown remote name")


def _yield_results_group(f):
    def wrapper(*args, **kwargs):
        return GroupedResult.from_results(dict(f(*args, **kwargs)))

    return wrapper


@_yield_results_group
def evaluate_request(domains: dict[str, vhostTestData], sni_name: RemoteAlias, host_header_name: RemoteAlias):
    for ticket_issuer_host, resumption_host in itertools.permutations(domains.values(), 2):
        assert ticket_issuer_host != resumption_host, "Same host; should not happen"
        sni = _select(sni_name, ticket_issuer_host.remote, resumption_host.remote)
        host_header = _select(host_header_name, ticket_issuer_host.remote, resumption_host.remote)

        resumption_response = request(
            resumption_host.remote, sni, host_header, ticket_issuer_host.initial_result.session
        )
        full_response = request(resumption_host.remote, sni, host_header)
        result = SingleResult.from_response(
            resumption_response=resumption_response,
            full_response=full_response,
            ticket_issuer=ticket_issuer_host,
            resumption=resumption_host,
        )
        yield f"issuer={ticket_issuer_host.remote.hostname}, resumption={resumption_host.remote.hostname}", result


@_yield_results_group
def evaluate_vhosts(domains: dict[str, vhostTestData]):
    for sni_name, host_header_name in itertools.product(
        [RemoteAlias.TICKET_ISSUER, RemoteAlias.RESUMPTION, None],
        [RemoteAlias.TICKET_ISSUER, RemoteAlias.RESUMPTION],
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
            logging.debug("Checking vhosts")
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
                try:
                    case_results[case_name] = evaluate_test_case(software_name, software_cfg, case_name, case_cfg)
                except:
                    logging.exception("Failed to evaluate %s %s", software_name, case_name)
                    raise
            software_results[software_name] = GroupedResult.from_results(case_results)
        all_results = GroupedResult.from_results(software_results)
    if all_results is not None:
        with open("results.json", "w") as f:
            f.write(all_results.model_dump_json(indent=2))
    else:
        logging.critical("No results")
    TEMP_DIR = None


if __name__ == "__main__":
    _logging.basicConfig(level=_logging.INFO)
    logging.setLevel(_logging.INFO)
    main()
