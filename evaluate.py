from dataclasses import dataclass
import ssl
import os
import logging
import itertools
from pathlib import Path
import docker as docker_lib
from docker.models.containers import Container
from docker.types import Mount
import tempfile
import time
from util import config
from util.request import Remote, request, HttpsResponse
from contextlib import ExitStack


@dataclass
class DeployedServer:
    ip: str
    container: Container
    temp_files: list[str]

    def teardown(self):
        self.container.remove(force=True)
        STARTED_CONTAINER_IDS.remove(self.container.id)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.teardown()


@dataclass
class vhostTestData:
    remote: Remote
    initial_result: HttpsResponse
    requires_sni: bool
    resumption_working: bool


docker = docker_lib.from_env()

TESTCASES_DIR = Path("testcases")
CERTS_DIR = TESTCASES_DIR / "certs"
SITES_DIR = TESTCASES_DIR / "sites"

TEMP_DIR = None
STARTED_CONTAINER_IDS = set()


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
    container = docker.containers.run(software_cfg.image, detach=True, name=name, auto_remove=True, mounts=mounts)
    # except:
    STARTED_CONTAINER_IDS.add(container.id)

    container.reload()
    ip = container.attrs["NetworkSettings"]["IPAddress"]
    assert ip is not None
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


def evaluate(software_name: str, software_cfg: config.SoftwareConfig, case_name: str, case_cfg: config.TestcaseConfig):
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

        for ticket_host, resumption_host in itertools.permutations(domains.values(), 2):
            assert ticket_host != resumption_host, "Same host; should not happen"

            for sni, host_header in itertools.product(
                [ticket_host.remote, resumption_host.remote, None],
                [ticket_host.remote, resumption_host.remote],
            ):
                r = request(resumption_host.remote, sni, host_header, ticket_host.initial_result.session)
                print(
                    f"Using ticket from {ticket_host.remote.hostname} at {resumption_host.remote.hostname} with SNI {sni.hostname if sni else 'None'} and Host {host_header.hostname}"
                )
                print(f"{'!' if r.session_reused else ' '}Session reused  : {r.session_reused}")
                is_ticket_body = r.body == ticket_host.initial_result.body
                is_resumption_body = r.body == resumption_host.initial_result.body
                assert not (
                    is_ticket_body and is_resumption_body
                ), "Same body for ticket and resumption; should've been caught earlier"
                if is_ticket_body:
                    print(f"{' ' if r.session_reused else '!'}Body: Initial")
                elif is_resumption_body:
                    print(f"{'!' if r.session_reused else ' '}Body: Resumption")
                else:
                    print("?Body: Unknown")
                # assert r.session_reused == False, "Resumed ticket at other host"


def main():
    global TEMP_DIR
    testconfig = config.parse_config_file(TESTCASES_DIR / "config.yml")
    with tempfile.TemporaryDirectory(delete=True) as temp_dir:
        TEMP_DIR = Path(temp_dir)
        for software_name, software_cfg in testconfig.software_config.items():
            for case_name, case_cfg in testconfig.test_cases.items():
                evaluate(software_name, software_cfg, case_name, case_cfg)
    TEMP_DIR = None


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    main()
