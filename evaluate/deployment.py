import logging as _logging
import os
import tempfile
import time
from typing import Union
from dataclasses import dataclass

import docker as docker_lib
from docker.models.containers import Container
from docker.types import Mount
from pydantic import BaseModel, Field

from .context import EvalContext
from .util import config
from .util.request import Remote

docker = docker_lib.from_env()

logging = _logging.getLogger(__name__)


def _generate_stek(length: int, prefix: Union[bytes, str] = b""):
    if isinstance(prefix, str):
        prefix = prefix.encode("ascii")
    stek = prefix
    stek += os.urandom(length - len(prefix))
    return stek


@dataclass(frozen=True)
class DeployedServer:
    ip: str
    container: Container
    temp_files: list[str]
    # remotes: list[Remote]
    CTX: EvalContext

    def teardown(self, exc_type=None, exc_value=None, traceback=None):
        logging.debug(
            "removing container id=%s name=%s (exc_type=%r)", self.container.id, self.container.name, exc_type
        )
        if exc_type is not None and not isinstance(exc_value, (KeyboardInterrupt, AssertionError)):
            # get logs
            logs = self.container.logs(stream=False)
            logging.error(logs)
        self.container.remove(force=True)
        self.CTX.STARTED_CONTAINER_IDS.remove(self.container.id)
        for f in self.temp_files:
            os.unlink(f)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.teardown(exc_type, exc_value, traceback)


class StekRegistry:
    def __init__(self):
        self.steks = {}
        self.stek_id_lookup = {}

    def get_stek(self, name: str, length: int):
        if name not in self.steks:
            self.steks[name] = _generate_stek(length, name)
            self.stek_id_lookup[self.steks[name][:16]] = name
        assert len(self.steks[name]) == length
        return self.steks[name]

    def lookup_stek(self, stek_id: bytes):
        ret = self.stek_id_lookup.get(stek_id[:16], None)
        if ret is not None:
            return ret
        return f"unknown({stek_id[:16].hex()})"


_SERVER_COUNTER = 0


def setup_server(
    software_name,
    testcase_name,
    software_cfg: config.SoftwareConfig,
    server_cfg: config.ServerConfig,
    steks: StekRegistry,
    number: int,
    CTX: EvalContext,
):
    global _SERVER_COUNTER
    _prefix = f"{_SERVER_COUNTER}_{number}_"
    _SERVER_COUNTER += 1

    tmp_files = []

    def create_temp_file(prefix, **kwargs):
        f = tempfile.NamedTemporaryFile(delete=False, dir=CTX.TEMP_DIR, prefix=_prefix + prefix, **kwargs)
        tmp_files.append(f.name)
        return f

    name = f"stekruebe_{software_name}_{testcase_name}_" + "_".join(v.hostname for v in server_cfg.vHosts)

    mounts = [
        Mount(source=str(CTX.CERTS_DIR.absolute()), target="/certs", read_only=True, type="bind"),
        Mount(source=str(CTX.SITES_DIR.absolute()), target="/sites", read_only=True, type="bind"),
    ]

    stek_file = create_temp_file("stek.key.")
    stek_file.write(steks.get_stek(server_cfg.stek_id, software_cfg.stek_length))
    stek_file.close()
    mounts.append(Mount(source=stek_file.name, target=software_cfg.stek_path, read_only=True, type="bind"))

    for vhost in server_cfg.vHosts:
        if vhost.stek_id:
            assert vhost.stek_path
            vhost_stek_file = create_temp_file(f".{vhost.hostname}.stek.key")
            vhost_stek_file.write(steks.get_stek(vhost.stek_id, software_cfg.stek_length))
            vhost_stek_file.close()
            mounts.append(Mount(source=vhost_stek_file.name, target=vhost.stek_path, read_only=True, type="bind"))

    config_file = create_temp_file(".server.conf", mode="w")
    config_file.write(software_cfg.render_config(server_cfg, comment=f"Config for container {name}"))
    config_file.close()
    # lwsw needs the config file to be writable
    mounts.append(Mount(source=config_file.name, target=software_cfg.config_path, read_only=False, type="bind"))

    for mount in software_cfg.additional_mounts:
        path = CTX.TESTCASES_DIR / mount.source
        mounts.append(Mount(source=str(path), target=mount.target, read_only=mount.read_only, type=mount.type))

    container = docker.containers.run(software_cfg.image, software_cfg.command, detach=True, name=name, auto_remove=False, mounts=mounts)

    assert container.id is not None
    CTX.STARTED_CONTAINER_IDS.add(container.id)

    container.reload()
    ip = container.attrs["NetworkSettings"]["IPAddress"]
    assert ip is not None
    logging.debug("started container id=%s name=%s", container.id, name)

    if "litespeed" in software_name:
        time.sleep(5) # some servers (LiteSpeed) take a while to get going

    return DeployedServer(ip=ip, container=container, temp_files=tmp_files, CTX=CTX)
