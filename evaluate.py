import base64
import itertools
import logging as _logging
import os
import ssl
import tempfile
import time
from abc import abstractmethod, ABC
from collections import namedtuple
from contextlib import ExitStack
from dataclasses import dataclass
from enum import Enum, IntEnum, StrEnum
from pathlib import Path
from typing import Any, Optional, TypeVar, Union, Iterable, overload

import click
import docker as docker_lib
from docker.models.containers import Container
from docker.types import Mount
from pydantic import BaseModel, Field, model_serializer
from pydantic_core import PydanticUndefined

from util import config
from util.request import HttpsResponse, Remote, request as _request, CTX_DEFAULT, CTX_TLS12, CTX_TLS13


docker = docker_lib.from_env()

TESTCASES_DIR = Path("testcases")
CERTS_DIR = TESTCASES_DIR / "certs"
SITES_DIR = TESTCASES_DIR / "sites"

CERTS = {}
for cert in CERTS_DIR.glob("*.crt"):
    with cert.open("r") as f:
        cert_pem_lines = f.readlines()
        assert cert_pem_lines[0] == "-----BEGIN CERTIFICATE-----\n"
        assert cert_pem_lines[-1] == "-----END CERTIFICATE-----\n"
        cert_pem = "".join(cert_pem_lines[1:-1])
        CERTS[cert.stem] = base64.b64decode(cert_pem)

TEMP_DIR = None
STARTED_CONTAINER_IDS: set[str] = set()

T = TypeVar("T")

logging = _logging.getLogger(__name__)


class TlsVersion(StrEnum):
    TLSv1_2 = "TLSv1.2"
    TLSv1_3 = "TLSv1.3"


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


@dataclass
class DeployedServer:
    ip: str
    container: Container
    temp_files: list[str]
    remotes: list[Remote] = Field(default_factory=list)

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
        for f in self.temp_files:
            os.unlink(f)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.teardown(exc_type, exc_value, traceback)


@dataclass
class vhostTestData:
    remote: Remote
    initial_result: HttpsResponse
    sessions: dict[TlsVersion, ssl.SSLSession]
    requires_sni: bool
    resumption_working: bool


class RemoteAlias(StrEnum):
    UNKNOWN = "unknown host"
    TICKET_ISSUER = "ticket issuer host"
    RESUMPTION = "resumption host"


class RemoteRole(StrEnum):
    SNI_VALUE = "sni value"
    HOST_VALUE = "host header value"


_RemoteNameSummary_MULTIPLE = "<multiple values>"


class RemoteNameSummary(BaseModel):
    data: set[Union[RemoteAlias, RemoteRole, str, None]]

    def __init__(self, *data):
        if len(data) == 1 and isinstance(data[0], set):
            data = data[0]
        else:
            assert not any(isinstance(d, set) for d in data)
        super().__init__(data=data)

    @model_serializer()
    def serialize(self):
        if len(self.data) == 0:
            return _RemoteNameSummary_MULTIPLE
        if len(self.data) == 1:
            return next(iter(self.data))
        return self.data

    def __eq__(self, value: object) -> bool:
        if isinstance(value, RemoteNameSummary):
            return self.data == value.data
        return self.data == value

    def __contains__(self, value: object) -> bool:
        return value in self.data

    @staticmethod
    def from_body(
        received,
        ticket_issuer_host: vhostTestData,
        resumption_host: vhostTestData,
        abstract_parameters: "TestCaseParameters",
    ):
        # assert (
        #     ticket_issuer_host.initial_result.body != resumption_host.initial_result.body
        # ), "Same body for ticket and resumption; should've been caught earlier"
        if ticket_issuer_host.initial_result.body == resumption_host.initial_result.body:
            return RemoteNameSummary(
                ticket_issuer_host.remote.hostname,
                RemoteAlias.TICKET_ISSUER,
                *abstract_parameters.get_roles(RemoteAlias.TICKET_ISSUER),
                resumption_host.remote.hostname,
                RemoteAlias.RESUMPTION,
                *abstract_parameters.get_roles(RemoteAlias.RESUMPTION),
            )
        if received == ticket_issuer_host.initial_result.body:
            return RemoteNameSummary(
                ticket_issuer_host.remote.hostname,
                RemoteAlias.TICKET_ISSUER,
                *abstract_parameters.get_roles(RemoteAlias.TICKET_ISSUER),
            )
        elif received == resumption_host.initial_result.body:
            return RemoteNameSummary(
                resumption_host.remote.hostname,
                RemoteAlias.RESUMPTION,
                *abstract_parameters.get_roles(RemoteAlias.RESUMPTION),
            )
        else:
            return RemoteNameSummary(RemoteAlias.UNKNOWN)

    @staticmethod
    def summarize(*remote_names):
        remote_names = list(remote_names)
        for i in range(len(remote_names)):
            if isinstance(remote_names[i], RemoteNameSummary):
                remote_names[i] = remote_names[i].data
            elif not isinstance(remote_names[i], set):
                # assume single value
                remote_names[i] = {remote_names[i]}

        ret = set(remote_names[0])
        for r in remote_names[1:]:
            ret.intersection_update(r)
        return RemoteNameSummary(ret)


assert RemoteNameSummary.summarize("a", "a").model_dump() == "a"
assert RemoteNameSummary.summarize("a", "b").model_dump() == _RemoteNameSummary_MULTIPLE
assert (
    RemoteNameSummary.summarize(RemoteAlias.RESUMPTION, RemoteAlias.RESUMPTION).model_dump() == RemoteAlias.RESUMPTION
)
assert (
    RemoteNameSummary.summarize(RemoteAlias.RESUMPTION, RemoteAlias.TICKET_ISSUER).model_dump()
    == _RemoteNameSummary_MULTIPLE
)
_A_ISS = RemoteNameSummary(RemoteAlias.TICKET_ISSUER, "a")
_A_RES = RemoteNameSummary(RemoteAlias.RESUMPTION, "a")
_B_ISS = RemoteNameSummary(RemoteAlias.TICKET_ISSUER, "b")
_B_RES = RemoteNameSummary(RemoteAlias.RESUMPTION, "b")
assert RemoteNameSummary.summarize(_A_ISS, _A_ISS).model_dump() == RemoteNameSummary(RemoteAlias.TICKET_ISSUER, "a")
assert RemoteNameSummary.summarize(_A_ISS, _A_RES).model_dump() == "a"
assert RemoteNameSummary.summarize(_A_ISS, _B_ISS).model_dump() == RemoteAlias.TICKET_ISSUER
assert RemoteNameSummary.summarize(_A_ISS, _B_RES).model_dump() == _RemoteNameSummary_MULTIPLE
del _A_ISS, _A_RES, _B_ISS, _B_RES


def request(
    host: Remote,
    sni_host: Remote | None,
    host_header_host: Remote = ...,  # type: ignore
    session=None,
    version: Optional[TlsVersion] = None,
    timeout=2,
):
    ctx = CTX_DEFAULT
    if version is TlsVersion.TLSv1_2:
        ctx = CTX_TLS12
    elif version is TlsVersion.TLSv1_3:
        ctx = CTX_TLS13
    return _request(host, sni_host, host_header_host, session, ctx, timeout)


class GeneratedModel(BaseModel):
    @staticmethod
    def _get_values_for_type(typ):
        if typ == type(None):
            return [None]

        if typ == str:
            raise ValueError("Cannot generate strings")

        if typ == bool:
            return [False, True]

        if hasattr(typ, "__origin__") and typ.__origin__ == Union:
            # handle Union/Optional
            values = set()
            for arg in typ.__args__:
                values.update(TestCaseParameters._get_values_for_type(arg))
            return values

        if issubclass(typ, Enum):
            return list(typ)

        raise ValueError(f"Unknown type {typ}")

    @classmethod
    def generate(cls, **given_parameters):
        field_value_space = {}
        for field_name, field_info in cls.model_fields.items():
            if field_name in given_parameters:
                if isinstance(given_parameters[field_name], (list, tuple, set)):
                    field_value_space[field_name] = given_parameters[field_name]
                else:
                    field_value_space[field_name] = [given_parameters[field_name]]
            elif isinstance(field_info.examples, list):
                field_value_space[field_name] = field_info.examples
            else:
                field_value_space[field_name] = TestCaseParameters._get_values_for_type(field_info.annotation)

        for values in itertools.product(*field_value_space.values()):
            parameters = dict(zip(field_value_space.keys(), values))
            yield cls(**parameters)


class TestCaseParameters(GeneratedModel):
    tls_version: TlsVersion = Field(examples=list(TlsVersion))
    sni_name: Optional[RemoteAlias] = Field(examples=[RemoteAlias.TICKET_ISSUER, RemoteAlias.RESUMPTION, None])
    host_header_name: RemoteAlias = Field(examples=[RemoteAlias.TICKET_ISSUER, RemoteAlias.RESUMPTION])

    def get_roles(self, alias: RemoteAlias) -> set[RemoteRole]:
        ret = set()
        if alias == self.sni_name:
            ret.add(RemoteRole.SNI_VALUE)
        if alias == self.host_header_name:
            ret.add(RemoteRole.HOST_VALUE)
        return ret


class ResultSummary(IntEnum):
    GOOD = 0
    WARN = 1
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
    parameters: dict[str, Any] = Field(exclude=True)
    summary: ResultSummary
    ticket_resumed: bool
    body: Optional[RemoteNameSummary]
    response_status_code: Optional[int]
    response_body: Optional[bytes]
    full_response_cert: Optional[RemoteNameSummary]
    full_response_body: Optional[RemoteNameSummary]
    full_body_equals_resumption_body: Optional[bool]
    full_body_equals_cert: Optional[bool]

    @staticmethod
    def from_response(
        abstract_parameters: TestCaseParameters,
        concrete_parameters: dict[str, Any],
        resumption_response: Optional[HttpsResponse],
        full_response: Optional[HttpsResponse],
        ticket_issuer: vhostTestData,
        resumption: vhostTestData,
    ):
        if full_response is None:
            assert resumption_response is None
            return SingleResult(
                parameters=concrete_parameters,
                summary=ResultSummary.GOOD,
                ticket_resumed=False,
                body=None,
                response_status_code=None,
                response_body=None,
                full_response_cert=None,
                full_response_body=None,
                full_body_equals_resumption_body=False,
                full_body_equals_cert=False,
            )
        assert resumption_response
        body_remote = RemoteNameSummary.from_body(
            resumption_response.body, ticket_issuer, resumption, abstract_parameters
        )
        full_response_body_remote = RemoteNameSummary.from_body(
            full_response.body, ticket_issuer, resumption, abstract_parameters
        )

        if full_response.cert == CERTS[ticket_issuer.remote.hostname]:
            full_response_cert = RemoteNameSummary(
                RemoteAlias.TICKET_ISSUER,
                ticket_issuer.remote.hostname,
                *abstract_parameters.get_roles(RemoteAlias.TICKET_ISSUER),
            )
        elif full_response.cert == CERTS[resumption.remote.hostname]:
            full_response_cert = RemoteNameSummary(
                RemoteAlias.RESUMPTION,
                resumption.remote.hostname,
                *abstract_parameters.get_roles(RemoteAlias.RESUMPTION),
            )
        else:
            for name, cert in CERTS.items():
                if full_response.cert == cert:
                    full_response_cert = RemoteNameSummary(name)
                    break
            else:
                full_response_cert = RemoteNameSummary(RemoteAlias.UNKNOWN)

        summary = None
        if not resumption_response.session_reused:
            summary = ResultSummary.GOOD
        else:
            # session was reused
            if RemoteAlias.TICKET_ISSUER in body_remote:
                summary = ResultSummary.GOOD
            elif RemoteAlias.RESUMPTION in body_remote:
                summary = ResultSummary.BAD
            else:
                # unknown body
                summary = ResultSummary.WARN

        return SingleResult(
            parameters=concrete_parameters,
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
            result_values.remove(None)  # type: ignore
        if not result_values:
            return None
        assert all(isinstance(r, (SingleResult, GroupedResult)) for r in result_values)

        summary = ResultSummary.GOOD
        for result in result_values:
            summary |= result.summary
        return GroupedResult(
            summary=summary,
            ticket_resumed=BoolSummary.summarize(*(r.ticket_resumed for r in result_values)),
            body=RemoteNameSummary.summarize(*(r.body for r in result_values)),
            full_response_cert=RemoteNameSummary.summarize(*(r.full_response_cert for r in result_values)),
            full_response_body=RemoteNameSummary.summarize(*(r.full_response_body for r in result_values)),
            full_body_equals_resumption_body=BoolSummary.summarize(
                *(r.full_body_equals_resumption_body for r in result_values)
            ),
            full_body_equals_cert=BoolSummary.summarize(*(r.full_body_equals_cert for r in result_values)),
            details=results,
        )


_SERVER_COUNTER = 0


def _generate_stek(length: int, prefix: Union[bytes, str] = b""):
    if isinstance(prefix, str):
        prefix = prefix.encode("ascii")
    stek = prefix
    stek += os.urandom(length - len(prefix))
    return stek


def setup_server(
    software_name,
    testcase_name,
    software_cfg: config.SoftwareConfig,
    server_cfg: config.ServerConfig,
    steks: StekRegistry,
    number: int,
):
    global _SERVER_COUNTER
    _prefix = f"{_SERVER_COUNTER}_{number}_"
    _SERVER_COUNTER += 1

    tmp_files = []

    def create_temp_file(prefix, **kwargs):
        f = tempfile.NamedTemporaryFile(delete=False, dir=TEMP_DIR, prefix=_prefix + prefix, **kwargs)
        tmp_files.append(f.name)
        return f

    name = f"stekruebe_{software_name}_{testcase_name}_" + "_".join(v.hostname for v in server_cfg.vHosts)

    mounts = [
        Mount(source=str(CERTS_DIR.absolute()), target="/certs", read_only=True, type="bind"),
        Mount(source=str(SITES_DIR.absolute()), target="/sites", read_only=True, type="bind"),
    ]

    stek_file = create_temp_file("stek.key.")
    stek_file.write(steks.get_stek(server_cfg.stek_id, software_cfg.stek_length))
    stek_file.close()
    mounts.append(Mount(source=stek_file.name, target="/stek.key", read_only=True, type="bind"))

    for vhost in server_cfg.vHosts:
        if vhost.stek_id:
            assert vhost.stek_path
            vhost_stek_file = create_temp_file(f".{vhost.hostname}.stek.key")
            vhost_stek_file.write(steks.get_stek(vhost.stek_id, software_cfg.stek_length))
            vhost_stek_file.close()
            mounts.append(Mount(source=vhost_stek_file.name, target=vhost.stek_path, read_only=True, type="bind"))

    config_file = create_temp_file(".server.conf", mode="w")
    config_file.write(software_cfg.render_config(server_cfg, "/stek.key", comment=f"Config for container {name}"))
    config_file.close()
    mounts.append(Mount(source=config_file.name, target=software_cfg.config_path, read_only=True, type="bind"))

    container = docker.containers.run(software_cfg.image, detach=True, name=name, auto_remove=False, mounts=mounts)

    assert container.id is not None
    STARTED_CONTAINER_IDS.add(container.id)

    container.reload()
    ip = container.attrs["NetworkSettings"]["IPAddress"]
    assert ip is not None
    logging.debug("started container id=%s name=%s", container.id, name)

    return DeployedServer(ip, container, tmp_files)


def precheck_remote(remote: Remote, steks: StekRegistry):
    logging.debug("Checking %s", remote)
    try:
        for _ in range(15):
            try:
                initial_result = request(remote, remote, remote, timeout=1)
                break
            except (ConnectionRefusedError, TimeoutError, OSError):
                time.sleep(0.1)
        else:
            # last attempt; will probably fail and raise the exception outwards
            initial_result = request(remote, remote, remote)
    except:
        logging.exception("Failed to connect to %s", remote)
        raise

    if remote.hostname not in CERTS:
        logging.warning("Did not ahve prior knowledge about cert for %s, storing now", remote.hostname)
        CERTS[remote.hostname] = initial_result.cert
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

    sessions = {}
    for version in TlsVersion:
        # for each version get a session
        response = request(remote, remote, remote, version=version)
        sessions[version] = response.session

        stek = steks.lookup_stek(response.ticket)

        # also validate that the cert and body are the same
        assert response.cert == CERTS[remote.hostname]
        # also check that the session can be resumed
        assert response.body == initial_result.body
        # also check that SNI requirements stay the same
        try:
            no_sni_response = request(remote, None, remote, version=version)
            no_sni_stek = steks.lookup_stek(no_sni_response.ticket)
            assert not requires_sni
            logging.info(
                "vhost %s (%s) uses stek %s, no SNI results in stek %s",
                remote.hostname,
                version,
                stek,
                no_sni_stek,
            )
        except ssl.SSLError:
            assert requires_sni
            logging.warning(
                "vhost %s (%s) uses stek %s, requires SNI",
                remote.hostname,
                version,
                stek,
            )

        # validate that the tickets can be resumed multiple times (i.e. no single use tickets; we assume that we can simply reuse the same ticket again and again)
        resumption_working = True
        r = request(remote, remote, remote, response.session, version=version)
        resumption_working = resumption_working and r.session_reused
        r = request(remote, remote, remote, response.session, version=version)
        resumption_working = resumption_working and r.session_reused
        assert resumption_working, "Resumption did not work"

    return vhostTestData(
        remote=remote,
        initial_result=initial_result,
        sessions=sessions,
        requires_sni=requires_sni,
        resumption_working=resumption_working,
    )


@overload
def _select(remote: None, issuer: T, resumption: T) -> None: ...


@overload
def _select(remote: RemoteAlias, issuer: T, resumption: T) -> T: ...


def _select(remote: Optional[RemoteAlias], issuer: T, resumption: T) -> T | None:
    if remote is None:
        return None
    if remote == RemoteAlias.TICKET_ISSUER:
        return issuer
    elif remote == RemoteAlias.RESUMPTION:
        return resumption
    else:
        raise ValueError("Unknown remote name")


def evaluate_request(domains: dict[str, vhostTestData], parameters: TestCaseParameters):
    for ticket_issuer_host, resumption_host in itertools.permutations(domains.values(), 2):
        assert ticket_issuer_host != resumption_host, "Same host; should not happen"
        sni = _select(parameters.sni_name, ticket_issuer_host.remote, resumption_host.remote)
        host_header = _select(parameters.host_header_name, ticket_issuer_host.remote, resumption_host.remote)

        try:
            resumption_response = request(
                resumption_host.remote,
                sni,
                host_header,
                ticket_issuer_host.sessions[parameters.tls_version],
                parameters.tls_version,
            )
        except ssl.SSLError as e:
            logging.error("Failed to perform TLS handshake: %s", e)
            yield SingleResult.from_response(
                abstract_parameters=parameters,
                concrete_parameters=dict(
                    issuer=ticket_issuer_host.remote.hostname, resumption=resumption_host.remote.hostname
                ),
                resumption_response=None,
                full_response=None,
                ticket_issuer=ticket_issuer_host,
                resumption=resumption_host,
            )
        else:
            full_response = request(resumption_host.remote, sni, host_header, None, parameters.tls_version)
            yield SingleResult.from_response(
                abstract_parameters=parameters,
                concrete_parameters=dict(
                    issuer=ticket_issuer_host.remote.hostname, resumption=resumption_host.remote.hostname
                ),
                resumption_response=resumption_response,
                full_response=full_response,
                ticket_issuer=ticket_issuer_host,
                resumption=resumption_host,
            )


def evaluate_test_case(
    software_name: str, software_cfg: config.SoftwareConfig, case_name: str, case_cfg: config.TestcaseConfig
):
    logging.info("Running server %s in case %s", software_name, case_name)
    server_instances = []
    domains: dict[str, vhostTestData] = {}
    steks = StekRegistry()
    with ExitStack() as stack:
        for i, server_cfg in enumerate(case_cfg.servers):
            instance = setup_server(software_name, case_name, software_cfg, server_cfg, steks, i)
            stack.enter_context(instance)
            server_instances.append(instance)
            logging.debug("Checking vhosts")
            vhost_remotes: list[Remote] = []
            for vhost_cfg in server_cfg.vHosts:
                assert vhost_cfg.hostname not in domains, "Duplicate domain - we do not handle this"
                vhost_remotes.append(Remote(vhost_cfg.hostname, ip=instance.ip, port=vhost_cfg.port))
            for additional_vhost_port in software_cfg.additional_vhost_ports:
                vhost_remotes.append(
                    Remote(f"additional_{i}_{additional_vhost_port}", ip=instance.ip, port=additional_vhost_port)
                )
            for remote in vhost_remotes:
                domains[remote.hostname] = precheck_remote(remote, steks)

        bodies: dict[bytes, list[str]] = {}
        # check for duplicate bodies
        for vhost, data in domains.items():
            body = data.initial_result.body
            if body in bodies:
                logging.warning("Duplicate body for %s and %s", vhost, bodies[body])
            else:
                bodies[body] = []
            bodies[body].append(vhost)
        # if len(bodies) != len(domains):
        #     logging.error("Duplicate bodies found")
        #     raise ValueError()

        for case_parameters in TestCaseParameters.generate():
            if case_parameters.sni_name is None and not software_cfg.supports_sni_none:
                continue
            logging.debug("Case Parameters %r", case_parameters)
            yield from _merge_identifier(
                **case_parameters.model_dump(),
                _from=evaluate_request(domains, case_parameters),
            )


def _merge_identifier(*, _from: Iterable[SingleResult], **identifiers):
    for result in _from:
        assert set(identifiers.keys()) & set(result.parameters.keys()) == set(), "Identifier already in parameters"
        result.parameters = {**identifiers, **result.parameters}
        yield result


def evaluate(testconfig: config.TestConfig):
    for software_name, software_cfg in testconfig.software_config.items():
        for case_name, case_cfg in testconfig.test_cases.items():
            try:
                yield from _merge_identifier(
                    software_name=software_name,
                    case_name=case_name,
                    _from=evaluate_test_case(software_name, software_cfg, case_name, case_cfg),
                )
            except:
                logging.exception("Failed to evaluate %s %s", software_name, case_name)
                raise


def group_results(results: Iterable[SingleResult], *group_keys, _used_keys=None):
    if _used_keys is None:
        _used_keys = set()
    else:
        _used_keys = set(_used_keys)

    current_key = group_keys[0]
    remaining_keys = group_keys[1:]

    if isinstance(current_key, tuple):
        for key in current_key:
            assert key not in _used_keys, "Key used multiple times"
            _used_keys.add(key)
    else:
        assert current_key not in _used_keys, "Key used multiple times"
        _used_keys.add(current_key)

    grouped: dict = {}
    for result in results:
        if isinstance(current_key, tuple):
            identifier = ", ".join(f"{k}={result.parameters[k]}" for k in current_key)
        else:
            identifier = f"{current_key}={result.parameters[current_key]}"

        if identifier not in grouped:
            grouped[identifier] = []
        grouped[identifier].append(result)

    if remaining_keys:
        for identifier in grouped:
            grouped[identifier] = group_results(grouped[identifier], *remaining_keys, _used_keys=_used_keys)
    else:
        left_over_keys = set(result.parameters.keys()) - _used_keys
        assert not left_over_keys, "Left over keys"  # minor todo: implement/handle
        for identifier in grouped:
            assert len(grouped[identifier]) == 1  # minor todo: implement/handle
            grouped[identifier] = grouped[identifier][0]
    return GroupedResult.from_results(grouped)


class TestConfigCli(click.ParamType):
    name = "testconfig"

    def convert(self, value, param, ctx):
        return config.parse_config_file(value)


class NameCliParameter(click.ParamType, ABC):
    def __init__(self, multiple_comma=True):
        self.multi_comma = multiple_comma

    def convert(self, value, param, ctx):
        testconfig = ctx.parent.params["testconfig"]
        assert isinstance(testconfig, config.TestConfig)
        dict_to_filter = self.get_dict_to_filter(testconfig)

        if self.multi_comma:
            all_items = set(map(str.strip, value.split(",")))
        else:
            all_items = {value}

        for item in all_items:
            if item not in dict_to_filter:
                raise ValueError(f"Unknown test case {item}")

        for item in list(dict_to_filter.keys()):
            if item not in all_items:
                dict_to_filter.pop(item)

        return all_items

    @abstractmethod
    def get_dict_to_filter(self, testconfig: config.TestConfig):
        raise NotImplementedError()


class TestCaseNameCli(NameCliParameter):
    name = "testcase_name"

    def get_dict_to_filter(self, testconfig: config.TestConfig):
        return testconfig.test_cases


class SoftwareNameCli(NameCliParameter):
    name = "software_name"

    def get_dict_to_filter(self, testconfig: config.TestConfig):
        return testconfig.software_config


@click.group()
@click.option("--config", "testconfig", type=TestConfigCli(), default=TESTCASES_DIR / "config.yml")
def main(**kwargs):
    # click handles this
    pass


@main.command("evaluate")
@click.pass_context
@click.option("--software", "_software_names", type=SoftwareNameCli(), default=None)
@click.option("--case", "_testcase_names", type=TestCaseNameCli(), default=None)
# def main_evaluate(testconfig: config.TestConfig, _testcase_names, _software_names):
def main_evaluate(
    ctx: click.Context,
    _testcase_names,
    _software_names,
):
    global TEMP_DIR
    import csv

    assert ctx.parent
    testconfig = ctx.parent.params["testconfig"]

    # testconfig = config.parse_config_file(TESTCASES_DIR / "config.yml")
    with tempfile.TemporaryDirectory(delete=True, prefix="steckruebe_") as temp_dir, open("results.csv", "w") as f:
        TEMP_DIR = Path(temp_dir)
        keys = None
        results = []
        for result in evaluate(testconfig):
            parameters = result.parameters
            assert isinstance(parameters, dict)
            assert isinstance(result, SingleResult)
            results.append(result)

            result = result.model_dump()
            # parameters = {f"parameters.{k}": v for k, v in parameters.items()}
            result = {f"result.{k}": v for k, v in result.items() if k != "parameters"}

            if keys is None:
                # first result
                keys = parameters.keys()
                writer = csv.DictWriter(f, fieldnames=[*keys, *result.keys()])
                writer.writeheader()
            else:
                assert keys == parameters.keys(), "Different keys"
            writer.writerow(
                {
                    **parameters,
                    **result,
                }
            )

    # group results
    group_keys = (
        "software_name",
        "case_name",
        ("sni_name", "host_header_name"),
        "tls_version",
        ("issuer", "resumption"),
    )
    with open("results.json", "w") as f:
        grouped = group_results(results, *group_keys)
        f.write(grouped.model_dump_json(indent=2))


@main.command("deploy")
@click.pass_context
@click.argument("_software_names", type=SoftwareNameCli(False))
@click.argument("_testcase_names", type=TestCaseNameCli(False))
def main_deploy(
    ctx: click.Context,
    _testcase_names,
    _software_names,
):
    assert ctx.parent
    testconfig = ctx.parent.params["testconfig"]

    with ExitStack() as stack:
        for software_name, software_cfg in testconfig.software_config.items():
            for case_name, case_cfg in testconfig.test_cases.items():
                steks = StekRegistry()
                for i, server_cfg in enumerate(case_cfg.servers):
                    instance = setup_server(software_name, case_name, software_cfg, server_cfg, steks, i)
                    stack.enter_context(instance)
                    print(f" Started {instance.container.name} at https://{instance.ip}")
                    for vhost in server_cfg.vHosts:
                        print(f"  - {vhost.hostname}: https://{vhost.hostname}:{vhost.port}/")
                        print(
                            f" curl -k --resolve '*:{vhost.port}:{instance.ip}' https://{vhost.hostname}:{vhost.port}/"
                        )
        try:
            print("\nStarted all servers. Press Ctrl+C to stop.")
            while True:
                time.sleep(60)
        except KeyboardInterrupt:
            print("\rStopping...")


if __name__ == "__main__":
    _logging.basicConfig(format="%(asctime)s %(levelname)7s | %(funcName)20s: %(message)s", level=_logging.INFO)
    logging.setLevel(_logging.INFO)

    main()
    if STARTED_CONTAINER_IDS:
        logging.warning("Some containers were not removed: %s", STARTED_CONTAINER_IDS)
