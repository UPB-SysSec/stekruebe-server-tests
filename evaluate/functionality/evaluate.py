import itertools
import logging as _logging
import ssl
import time
from contextlib import ExitStack
from typing import Iterable, Optional, TypeVar, overload

from ..context import EvalContext
from ..deployment import StekRegistry, setup_server
from ..enums import RemoteAlias, TlsVersion
from ..parameters import TestCaseParameters
from ..result import SingleResult, vhostTestData
from ..util import config
from ..util.request import CTX_DEFAULT, CTX_TLS12, CTX_TLS13, Remote
from ..util.request import request as _request

logging = _logging.getLogger(__name__)

T = TypeVar("T")


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


def precheck_remote(remote: Remote, steks: StekRegistry, CTX: EvalContext):
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

    if remote.hostname not in CTX.CERTS:
        logging.warning("Did not have prior knowledge about cert for %s, storing now", remote.hostname)
        CTX.CERTS[remote.hostname] = initial_result.cert
    if initial_result.cert != CTX.CERTS[remote.hostname]:
        logging.error("Certificate mismatch for %s", remote)
        logging.error("Received: %s", initial_result.cert.hex())
        for k, v in CTX.CERTS.items():
            if v == initial_result.cert:
                logging.error("Received matched with %s", k)
        logging.error("Expected: %s", CTX.CERTS[remote.hostname].hex())
        for k, v in CTX.CERTS.items():
            if v == CTX.CERTS[remote.hostname]:
                logging.error("Expected matched with %s", k)
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
        assert response.cert == CTX.CERTS[remote.hostname]
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


def evaluate_request(domains: dict[str, vhostTestData], parameters: TestCaseParameters, CTX: EvalContext):
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
                CTX=CTX,
            )
        else:
            try:
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
                    CTX=CTX,
                )
            except ssl.SSLError as e:
                logging.error("Failed to perform full TLS handshake: %s", e)
                yield SingleResult.from_response(
                    abstract_parameters=parameters,
                    concrete_parameters=dict(
                        issuer=ticket_issuer_host.remote.hostname, resumption=resumption_host.remote.hostname
                    ),
                    resumption_response=None,
                    full_response=None,
                    ticket_issuer=ticket_issuer_host,
                    resumption=resumption_host,
                    CTX=CTX,
                )


def evaluate_test_case(
    software_name: str,
    software_cfg: config.SoftwareConfig,
    case_name: str,
    case_cfg: config.TestcaseConfig,
    CTX: EvalContext,
):
    logging.info("Running server %s in case %s", software_name, case_name)
    server_instances = []
    domains: dict[str, vhostTestData] = {}
    steks = StekRegistry()
    with ExitStack() as stack:
        for i, server_cfg in enumerate(case_cfg.servers):
            instance = setup_server(software_name, case_name, software_cfg, server_cfg, steks, i, CTX)
            stack.enter_context(instance)
            server_instances.append(instance)
            logging.debug("Checking vhosts")
            vhost_remotes: list[Remote] = []
            for vhost_cfg in server_cfg.vHosts:
                assert vhost_cfg.hostname not in domains, "Duplicate domain - we do not handle this"
                vhost_remotes.append(Remote(vhost_cfg.hostname, ip=instance.ip, port=vhost_cfg.port))
            for additional_vhost_port in software_cfg.additional_vhost_ports:
                vhost_remotes.append(
                    Remote(
                        f"{software_name}_additional_{i}_{additional_vhost_port}",
                        ip=instance.ip,
                        port=additional_vhost_port,
                    )
                )
            for remote in vhost_remotes:
                domains[remote.hostname] = precheck_remote(remote, steks, CTX=CTX)

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
                _from=evaluate_request(domains, case_parameters, CTX),
            )


def _merge_identifier(*, _from: Iterable[SingleResult], **identifiers):
    for result in _from:
        assert set(identifiers.keys()) & set(result.parameters.keys()) == set(), "Identifier already in parameters"
        result.parameters = {**identifiers, **result.parameters}
        yield result


def evaluate(testconfig: config.TestConfig, CTX: EvalContext):
    for software_name, software_cfg in testconfig.software_config.items():
        for case_name, case_cfg in testconfig.test_cases.items():
            try:
                yield from _merge_identifier(
                    software_name=software_name,
                    case_name=case_name,
                    _from=evaluate_test_case(software_name, software_cfg, case_name, case_cfg, CTX),
                )
            except:
                logging.exception("Failed to evaluate %s %s", software_name, case_name)
                raise
