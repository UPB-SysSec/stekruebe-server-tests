import http.client
import logging as _logging
import socket
import ssl
from dataclasses import dataclass
import time
from typing import Optional


logging = _logging.getLogger(__name__)

try:
    try:
        from .openssl_ticket import get_ticket_bytes
    except ImportError:
        from openssl_ticket import get_ticket_bytes
except:
    logging.exception("Failed to import get_ticket_bytes; using a stub function")

    def get_ticket_bytes(session) -> bytes:
        return None


def create_ssl_context(minimum_version=None, maximum_version=None, keylogfile=False):
    context = ssl.create_default_context()  # NOSONAR
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # NOSONAR
    if minimum_version is not None:
        context.minimum_version = minimum_version
    if maximum_version is not None:
        context.maximum_version = maximum_version
    if keylogfile:
        context.keylog_filename = "/tmp/keylogfile"
    return context


CTX_ANY = create_ssl_context()
CTX_TLS12 = create_ssl_context(maximum_version=ssl.TLSVersion.TLSv1_2)
CTX_TLS13 = create_ssl_context(minimum_version=ssl.TLSVersion.TLSv1_3)
CTX_DEFAULT = CTX_ANY


@dataclass(frozen=False)
class Remote:
    hostname: str
    ip: str | None = None
    port: int = 443

    def __post_init__(self):
        if self.hostname and ":" in self.hostname:
            # assume we got an IPv6
            self.ip = self.hostname
            self.hostname = None

    def get_connectable(self):
        if self.ip is None:
            # pin IP
            self.ip = socket.gethostbyname(self.hostname)
        addr = self.hostname if self.ip is None else self.ip
        return (addr, self.port)

    def __str__(self):
        if self.ip:
            return f"{self.hostname}@{self.ip}:{self.port}"
        return f"{self.hostname}:{self.port}"


@dataclass(frozen=True)
class HttpsResponse:
    session: ssl.SSLSession
    response: http.client.HTTPResponse
    body: bytes
    session_reused: bool
    ticket: Optional[bytes]
    cert: dict
    peername: tuple


def request(
    host: Remote,
    sni_host: Remote | None,
    host_header_host: Remote = ...,  # type: ignore
    session=None,
    context=CTX_DEFAULT,
    timeout=2,
):
    assert isinstance(host, Remote)
    assert isinstance(sni_host, (Remote, type(None)))
    if host_header_host is ...:
        host_header_host = host
    assert isinstance(host_header_host, Remote)

    sni_name = sni_host.hostname if sni_host is not None else None
    request = f"""GET / HTTP/1.1
Host: {host_header_host.hostname}
User-Agent: cli/1
Accept: */*
Connection: close

""".replace(
        "\n", "\r\n"
    ).encode()
    while not request.endswith(b"\r\n\r\n"):
        request += b"\r\n"

    logging.debug("Connecting to %s", host)
    with socket.create_connection(host.get_connectable(), timeout=timeout) as tcp_sock:
        logging.debug("Wrapping into TLS")
        with context.wrap_socket(tcp_sock, server_hostname=sni_name, session=session) as sock:
            logging.debug("Sending HTTP request")
            sock.write(request)

            response = http.client.HTTPResponse(sock)
            response.begin()
            logging.debug("Reading HTTP response")
            body = response.read()

            # do another receive to catch any trailing data
            # for closed lite speed we expect the ticket to come in the same flight of the close notify, this receive should cause the ticket and close notify to be parsed
            _trailing_data = sock.recv(4096)
            assert not _trailing_data, f"Received trailing data after response {_trailing_data!r}"

            # print("[ ]", host)
            # print("[ ]", request)
            # print("[ ]", response.status, response.reason)
            return HttpsResponse(
                session=sock.session,
                response=response,
                body=body,
                session_reused=sock.session_reused,
                ticket=get_ticket_bytes(sock.session),
                cert=sock.getpeercert(True),
                peername=sock.getpeername(),
            )
