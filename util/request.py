from dataclasses import dataclass
import ssl
import socket
import http.client


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
    cert: dict
    peername: tuple


def request(host: Remote, sni_host: Remote | None, host_header_host: Remote = ..., session=None, context=CTX_ANY):
    assert isinstance(host, Remote)
    assert isinstance(sni_host, (Remote, type(None)))
    if host_header_host is ...:
        host_header_host = host
    assert isinstance(host_header_host, Remote)

    with socket.create_connection(host.get_connectable()) as tcp_sock:
        sni_name = sni_host.hostname if sni_host is not None else None
        with context.wrap_socket(tcp_sock, server_hostname=sni_name, session=session) as sock:
            request = (
                b"GET / HTTP/1.1\r\nHost: "
                + host_header_host.hostname.encode()
                + b"\r\nUser-Agent: cli/1\r\nAccept: */*\r\n\r\n"
            )
            sock.write(request)

            response = http.client.HTTPResponse(sock)
            response.begin()
            body = response.read()

            # print("[ ]", host)
            # print("[ ]", request)
            # print("[ ]", response.status, response.reason)
            return HttpsResponse(
                session=sock.session,
                response=response,
                body=body,
                session_reused=sock.session_reused,
                cert=sock.getpeercert(),
                peername=sock.getpeername(),
            )
