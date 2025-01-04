import cffi
import ssl
import sys
import os.path as op

_FFI = cffi.FFI()


_FFI.cdef(
    """
int get_ticket_bytes(const void* pysession, const unsigned char** out, size_t offset);
"""
)


with open(op.join(op.dirname(__file__), "openssl_ticket.c")) as f:
    _C = _FFI.verify(
        f.read(),
        "/tmp/openssl_ticket",
        include_dirs=["/usr/include/python-3.12"],
        libraries=["ssl"],
    )


def get_ticket_bytes(session) -> bytes:
    out = _FFI.new("unsigned char**")
    c_session = _FFI.cast("void*", id(session))
    ticket_length = _C.get_ticket_bytes(c_session, out, sys.getsizeof(None))
    # print(ticket_length)
    if ticket_length < 0:
        raise ValueError(f"Got no ticket (code {ticket_length})")
    return bytes(_FFI.unpack(out[0], ticket_length))


def main(connect_host, server_name, host_header):
    import socket
    import ssl

    context = ssl.create_default_context()
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.keylog_filename = "/tmp/keylogfile"
    with socket.create_connection(connect_host) as tcp_sock:
        with context.wrap_socket(tcp_sock, server_hostname=server_name) as sock:
            sock.send(b"GET / HTTP/1.1\r\nHost: " + host_header.encode() + b"\r\nConnection: close\r\n\r\n")
            response = sock.recv(4096)
            _empty = sock.recv(4096)
            print("Has Ticket", sock.session.has_ticket)
            ticket = get_ticket_bytes(sock.session)
            print("Ticket Len", len(ticket))
            print("Ticket    ", repr(ticket.hex()))
            sock.close()


if __name__ == "__main__":
    _host = "10.127.0.2"
    _sni = "b.com"
    _host_header = _sni
    main((_host, 443), _sni, _host_header)
