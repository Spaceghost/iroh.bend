"""Check the HTTP routes exposed by the Iroh 1.5 relay."""

from http.client import HTTPConnection, HTTPSConnection
import json
import socket
import ssl
import sys
from urllib.parse import urlsplit


def pipelined(origin, context):
    with socket.create_connection((origin.hostname, origin.port), timeout=4) as raw:
        connection = context.wrap_socket(raw, server_hostname=origin.hostname) if context else raw
        with connection, connection.makefile("rb") as replies:
            connection.sendall(
                b"GET /ping HTTP/1.1\r\nHost: localhost\r\n\r\n"
                b"GET /robots.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            for body in (b"", b"User-agent: *\nDisallow: /\n"):
                assert replies.readline().startswith(b"HTTP/1.1 200 ")
                fields = {}
                while (line := replies.readline()) != b"\r\n":
                    assert line, "incomplete HTTP header"
                    name, value = line.split(b":", 1)
                    fields[name.lower()] = value.strip()
                assert replies.read(int(fields[b"content-length"])) == body
            assert replies.read(1) == b""


def exercise(origin, context):
    def check(path, expected, headers=None, method="GET"):
        if context is None:
            connection = HTTPConnection(origin.hostname, origin.port, timeout=4)
        else:
            connection = HTTPSConnection(origin.hostname, origin.port, timeout=4, context=context)
        try:
            connection.request(method, path, headers=headers or {})
            reply = connection.getresponse()
            fields = {name.lower(): value for name, value in reply.getheaders()}
            body = reply.read()
            assert reply.status == expected, (origin.geturl(), method, path, reply.status, expected, body)
            return fields, body
        finally:
            connection.close()
    for path in ("/", "/index.html"):
        fields, body = check(path, 200)
        assert fields["content-type"].startswith("text/html") and b"iroh.computer" in body
    fields, body = check("/ping?fixture=1", 200)
    assert fields["access-control-allow-origin"] == "*" and body == b""
    assert fields["strict-transport-security"] == "max-age=63072000; includeSubDomains"
    assert "frame-ancestors 'none'" in fields["content-security-policy"]
    _, body = check("/robots.txt", 200)
    assert body == b"User-agent: *\nDisallow: /\n"
    fields, body = check("/healthz", 200)
    assert fields["content-type"] == "application/json"
    assert json.loads(body)["status"] == "ok"
    if origin.scheme == "http":
        for challenge in ("123az__.", "A-0_", "a" * 63):
            fields, body = check("/generate_204", 204, {"X-Iroh-Challenge": challenge})
            assert body == b"" and fields["x-iroh-response"] == "response " + challenge
        for challenge in ("", "a" * 64, "a/b", "a b", "a,b"):
            fields, body = check("/generate_204", 204, {"X-Iroh-Challenge": challenge})
            assert body == b"" and "x-iroh-response" not in fields
        fields, body = check("/generate_204", 204)
        assert body == b"" and "x-iroh-response" not in fields
    else:
        check("/generate_204", 404, {"X-Iroh-Challenge": "valid"})
    check("/unknown", 404)
    check("/ping", 404, method="POST")
    pipelined(origin, context)
    print(f"PASS relay HTTP routes over {origin.scheme.upper()}")


if __name__ == "__main__":
    origin = urlsplit(sys.argv[1])
    tls_context = ssl.create_default_context(cafile=sys.argv[2]) if origin.scheme == "https" else None
    exercise(origin, tls_context)
