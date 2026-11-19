"""Check challenge freshness, plaintext exporter fallback and malformed proof handling."""

from base64 import b64encode, urlsafe_b64encode
from os import urandom
from socket import create_connection
from sys import argv

KEY = bytes.fromhex("197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61")


def frame(stream):
    prefix = stream.read(2)
    assert len(prefix) == 2, prefix
    op, size = prefix
    assert size < 126, prefix
    payload = stream.read(size)
    assert len(payload) == size
    return op, payload


def challenge(port, auth=None, malformed=False):
    with create_connection(("127.0.0.1", port), timeout=4) as ws, ws.makefile("rb") as stream:
        token = b64encode(urandom(16)).decode()
        request = (
            f"GET /relay HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n"
            "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Key: {token}\r\nSec-WebSocket-Protocol: iroh-relay-v2\r\n"
        )
        if auth is not None:
            request += f"X-Iroh-Relay-Client-Auth-V1: {auth}\r\n"
        ws.sendall((request + "\r\n").encode())
        assert stream.readline().startswith(b"HTTP/1.1 101 ")
        for line in stream:
            if line == b"\r\n":
                break
        else:
            raise AssertionError("upgrade response ended before its headers")
        if malformed:
            first_byte = stream.read(1)
            assert first_byte in (b"", b"\x88"), first_byte
            return None
        op, nonce = frame(stream)
        assert op == 0x82 and len(nonce) == 17 and nonce[0] == 0

        proof = b"\x01" + KEY + b"\x40" + bytes(64)
        mask = urandom(4)
        body = bytes(byte ^ mask[i % 4] for i, byte in enumerate(proof))
        ws.sendall(bytes([0x82, 0x80 | len(body)]) + mask + body)
        op, response = frame(stream)
        assert op == 0x82 and response == b"\x03\x11signature invalid", response
        return nonce


port = int(argv[1])
formatted_proof = urlsafe_b64encode(KEY + b"\x40" + bytes(80)).rstrip(b"=").decode()
assert challenge(port) != challenge(port, auth=formatted_proof)
challenge(port, auth="!" * 151, malformed=True)
challenge(port, auth=formatted_proof[:-1] + "B", malformed=True)
challenge(port, auth="short", malformed=True)
print("PASS relay challenge freshness, exporter fallback and malformed proof rejection")
