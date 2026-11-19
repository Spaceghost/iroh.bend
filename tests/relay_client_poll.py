"""Pause delivery inside a frame and between WebSocket fragments."""

from base64 import b64encode
from hashlib import sha1
from select import select
from socket import create_server
from subprocess import PIPE, Popen
from sys import argv

GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
SOURCE = bytes.fromhex("772c8a442b7db06e166cfbc1ccbcbcde6f3eba76a4e98ef3ffc519502237d6ef")
DATAGRAM = b"\x06" + SOURCE + b"\x03\x00\xff\x2a"


def ws_frame(opcode, data):
    assert len(data) < 126
    return bytes([opcode, len(data)]) + data


def client_frame(stream, opcode):
    data = stream.read(2)
    assert len(data) == 2 and data[0] == opcode and 0x80 <= data[1] < 0xFE, data
    size = data[1] & 0x7F
    mask = stream.read(4)
    body = stream.read(size)
    assert len(mask) == 4 and len(body) == size, (mask, body)
    return bytes(byte ^ mask[index % 4] for index, byte in enumerate(body))


def upgrade(conn, stream):
    assert stream.readline().startswith(b"GET /relay HTTP/1.1\r\n")
    headers = {}
    for line in stream:
        if line == b"\r\n":
            break
        name, value = line.split(b":", 1)
        headers[name.lower()] = value.strip()
    accept = b64encode(sha1(headers[b"sec-websocket-key"] + GUID).digest())
    conn.sendall(
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\nConnection: Upgrade\r\n"
        b"Sec-WebSocket-Protocol: iroh-relay-v2\r\nSec-WebSocket-Accept: " + accept + b"\r\n\r\n"
        + ws_frame(0x82, bytes(17))
    )
    proof = client_frame(stream, 0x82)
    assert len(proof) == 98 and proof[0] == 1, proof


def check(client, first, last):
    with create_server(("127.0.0.1", 0)) as listener:
        listener.settimeout(5)
        port = listener.getsockname()[1]
        with Popen([client, f"ws://127.0.0.1:{port}/relay", "poll-partial"], stdout=PIPE, stderr=PIPE) as child:
            try:
                conn, _ = listener.accept()
                with conn, conn.makefile("rb") as stream:
                    conn.settimeout(5)
                    upgrade(conn, stream)
                    conn.sendall(ws_frame(0x82, b"\x02") + first)
                    assert select([child.stdout], [], [], 5)[0], "client did not report the partial message"
                    assert child.stdout.readline() == b"relay message pending\n"
                    conn.sendall(last)
                    client_frame(stream, 0x88)
                    conn.sendall(ws_frame(0x88, b"\x03\xe8"))
                out, err = child.communicate(timeout=5)
                assert child.returncode == 0 and b"exchanged a datagram" in out, (out, err)
            finally:
                if child.poll() is None:
                    child.kill()


if __name__ == "__main__":
    packet = ws_frame(0x82, DATAGRAM)
    check(argv[1], packet[:12], packet[12:])
    check(argv[1], ws_frame(0x02, DATAGRAM[:12]), ws_frame(0x80, DATAGRAM[12:]))
    print("PASS relay receive deadlines preserve partial WebSocket messages")
