"""Exercise Bend's HTTP and WebSocket codecs on raw TCP and TLS listeners."""

import asyncio
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path

from relay_server_fragments import frame, unmask


def masked(opcode, payload):
    size = len(payload)
    if size < 126:
        length = bytes((128 | size,))
    elif size < 65536:
        length = b"\xfe" + size.to_bytes(2, "big")
    else:
        length = b"\xff" + size.to_bytes(8, "big")
    key = b"\x02\xf7\x19\x48"
    return bytes((opcode,)) + length + key + unmask(payload, key)


async def peer(port, tls, offer, expected, early=False):
    incoming, outgoing = await asyncio.open_connection("127.0.0.1", port, ssl=tls)
    if tls:
        assert outgoing.get_extra_info("ssl_object").selected_alpn_protocol() == "http/1.1"
    head = (
        "GET /relay?one=1 HTTP/1.1\r\nHost: localhost\r\n"
        "Upgrade: websocket\r\nConnection: keep-alive, UpGrAdE\r\n"
        "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        f"Sec-WebSocket-Protocol: {offer}\r\n\r\n"
    ).encode()
    outgoing.write(head[:-1])
    await outgoing.drain()
    # Hold the final byte until a separate application turn.
    await asyncio.sleep(0.025)
    outgoing.write(head[-1:] + (masked(0x89, b"prefix\x00") if early else b""))
    await outgoing.drain()

    reply = await incoming.readuntil(b"\r\n\r\n")
    assert reply.startswith(b"HTTP/1.1 101 "), reply
    assert b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n" in reply, reply
    assert f"Sec-WebSocket-Protocol: {expected}\r\n".encode() in reply, reply
    if early:
        opcode, payload, _ = await frame(incoming)
        assert (opcode, payload) == (0x8A, b"prefix\x00"), (opcode, payload)
    return incoming, outgoing


async def exchange(port, tls):
    incoming, outgoing = await peer(port, tls, "iroh-relay-v1, iroh-relay-v2", "iroh-relay-v2", early=True)
    peer_in, peer_out = await peer(port, tls, "iroh-relay-v1", "iroh-relay-v1")
    try:
        outgoing.write(masked(0x02, b"first\x00") + masked(0x89, b"middle") + masked(0x80, b"\xfflast"))
        peer_out.write(masked(0x82, b"independent"))
        await asyncio.gather(outgoing.drain(), peer_out.drain())
        assert (await frame(incoming))[:2] == (0x8A, b"middle")
        assert (await frame(incoming))[:2] == (0x82, b"first\x00\xfflast")
        assert (await frame(peer_in))[:2] == (0x82, b"independent")

        large = bytes(range(256)) * 256
        outgoing.write(masked(0x82, large))
        await outgoing.drain()
        assert (await frame(incoming))[:2] == (0x82, large)
        outgoing.write(masked(0x88, b"\x03\xe8"))
        await outgoing.drain()
        assert (await frame(incoming))[:2] == (0x88, b"\x03\xe8")
        assert await incoming.read() == b""
    finally:
        outgoing.close()
        peer_out.close()
        await asyncio.gather(outgoing.wait_closed(), peer_out.wait_closed(), return_exceptions=True)


async def check(binary, cert=None, key=None):
    setup = [str(cert), str(key)] if cert else []
    context = ssl.create_default_context(cafile=str(cert)) if cert else None
    if context:
        context.set_alpn_protocols(["h2", "http/1.1"])
    child = await asyncio.create_subprocess_exec(binary, *setup, stdout=asyncio.subprocess.PIPE)
    try:
        port = int(await asyncio.wait_for(child.stdout.readline(), 10))
        await asyncio.wait_for(exchange(port, context), 10)
        wire = "TLS" if context else "TCP"
        print(f"PASS Bend upgrades, fragmented frames, overlapping peers and clean close over raw {wire}")
    finally:
        if child.returncode is None:
            child.kill()
        await child.wait()


async def main(binary):
    await check(binary)
    with tempfile.TemporaryDirectory(prefix="iroh-relay-raw-") as root:
        cert, key = (Path(root) / name for name in ("cert.pem", "key.pem"))
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
             "-out", cert, "-keyout", key],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        await check(binary, cert, key)


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
