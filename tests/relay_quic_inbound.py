import asyncio
import sys

from relay_quic_reconnect import child, expect


async def confirmed(server, iroh, server_message, client_message):
    await expect(server, server_message)
    await expect(iroh, client_message)
    if iroh.returncode is None:
        try:
            iroh.stdin.write(b"FINISH\n")
            await iroh.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            pass  # Older fixture binaries exit after receiving the QUIC close.
    if await iroh.wait() or await server.wait():
        raise RuntimeError("inbound listener interoperability test failed")


async def check(native, client, relay, origin):
    async with asyncio.timeout(25):
        async with child(native, "listen-relay-identity", relay) as server:
            await expect(server, b"relay identity listener ready")
            async with child(client, origin) as iroh:
                await confirmed(
                    server, iroh,
                    b"PASS Bend accepted two authenticated identities over one relay registration",
                    b"PASS two overlapping Iroh peers exchanged streams and datagrams through one relay registration")
    print("PASS two overlapping Iroh peers exchanged streams and datagrams through one relay registration")


async def check_mixed(native, client, relay, origin):
    async with asyncio.timeout(25):
        async with child(native, "listen-direct-relay", relay) as server:
            prefix = b"direct and relay identity listener ready "
            line = await server.stdout.readline()
            if not line.startswith(prefix):
                raise RuntimeError(f"Bend mixed listener failed to bind: {line!r}")
            port = int(line[len(prefix):])
            async with child(client, origin, "direct-relay", f"127.0.0.2:{port}", f"[::1]:{port}") as iroh:
                await confirmed(
                    server, iroh,
                    b"PASS Bend authenticated three peers through the same listener",
                    b"PASS Iroh peers exchanged data over direct IPv4, direct IPv6 and relay routes")
    print("PASS three overlapping Iroh peers exchanged streams and datagrams over IPv4, IPv6 and relay")


if __name__ == "__main__":
    if sys.argv[1] == "--direct-relay":
        asyncio.run(check_mixed(*sys.argv[2:]))
    else:
        asyncio.run(check(*sys.argv[1:]))
