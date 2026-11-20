import asyncio
import sys
from urllib.parse import urlsplit

from relay_quic_reconnect import RelayProxy, child, expect


async def check(native, reference, url, origin, address):
    relay = urlsplit(url)
    proxy = RelayProxy(relay)
    async with await asyncio.start_server(proxy.handle, "127.0.0.1", 0) as listener:
        port = listener.sockets[0].getsockname()[1]
        bridge = relay._replace(netloc=f"{relay.hostname}:{port}").geturl()
        async with asyncio.timeout(28):
            async with child(native, bridge, address) as server:
                prefix = b"inbound NAT listener ready "
                line = await server.stdout.readline()
                if not line.startswith(prefix):
                    raise RuntimeError(f"Bend NAT listener failed to bind: {line!r}")
                direct_port = int(line[len(prefix):])
                direct = f"[{address}]:{direct_port}" if ":" in address else f"{address}:{direct_port}"
                await proxy.expect_attempt(True)
                async with child(reference, origin, direct) as iroh:
                    await expect(iroh, b"READY to disconnect the relay")
                    proxy.disconnect()
                    await proxy.expect_attempt(False)
                    iroh.stdin.write(b"RESUME\n")
                    await iroh.stdin.drain()
                    await expect(server, b"PASS Bend finished the accepted stream after relay loss")
                    await expect(iroh, b"PASS Iroh finished the original stream over direct UDP")
                    iroh.stdin.write(b"FINISH\n")
                    await iroh.stdin.drain()
                    if await iroh.wait() or await server.wait():
                        raise RuntimeError("inbound NAT fixture exited with an error")
    print(f"PASS inbound Iroh stream survived {relay.scheme} relay loss using {address}")


async def main(native, reference, url, origin):
    for address in ("127.0.0.2", "::1"):
        await check(native, reference, url, origin, address)


if __name__ == "__main__":
    asyncio.run(main(*sys.argv[1:]))
