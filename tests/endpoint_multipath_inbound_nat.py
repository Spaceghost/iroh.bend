import asyncio
import sys
from urllib.parse import urlsplit

from relay_quic_reconnect import RelayProxy, child, expect


async def check(native, reference, url, origin, address, observed=False):
    relay = urlsplit(url)
    proxy = RelayProxy(relay)
    ipv6_relay = ":" in relay.hostname
    proxy_ip = "::1" if ipv6_relay else "127.0.0.1"
    relay_host = f"[{relay.hostname}]" if ipv6_relay else relay.hostname
    async with await asyncio.start_server(proxy.handle, proxy_ip, 0) as listener:
        port = listener.sockets[0].getsockname()[1]
        bridge = relay._replace(netloc=f"{relay_host}:{port}").geturl()
        async with asyncio.timeout(55):
            async with child(native, bridge, "observed" if observed else address) as server:
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
                    await expect(server, b"PASS Bend finished the original accepted stream")
                    await expect(iroh, b"PASS Iroh finished the original stream over direct UDP")
                    iroh.stdin.write(b"FINISH\n")
                    await iroh.stdin.drain()
                    if await iroh.wait() or await server.wait():
                        raise RuntimeError("inbound NAT fixture exited with an error")
    source = "discovered" if observed else "explicit"
    print(f"PASS inbound Iroh stream survived {relay.scheme} relay loss using {source} address {address}")


async def main(native, reference, url, origin, mode="explicit"):
    if mode == "observed":
        host = urlsplit(url).hostname
        if host not in ("127.0.0.1", "::1"):
            raise ValueError("the QAD integration fixture requires a loopback relay")
        await check(native, reference, url, origin, host, observed=True)
    elif mode == "explicit":
        for address in ("127.0.0.2", "::1"):
            await check(native, reference, url, origin, address)
    else:
        raise ValueError(f"unknown NAT address source {mode!r}")


if __name__ == "__main__":
    asyncio.run(main(*sys.argv[1:]))
