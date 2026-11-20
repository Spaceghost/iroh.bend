"""Verify the timeout negotiated by Iroh on a warm connection and its resumed successor."""
import argparse
import asyncio
from contextlib import AsyncExitStack

from relay_quic_reconnect import child


DEFAULT = 30_000
SHORT = 1_150
WIDE = 2**32 + 123


def words(value):
    return str(value >> 32), str(value & 0xffffffff)


async def output(process):
    lines = (await process.stdout.read()).decode().splitlines()
    return await process.wait(), lines


async def verify(processes, warm, resumed, quiet=False, relayed=False):
    results = await asyncio.gather(*(output(proc) for proc in processes))
    for status, lines in results:
        if status:
            raise RuntimeError(f"resumption fixture exited {status}: {lines}")
    observed = results[0][1]
    for stage, ms in (("warm", warm), ("resumed", resumed)):
        if f"IDLE {stage} {ms}" not in observed:
            raise AssertionError(f"Iroh did not confirm {stage} timeout {ms} ms: {observed}")
    if relayed and not {"RELAY warm", "RELAY resumed"}.issubset(observed):
        raise AssertionError(f"Iroh did not receive datagrams over the relay on both connections: {observed}")
    if quiet:
        expiry = [int(line.split()[1]) for line in observed if line.startswith("EXPIRED ")]
        if len(expiry) != 1 or not resumed - 175 <= expiry[0] < 8000:
            raise AssertionError(f"Iroh reported unexpected expiry time: {observed}")
        if "PASS resumed without early data and reported TimedOut" not in results[1][1]:
            raise AssertionError(f"Bend did not report idle expiry: {results[1][1]}")
        return expiry[0]


async def client_case(bend, reference, host, mode, resumed):
    listen = "listen6" if host == "::1" else "listen"
    suffix = {"accept": "", "reject": "-rotated", "quiet": "-idle"}[mode]
    async with child(reference, listen + suffix, str(DEFAULT), str(resumed)) as peer:
        endpoints = (await peer.stdout.readline()).decode().split()
        if len(endpoints) != 2:
            raise RuntimeError(f"Iroh did not announce its warm and resumed addresses: {endpoints}")
        ports = [str(int(addr.rsplit(":", 1)[1])) for addr in endpoints]
        async with child(bend, "client", host, *ports, mode, *words(resumed)) as conn:
            elapsed = await verify([peer, conn], DEFAULT, resumed, mode == "quiet")
    timing = f", expired after {elapsed} ms" if elapsed is not None else ""
    print(f"PASS Bend client {host} {mode} negotiated {DEFAULT} -> {resumed} ms{timing}", flush=True)


async def read_port(process, kind):
    announced = (await process.stdout.readline()).decode().strip()
    if not announced.isascii() or not announced.isdecimal() or int(announced) > 65535:
        raise RuntimeError(f"Bend {kind} listener did not announce a valid port: {announced!r}")
    return int(announced)


async def listener(stack, bend, host, mode, idle, kind):
    proc = await stack.enter_async_context(child(bend, kind, host, mode, *words(idle)))
    port = await read_port(proc, kind)
    return proc, f"[{host}]:{port}" if host == "::1" else f"{host}:{port}"


async def server_case(bend, reference, host, rotate, warm, resumed, kind="server"):
    async with AsyncExitStack() as stack:
        first, address = await listener(stack, bend, host, "warm" if rotate else "accept", warm, kind)
        servers = [first]
        args = ["dial", address]
        if rotate:
            second, target = await listener(stack, bend, host, "reject", resumed, kind)
            servers.append(second)
            args = ["dial-rotated", address, target]
        peer = await stack.enter_async_context(child(reference, *args, str(warm), str(resumed)))
        await verify([peer, *servers], warm, resumed)
    mode = "reject" if rotate else "accept"
    print(f"PASS Bend {kind} listener {host} {mode} negotiated {warm} -> {resumed} ms", flush=True)


async def relay_case(bend, reference, urls, kind, host, idle):
    async with child(bend, kind, urls[0], *words(idle)) as server:
        port = await read_port(server, kind)
        if (kind == "relay") != (port == 0):
            raise AssertionError(f"unexpected direct port {port} for {kind}")
        if host:
            address = f"[{host}]:{port}" if host == "::1" else f"{host}:{port}"
            args = ["dial", address]
        else:
            args = ["dial-relay", urls[1]]
        async with child(reference, *args, str(idle), str(idle)) as peer:
            await verify([peer, server], idle, idle, relayed=host is None)
    print(f"PASS Bend {kind} listener negotiated {idle} ms on warm and resumed {host or urls[0]} connections", flush=True)


async def run(bend, reference, urls):
    if urls:
        for kind, host, idle in [("relay", None, WIDE), ("direct-relay", None, SHORT),
                                 ("direct-relay", "127.0.0.1", SHORT), ("direct-relay", "::1", 0)]:
            await asyncio.wait_for(relay_case(bend, reference, urls, kind, host, idle), 30)
        return
    for host in ("127.0.0.1", "::1"):
        for mode, limit in [("accept", SHORT), ("accept", 0), ("reject", WIDE), ("quiet", SHORT)]:
            await asyncio.wait_for(client_case(bend, reference, host, mode, limit), 25)
        for rotate, warm, resumed in [(False, WIDE, WIDE), (True, WIDE, SHORT), (True, SHORT, 0)]:
            await asyncio.wait_for(server_case(bend, reference, host, rotate, warm, resumed), 25)
        for kind in ("identity", "dual"):
            for rotate, warm, resumed in [(False, SHORT, SHORT), (True, 0, WIDE)]:
                await asyncio.wait_for(server_case(bend, reference, host, rotate, warm, resumed, kind), 25)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bend")
    parser.add_argument("reference")
    parser.add_argument("--relay", nargs=2, metavar=("BEND_WS_URL", "IROH_HTTP_URL"))
    args = parser.parse_args()
    asyncio.run(run(args.bend, args.reference, args.relay))
