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


async def verify(processes, warm, resumed, quiet=False):
    results = await asyncio.gather(*(output(proc) for proc in processes))
    for status, lines in results:
        if status:
            raise RuntimeError(f"resumption fixture exited {status}: {lines}")
    observed = results[0][1]
    for stage, ms in (("warm", warm), ("resumed", resumed)):
        if f"IDLE {stage} {ms}" not in observed:
            raise AssertionError(f"Iroh did not confirm {stage} timeout {ms} ms: {observed}")
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


async def listener(stack, bend, host, mode, idle):
    proc = await stack.enter_async_context(child(bend, "server", host, mode, *words(idle)))
    port = int(await proc.stdout.readline())
    return proc, f"[{host}]:{port}" if host == "::1" else f"{host}:{port}"


async def server_case(bend, reference, host, rotate, warm, resumed):
    async with AsyncExitStack() as stack:
        first, address = await listener(stack, bend, host, "warm" if rotate else "accept", warm)
        servers = [first]
        args = ["dial", address]
        if rotate:
            second, target = await listener(stack, bend, host, "reject", resumed)
            servers.append(second)
            args = ["dial-rotated", address, target]
        peer = await stack.enter_async_context(child(reference, *args, str(warm), str(resumed)))
        await verify([peer, *servers], warm, resumed)
    mode = "reject" if rotate else "accept"
    print(f"PASS Bend listener {host} {mode} negotiated {warm} -> {resumed} ms", flush=True)


async def run(bend, reference):
    for host in ("127.0.0.1", "::1"):
        for mode, limit in [("accept", SHORT), ("accept", 0), ("reject", WIDE), ("quiet", SHORT)]:
            await asyncio.wait_for(client_case(bend, reference, host, mode, limit), 25)
        for rotate, warm, resumed in [(False, WIDE, WIDE), (True, WIDE, SHORT), (True, SHORT, 0)]:
            await asyncio.wait_for(server_case(bend, reference, host, rotate, warm, resumed), 25)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bend")
    parser.add_argument("reference")
    args = parser.parse_args()
    asyncio.run(run(args.bend, args.reference))
