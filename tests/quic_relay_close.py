"""Check application close over a relay-only route, using the public endpoint owners."""
import argparse
import asyncio
from urllib.parse import urlsplit

from relay_quic_reconnect import child, expect


async def passed(process, role, case):
    output, _ = await process.communicate()
    marker = f"PASS close {case}".encode()
    if process.returncode or marker not in output.splitlines():
        raise RuntimeError(f"{role} exited {process.returncode}: {output.decode(errors='replace')}")


async def exchange(bend, peer, relay, origin, listens, sends, case, control):
    def command(listener):
        tested = listener == listens
        native = tested and not control
        role = "listen" if listener else "dial"
        op = "send" if tested == sends else "receive"
        return [bend if native else peer, role, relay if native else origin, op, str(case),
                *(["control"] if tested and control else [])]

    context = f"{urlsplit(relay).scheme} {'listener' if listens else 'dialer'} {'send' if sends else 'receive'} {case}"
    try:
        async with asyncio.timeout(28):
            async with child(*command(True)) as server:
                await expect(server, b"READY relay")
                async with child(*command(False)) as client:
                    await asyncio.gather(passed(server, "listener", case), passed(client, "dialer", case))
    except (TimeoutError, RuntimeError) as error:
        raise RuntimeError(f"relay close {context}: {error}") from error
    print(f"PASS relay close {context}", flush=True)


async def run(args):
    for case in args.cases:
        for listens in (True, False):
            for sends in (True, False):
                await exchange(args.bend, args.peer, args.relay, args.origin, listens, sends, case, args.control)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bend")
    parser.add_argument("peer")
    parser.add_argument("relay", help="Bend WebSocket URL including /relay")
    parser.add_argument("origin", help="Iroh HTTP or HTTPS relay base URL")
    parser.add_argument("--control", action="store_true")
    parser.add_argument("--cases", nargs="+", type=int, choices=range(8), default=range(8))
    asyncio.run(run(parser.parse_args()))
