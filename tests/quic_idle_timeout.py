"""Compare idle expiry on authenticated loopback connections with Iroh 1.5.0."""
import argparse
import asyncio

from relay_quic_reconnect import child


async def check(bend, reference, case, host, bend_listens, control):
    def args(listener, port):
        tested = listener == bend_listens
        if tested and not control:
            return [bend, host, str(port), case]
        address = f"[{host}]:{port}" if host == "::1" else f"{host}:{port}"
        mode = ["listen6" if host == "::1" else "listen"] if listener else ["dial", address]
        return [reference, *mode, case, *(["control"] if tested else [])]

    marker = f"PASS {case} timed out".encode()
    context = f"{case} {host} {'listener' if bend_listens else 'dialer'}"
    async with asyncio.timeout(18):
        async with child(*args(True, 0)) as server:
            port = int((await server.stdout.readline()).rsplit(b":", 1)[-1])
            async with child(*args(False, port)) as client:
                outputs = await asyncio.gather(server.communicate(), client.communicate())
                for name, proc, (output, _) in zip(("listener", "dialer"), (server, client), outputs):
                    if proc.returncode or marker not in output.splitlines():
                        raise RuntimeError(f"{context} {name} exited {proc.returncode}: {output!r}")
    print(f"PASS idle timeout {context}", flush=True)


async def run(args):
    for case in args.cases:
        await asyncio.gather(*(check(args.bend, args.reference, case, host, listens, args.control)
                               for host in ("127.0.0.1", "::1") for listens in (True, False)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bend")
    parser.add_argument("reference")
    parser.add_argument("--control", action="store_true")
    parser.add_argument("--cases", nargs="+", choices=("idle", "activity"), default=("idle", "activity"))
    asyncio.run(run(parser.parse_args()))
