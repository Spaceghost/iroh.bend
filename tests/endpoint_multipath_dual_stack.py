import selectors
import socket
import subprocess
import sys
from contextlib import ExitStack

from quic_rebind import bind, process


def check(server, client, relay, limit):
    with ExitStack() as stack:
        dead = bind(stack, "::1", socket.AF_INET6)
        peer = stack.enter_context(process(server, relay, str(dead.getsockname()[1]), str(limit), "0", "6", "0"))
        ready = stack.enter_context(selectors.DefaultSelector())
        ready.register(peer.stdout, selectors.EVENT_READ)
        if not ready.select(10) or peer.stdout.readline() != b"READY\n":
            raise RuntimeError("Bend relay fixture did not become ready")
        ready.unregister(peer.stdout)
        ready.register(dead, selectors.EVENT_READ)

        dial = stack.enter_context(process(client, "127.0.0.1", "0", "0", relay, "auto"))
        if not ready.select(5):
            raise RuntimeError("the first advertised IPv6 candidate was never probed")
        dead.recvfrom(65536)
        # This socket stays open and never responds. The peer adds the IPv4
        # candidate while the IPv6 probe round is still pending.
        output, _ = dial.communicate(timeout=12)
        print(output.decode(), end="", flush=True)
        if dial.returncode or b"PASS routed endpoint promoted the direct path" not in output:
            raise RuntimeError("IPv4 was not promoted while IPv6 probes went unanswered")
        output, _ = peer.communicate(timeout=6)
        print(output.decode(), end="", flush=True)
        if peer.returncode:
            raise RuntimeError("the relay fixture did not exchange data on both paths")
        print(f"PASS promoted IPv4 before unanswered IPv6 probes expired with candidate limit {limit}", flush=True)


if __name__ == "__main__":
    for limit in (64, 1):
        check(*sys.argv[1:], limit)
