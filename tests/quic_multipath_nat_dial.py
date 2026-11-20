import selectors
import socket
import sys
import time
from contextlib import ExitStack

from quic_rebind import bind, process, read_address


def check(dialer, fixture, host, family, mode, automatic=False):
    with ExitStack() as stack:
        iroh = stack.enter_context(process(fixture, mode))
        direct_port = read_address(iroh)
        target = host, direct_port
        entrance = bind(stack, host, family)
        proxy_port = entrance.getsockname()[1]
        dial_mode = "iroh-nat-automatic" if automatic else "iroh-nat-punch"
        bend = stack.enter_context(process(dialer, host, str(proxy_port), dial_mode))
        ready = stack.enter_context(selectors.DefaultSelector())
        ready.register(entrance, selectors.EVENT_READ)
        ready.register(bend.stdout, selectors.EVENT_READ)
        ready.register(iroh.stdout, selectors.EVENT_READ)
        peers = {}
        response_prefix = b"PASS Bend dialer verified Iroh's PATH_RESPONSE from port "
        response_port = None
        direct_path = False
        open_outputs = 2
        deadline = time.monotonic() + 25
        while open_outputs:
            events = ready.select(max(0, deadline - time.monotonic()))
            if not events or time.monotonic() >= deadline:
                raise TimeoutError(f"dialer NAT probe stalled on {host}")
            for key, _ in events:
                source = key.fileobj
                if source == entrance:
                    packet, peer = entrance.recvfrom(65536)
                    if peer not in peers:
                        peers[peer] = bind(stack, host, family)
                        ready.register(peers[peer], selectors.EVENT_READ, peer)
                    peers[peer].sendto(packet, target)
                elif source in (bend.stdout, iroh.stdout):
                    line = source.readline()
                    if not line:
                        ready.unregister(source)
                        open_outputs -= 1
                    elif source == bend.stdout and line.startswith(response_prefix):
                        response_port = int(line.removeprefix(response_prefix))
                    elif source == bend.stdout and line.strip() in (
                        b"PASS Bend validated the new QUIC path on the punched UDP socket",
                        b"PASS Bend automatically opened the punched QUIC path",
                    ):
                        direct_path = True
                else:
                    packet, _ = source.recvfrom(65536)
                    entrance.sendto(packet, key.data)
        bend_status = bend.wait(timeout=2)
        iroh_status = iroh.wait(timeout=2)
        if bend_status or iroh_status:
            raise RuntimeError(f"dialer NAT probe failed on {host} ({bend_status}, {iroh_status})")
        if not automatic and (response_port != direct_port or response_port == proxy_port):
            raise RuntimeError(f"expected a response from Iroh's direct UDP port on {host}")
        if not direct_path:
            raise RuntimeError(f"expected application traffic on the punched QUIC path on {host}")
        if automatic:
            print(f"PASS Bend automatically opened Iroh's punched UDP path on {host}", flush=True)
        else:
            print(f"PASS Bend dialer opened Iroh's punched UDP path on {host}", flush=True)


if __name__ == "__main__":
    dialer, fixture = sys.argv[1:]
    check(dialer, fixture, "127.0.0.1", socket.AF_INET, "listen")
    check(dialer, fixture, "::1", socket.AF_INET6, "listen6")
    check(dialer, fixture, "127.0.0.1", socket.AF_INET, "listen", automatic=True)
    check(dialer, fixture, "::1", socket.AF_INET6, "listen6", automatic=True)
