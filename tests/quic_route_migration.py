import selectors
import socket
import subprocess
import sys
import time
from contextlib import ExitStack, suppress

from quic_rebind import bind, process, read_address


def to_direct(client, peer, relay, peer_relay, host, mode):
    with process(peer, mode, peer_relay) as server:
        port = read_address(server)
        subprocess.run((client, relay, host, str(port), "0"), timeout=24, check=True)
        if server.wait(timeout=5):
            raise RuntimeError("Iroh did not finish the original stream")
        print(f"PASS Bend migrated from the Iroh relay to the direct route at {host}")


def to_relay(client, peer, relay, peer_relay, host, family, mode, automatic=False):
    with ExitStack() as stack:
        server = stack.enter_context(process(peer, mode, peer_relay))
        port = read_address(server)
        entrance = bind(stack, host, family)
        upstream = bind(stack, host, family)
        upstream.connect((host, port))
        direction = "2" if automatic else "1"
        dial = stack.enter_context(process(client, relay, host, str(entrance.getsockname()[1]), direction))
        ready = stack.enter_context(selectors.DefaultSelector())
        for source in (dial.stdout, entrance, upstream):
            ready.register(source, selectors.EVENT_READ)
        address = None
        cut = False
        relayed = False
        dropped = 0
        deadline = time.monotonic() + 24
        while time.monotonic() < deadline:
            events = sorted(ready.select(0.1), key=lambda event: event[0].fileobj != dial.stdout)
            for key, _ in events:
                source = key.fileobj
                if source == dial.stdout:
                    line = dial.stdout.readline().strip()
                    if line == b"CUT_DIRECT" and automatic and not cut and address is not None:
                        cut = True
                    elif line == b"PASS relay path validated" and not relayed and (not automatic or dropped):
                        relayed = True
                        ready.unregister(entrance)
                        ready.unregister(upstream)
                    elif line == b"PASS Bend kept the original QUIC connection and stream" and relayed:
                        if dial.wait(timeout=3) or server.wait(timeout=5):
                            raise RuntimeError("Iroh did not finish the original stream")
                        recovery = "automatically recovered" if automatic else "migrated"
                        print(f"PASS Bend {recovery} from the direct route at {host} to the Iroh relay")
                        return
                    else:
                        raise RuntimeError(f"unexpected Bend route migration output: {line!r}")
                elif not relayed:
                    with suppress(ConnectionRefusedError):
                        if source == entrance:
                            payload, sender = entrance.recvfrom(65536)
                            if cut:
                                dropped += 1
                            else:
                                address = sender
                                upstream.send(payload)
                        else:
                            payload = upstream.recv(65536)
                            if not cut:
                                entrance.sendto(payload, address)
        raise TimeoutError(f"QUIC migration to the relay stalled on {host}")


if __name__ == "__main__":
    client, peer, relay, peer_relay = sys.argv[1:]
    if not relay or not peer_relay:
        raise SystemExit("Set RELAY_URL and UPSTREAM_IROH_RELAY_URL for the same relay")
    for host, family, mode in (
        ("127.0.0.1", socket.AF_INET, "listen"),
        ("::1", socket.AF_INET6, "listen6"),
    ):
        to_direct(client, peer, relay, peer_relay, host, mode)
        to_relay(client, peer, relay, peer_relay, host, family, mode)
        to_relay(client, peer, relay, peer_relay, host, family, mode, automatic=True)
