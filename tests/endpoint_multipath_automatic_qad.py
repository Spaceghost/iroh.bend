import selectors
import socket
import sys
import time
from contextlib import ExitStack

from quic_rebind import bind, process


def check(server, client, relay, qad_port, host):
    ipv6 = ":" in host
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    with ExitStack() as stack:
        gate = stack.enter_context(socket.socket(family, socket.SOCK_DGRAM))
        gate.bind((host, 7842))
        outside = bind(stack, host, family)
        outside.connect((host, qad_port))
        blackhole = bind(stack, host, family)
        mapped_port = outside.getsockname()[1]
        peer = stack.enter_context(process(
            server, relay, str(blackhole.getsockname()[1]), "1", str(mapped_port), "6" if ipv6 else "4"
        ))
        ready = stack.enter_context(selectors.DefaultSelector())
        ready.register(peer.stdout, selectors.EVENT_READ)
        if not ready.select(10) or peer.stdout.readline() != b"READY\n":
            raise RuntimeError("Bend relay fixture did not become ready")
        ready.unregister(peer.stdout)
        ready.register(gate, selectors.EVENT_READ)
        ready.register(outside, selectors.EVENT_READ)
        dial = stack.enter_context(process(client, host, "0", "0", relay, "auto"))

        source = None
        deadline = time.monotonic() + 14
        while dial.poll() is None and time.monotonic() < deadline:
            for key, _ in ready.select(0.05):
                if key.fileobj is gate:
                    packet, sender = gate.recvfrom(65536)
                    if sender[1] == mapped_port or (source is not None and sender != source):
                        raise RuntimeError("unexpected discovery source")
                    source = sender
                    outside.send(packet)
                elif source is not None:
                    gate.sendto(outside.recv(65536), source)

        output, _ = dial.communicate(timeout=1)
        print(output.decode(), end="", flush=True)
        if dial.returncode or source is None:
            raise RuntimeError("the automatically discovered path was not promoted")
        output, _ = peer.communicate(timeout=6)
        print(output.decode(), end="", flush=True)
        if peer.returncode or b"PASS routed endpoint advertised the relay-observed UDP mapping" not in output:
            raise RuntimeError("the routed endpoint did not advertise the authenticated UDP mapping")


if __name__ == "__main__":
    server, client, relay, qad_port, host = sys.argv[1:]
    check(server, client, relay, int(qad_port), host)
