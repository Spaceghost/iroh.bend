import selectors
import socket
import sys
import time
from contextlib import ExitStack

from quic_rebind import bind, process


def check(server, client, relay, qad_port, host, refresh=False):
    ipv6 = ":" in host
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    with ExitStack() as stack:
        gate = stack.enter_context(socket.socket(family, socket.SOCK_DGRAM))
        gate.bind((host, 7842))
        outside = bind(stack, host, family)
        outside.connect((host, qad_port))
        replacement = bind(stack, host, family) if refresh else None
        if replacement:
            replacement.connect((host, qad_port))
        replacement_port = replacement.getsockname()[1] if replacement else 0
        blackhole = bind(stack, host, family)
        mapped_port = outside.getsockname()[1]
        peer = stack.enter_context(process(
            server, relay, str(blackhole.getsockname()[1]), "1", str(mapped_port), "6" if ipv6 else "4", str(replacement_port)
        ))
        ready = stack.enter_context(selectors.DefaultSelector())
        ready.register(peer.stdout, selectors.EVENT_READ)
        if not ready.select(10) or peer.stdout.readline() != b"READY\n":
            raise RuntimeError("Bend relay fixture did not become ready")
        ready.register(gate, selectors.EVENT_READ)
        ready.register(outside, selectors.EVENT_READ)
        if replacement:
            ready.register(replacement, selectors.EVENT_READ)
        dial = stack.enter_context(process(client, "qad-refresh" if refresh else host, "0", "0", relay, "auto"))

        source = None
        forwarder = outside
        transcript = []
        deadline = time.monotonic() + (44 if refresh else 14)
        while dial.poll() is None and time.monotonic() < deadline:
            for key, _ in ready.select(0.05):
                if key.fileobj is gate:
                    packet, sender = gate.recvfrom(65536)
                    if sender[1] == mapped_port or (source is not None and sender != source):
                        raise RuntimeError("unexpected discovery source")
                    source = sender
                    forwarder.send(packet)
                elif key.fileobj is peer.stdout:
                    line = peer.stdout.readline()
                    if not line:
                        ready.unregister(peer.stdout)
                    else:
                        transcript.append(line)
                        if replacement and b"advertised the relay-observed UDP mapping" in line:
                            forwarder = replacement
                elif source is not None:
                    gate.sendto(key.fileobj.recv(65536), source)

        output, _ = dial.communicate(timeout=1)
        print(output.decode(), end="", flush=True)
        if dial.returncode or source is None:
            print(b"".join(transcript).decode(), end="", flush=True)
            raise RuntimeError("the automatically discovered path was not promoted")
        output, _ = peer.communicate(timeout=6)
        observed = b"".join(transcript) + output
        print(observed.decode(), end="", flush=True)
        if peer.returncode or observed.count(b"PASS routed endpoint advertised the relay-observed UDP mapping") != (2 if refresh else 1):
            raise RuntimeError("the routed endpoint did not advertise the authenticated UDP mapping")
        if refresh:
            print("PASS changed QAD mapping advertised while the direct path stayed active", flush=True)


if __name__ == "__main__":
    server, client, relay, qad_port, host, *flags = sys.argv[1:]
    check(server, client, relay, int(qad_port), host, flags == ["--refresh"])
