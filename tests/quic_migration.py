import selectors
import socket
import sys
import time
from contextlib import ExitStack, suppress

from quic_rebind import bind, process, read_address


def check(client_binary, fixture, host, family, mode, allow_candidate):
    with ExitStack() as stack:
        server = stack.enter_context(process(fixture, mode))
        target = (host, read_address(server))
        entrance = bind(stack, host, family)
        original = bind(stack, host, family)
        candidate = bind(stack, host, family)
        legs = (original, candidate)
        for leg in legs:
            leg.connect(target)

        expected = 2 if allow_candidate else 3
        client = stack.enter_context(
            process(client_binary, host, str(entrance.getsockname()[1]), str(expected))
        )
        ready = stack.enter_context(selectors.DefaultSelector())
        for source in (entrance, original, candidate, client.stdout):
            ready.register(source, selectors.EVENT_READ)

        addresses = [None, None]
        reported_port = None
        validated = False
        passed = False
        candidate_packets = 0
        settled_packets = 0
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            if passed and client.poll() is not None and server.poll() is not None:
                if client.returncode or server.returncode:
                    raise RuntimeError("QUIC migration fixture failed")
                if not candidate_packets or not settled_packets or addresses[1][1] != reported_port:
                    raise RuntimeError("QUIC migration did not use the reported candidate socket")
                outcome = "validated the new path" if allow_candidate else "retained the original path"
                print(f"PASS Bend {outcome} on {host} with Iroh")
                return
            for key, _ in ready.select(0.1):
                source = key.fileobj
                if source == entrance:
                    payload, sender = entrance.recvfrom(65536)
                    if addresses[0] is None:
                        addresses[0] = sender
                    index = int(sender != addresses[0])
                    if addresses[index] not in (None, sender):
                        raise RuntimeError("QUIC dialer used more than two UDP addresses")
                    addresses[index] = sender
                    candidate_packets += index
                    if index == 1 and not allow_candidate:
                        continue
                    if validated:
                        if index != int(allow_candidate):
                            continue
                        settled_packets += 1
                    with suppress(ConnectionRefusedError):
                        legs[index].send(payload)
                elif source in legs:
                    index = legs.index(source)
                    with suppress(ConnectionRefusedError):
                        payload = source.recv(65536)
                        if not validated or index == int(allow_candidate):
                            entrance.sendto(payload, addresses[index])
                else:
                    line = source.readline().strip()
                    if line.startswith(b"CANDIDATE ") and reported_port is None:
                        reported_port = int(line.split()[1])
                    elif line == f"VALIDATION {expected}".encode() and not validated:
                        validated = True
                    elif line == b"PASS Bend kept the original QUIC connection and stream" and validated:
                        passed = True
                        ready.unregister(source)
                    else:
                        raise RuntimeError(f"unexpected QUIC migration output: {line!r}")
        raise TimeoutError(f"QUIC migration stalled on {host}")


if __name__ == "__main__":
    bend, iroh = sys.argv[1:]
    for host, family, mode in (
        ("127.0.0.1", socket.AF_INET, "listen"),
        ("::1", socket.AF_INET6, "listen6"),
    ):
        check(bend, iroh, host, family, mode, True)
        check(bend, iroh, host, family, mode, False)
