import os
import selectors
import socket
import subprocess
import sys
import time
from contextlib import ExitStack

from quic_rebind import bind, process, read_address


def check(client, fixture, host, mode, family, relay, peer_relay, binary=False):
    command = (fixture, mode, peer_relay) if relay else (fixture, mode)
    if binary:
        command = ("env", "IROH_MULTIPATH_BINARY_ALPN=1", *command)
    with process(*command) as server:
        port = read_address(server)
        with socket.socket(family, socket.SOCK_DGRAM) as blackhole:
            blackhole.bind((host, 0))
            args = (client, host, str(port))
            if relay:
                args += (str(blackhole.getsockname()[1]), relay)
            if binary:
                args += ("binary",)
            subprocess.run(args, timeout=18, check=True)
        transcript, _ = server.communicate(timeout=5)
        print(transcript.decode(), end="", flush=True)
        if server.returncode:
            raise RuntimeError("Iroh rejected the multipath route exchange")
        if binary:
            print(f"PASS Bend endpoint dialed Iroh with a 255-byte binary ALPN on {host}", flush=True)


def check_routed(client, fixture, host, mode, family, relay, peer_relay):
    with ExitStack() as stack:
        server = stack.enter_context(process(fixture, mode, peer_relay))
        target = (host, read_address(server))
        blocked = bind(stack, host, family)
        gated = bind(stack, host, family)
        child = stack.enter_context(process(
            client, host, str(blocked.getsockname()[1]), str(gated.getsockname()[1]), relay, "auto"
        ))
        ready = stack.enter_context(selectors.DefaultSelector())
        ready.register(blocked, selectors.EVENT_READ)
        ready.register(gated, selectors.EVENT_READ)
        ready.register(child.stdout, selectors.EVENT_READ)
        enabled = False
        remote = None
        dropped = 0
        forwarded = 0
        deadline = time.monotonic() + 16
        while time.monotonic() < deadline:
            for key, _ in ready.select(max(0, deadline - time.monotonic())):
                if key.fileobj == blocked:
                    blocked.recvfrom(65536)
                    dropped += 1
                elif key.fileobj == gated:
                    packet, sender = gated.recvfrom(65536)
                    if sender[:2] == target:
                        if remote is not None:
                            gated.sendto(packet, remote)
                    elif enabled:
                        remote = sender
                        gated.sendto(packet, target)
                        forwarded += 1
                else:
                    line = child.stdout.readline().strip()
                    if line == b"ENABLE_DIRECT":
                        enabled = True
                    elif line == b"PASS routed endpoint promoted the direct path":
                        print(line.decode(), flush=True)
                        if child.wait(timeout=5) != 0:
                            raise RuntimeError("Bend failed after promoting the direct path")
                        transcript, _ = server.communicate(timeout=5)
                        print(transcript.decode(), end="", flush=True)
                        if server.returncode:
                            raise RuntimeError("Iroh rejected the automatic path exchange")
                        return
                    elif not line:
                        raise RuntimeError(
                            f"Bend exited during automatic path selection after {dropped} blocked "
                            f"and {forwarded} forwarded UDP packets"
                        )
                    else:
                        raise RuntimeError(f"Unexpected Bend output {line!r}")
        raise TimeoutError("Bend did not promote the direct path")


if __name__ == "__main__":
    client, fixture, relay, peer_relay = sys.argv[1:]
    if bool(relay) != bool(peer_relay):
        raise SystemExit("Set both RELAY_URL and UPSTREAM_IROH_RELAY_URL for relay cases")
    for host, mode, family in (
        ("127.0.0.1", "listen", socket.AF_INET),
        ("::1", "listen6", socket.AF_INET6),
    ):
        check(client, fixture, host, mode, family, "", "")
        if os.environ.get("CHECK_BINARY_ALPN") == "1":
            check(client, fixture, host, mode, family, "", "", binary=True)
        if relay:
            check(client, fixture, host, mode, family, relay, peer_relay)
            check_routed(client, fixture, host, mode, family, relay, peer_relay)
