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


def check_relay_nat(client, fixture, host, mode, relay, peer_relay):
    with process(fixture, mode, peer_relay) as server:
        read_address(server)
        subprocess.run((client, host, relay), timeout=24, check=True)
        transcript, _ = server.communicate(timeout=5)
        print(transcript.decode(), end="", flush=True)
        if server.returncode:
            raise RuntimeError(f"Iroh rejected the relay-to-NAT exchange on {host}")


def check_relay_qad(client, fixture, host, mode, relay, peer_relay, port, name, ca):
    with process(fixture, mode, peer_relay) as server:
        read_address(server)
        subprocess.run((client, host, relay, port, name, ca), timeout=28, check=True)
        transcript, _ = server.communicate(timeout=5)
        print(transcript.decode(), end="", flush=True)
        if server.returncode:
            raise RuntimeError(f"Iroh rejected the discovered UDP route on {host}")
    for tls_name, roots, expected in (
        ("invalid.iroh.example", ca, b"address discovery closed before an authenticated report"),
        (name, ca + ".missing", b"could not start authenticated address discovery"),
    ):
        with process(fixture, mode, peer_relay) as server:
            read_address(server)
            rejected = subprocess.run((client, host, relay, port, tls_name, roots), timeout=25, capture_output=True)
            if rejected.returncode == 0 or expected not in rejected.stderr:
                raise RuntimeError(f"unexpected QAD authentication result on {host}: {rejected.stderr!r}")
    print(f"PASS address discovery rejected the wrong TLS name and missing trust roots on {host}", flush=True)


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


def check_recovery(client, fixture, host, mode, family, relay, peer_relay, restore):
    with ExitStack() as stack:
        scenario = "2" if restore else "1"
        server = stack.enter_context(process("env", f"IROH_RELAY_RECOVERY={scenario}", fixture, mode, peer_relay))
        target = (host, read_address(server))
        gate = bind(stack, host, family)
        args = (client, host, str(gate.getsockname()[1]), relay)
        child = stack.enter_context(process(*args, "restore") if restore else process(*args))
        ready = stack.enter_context(selectors.DefaultSelector())
        ready.register(gate, selectors.EVENT_READ)
        ready.register(child.stdout, selectors.EVENT_READ)
        remote = None
        phase = "direct"
        dropped = 0
        report = (b"PASS open stream survived direct UDP restoration and a second outage" if restore else
                  b"PASS open stream continued on the relay after direct path loss")
        expected_phase = "blocked-again" if restore else "blocked"
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            events = sorted(ready.select(0.1), key=lambda event: event[0].fileobj != child.stdout)
            for key, _ in events:
                if key.fileobj == gate:
                    packet, sender = gate.recvfrom(65536)
                    if phase in ("blocked", "blocked-again"):
                        dropped += 1
                    elif sender[:2] == target:
                        if remote is not None:
                            gate.sendto(packet, remote)
                    else:
                        remote = sender
                        gate.sendto(packet, target)
                    continue
                line = child.stdout.readline().strip()
                if line == b"CUT_DIRECT" and phase == "direct" and remote is not None:
                    phase = "blocked"
                elif line == b"RESTORE_DIRECT" and restore and phase == "blocked" and dropped:
                    phase = "restored"
                    remote = None
                elif line == b"CUT_DIRECT" and restore and phase == "restored" and remote is not None:
                    phase = "blocked-again"
                elif line == report and phase == expected_phase and dropped:
                    if child.wait(timeout=5):
                        raise RuntimeError("Bend failed after recovering the relay path")
                    transcript, _ = server.communicate(timeout=5)
                    print(transcript.decode(), end="", flush=True)
                    if server.returncode:
                        raise RuntimeError("Iroh rejected the traffic after direct path loss")
                    print(f"{line.decode()} on {host}", flush=True)
                    return
                else:
                    raise RuntimeError(f"Unexpected recovery output {line!r} after {dropped} dropped packets")
        raise TimeoutError(f"Bend did not recover the relay path after dropping {dropped} packets")


if __name__ == "__main__":
    client, fixture, relay, peer_relay, *flags = sys.argv[1:]
    restore = flags == ["--restore-direct"]
    recovery = restore or flags == ["--recovery"]
    relay_nat = flags == ["--relay-nat"]
    relay_qad = len(flags) == 5 and flags[0] == "--relay-qad"
    if relay_qad and (flags[1] not in ("127.0.0.1", "::1") or not all(flags[2:])):
        raise SystemExit("Set QAD_TEST_IP, QAD_TEST_PORT, QAD_TEST_TLS_NAME and QAD_TEST_CA_BUNDLE")
    if bool(relay) != bool(peer_relay):
        raise SystemExit("Set both RELAY_URL and UPSTREAM_IROH_RELAY_URL for relay cases")
    if (recovery or relay_nat or relay_qad) and not relay:
        raise SystemExit("Relay tests require RELAY_URL and UPSTREAM_IROH_RELAY_URL")
    for host, mode, family in (
        ("127.0.0.1", "listen", socket.AF_INET),
        ("::1", "listen6", socket.AF_INET6),
    ):
        if relay_qad:
            _, local_ip, port, name, ca = flags
            if host == local_ip:
                check_relay_qad(client, fixture, host, mode, relay, peer_relay, port, name, ca)
            continue
        if relay_nat:
            check_relay_nat(client, fixture, host, mode, relay, peer_relay)
            continue
        if recovery:
            check_recovery(client, fixture, host, mode, family, relay, peer_relay, restore)
            continue
        check(client, fixture, host, mode, family, "", "")
        if os.environ.get("CHECK_BINARY_ALPN") == "1":
            check(client, fixture, host, mode, family, "", "", binary=True)
        if relay:
            check(client, fixture, host, mode, family, relay, peer_relay)
            check_routed(client, fixture, host, mode, family, relay, peer_relay)
