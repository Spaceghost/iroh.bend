import os
import selectors
import socket
import struct
import subprocess
import sys
import time
from contextlib import ExitStack
from http.server import HTTPServer
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event

from endpoint_candidate_lookup import (check_supplied_addresses, direct_ticket, initial_ids,
                                       ip_ticket, require_exchange, silent_socket, supplied_route)
from endpoint_lookup_race import dns_proxy, serve
from endpoint_ticket_urls import ticket
from pkarr_http import LABEL, Relay as PkarrRelay

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


# The upstream multipath fixture binds an endpoint with secret seed [42; 32].
SERVER_KEY = bytes.fromhex("197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61")


def check_ticket_paths(client, fixture, host, mode, both_live):
    with process(fixture, mode) as server:
        port = read_address(server)
        direct = ip_ticket(ticket([], SERVER_KEY), mode, [port])
        check_supplied_addresses(client, direct, mode, server, both_live, (host, str(port)))


def check_ticket_identity(client, fixture, host, mode):
    other_key = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    with process(fixture, mode) as server:
        port = read_address(server)
        wrong = ip_ticket(ticket([], other_key), mode, [port])
        result = subprocess.run((client, "dial-ticket", wrong, "direct", host, str(port)), capture_output=True, timeout=6)
        if not result.returncode or b"peer endpoint key mismatch" not in result.stderr:
            raise AssertionError(f"Multipath did not reject the wrong ticket identity: {result.stderr!r}")
        server.communicate(timeout=4)
        if not server.returncode:
            raise AssertionError("Iroh accepted the exchange with a mismatched ticket key")
    print(f"PASS {mode} rejected the wrong ticket identity and notified Iroh", flush=True)


def check_single_path_peer(client, fixture, host, mode):
    with process(fixture, "listen-single-path", host) as peer:
        port = read_address(peer)
        direct = ip_ticket(ticket([], SERVER_KEY), mode, [port])
        result = subprocess.run((client, "dial-ticket", direct, "direct", host, str(port)), capture_output=True, timeout=6)
        transcript, _ = peer.communicate(timeout=5)
        if (result.returncode != 95 or b"peer did not negotiate QUIC multipath" not in result.stderr
                or peer.returncode or b"PEER_CLOSED" not in transcript):
            raise AssertionError(f"Multipath refusal failed: {result.stderr!r}, single-path peer {transcript!r}")
    print(f"PASS {mode} single-path peer received the multipath dialer's close", flush=True)


def signed_address(address):
    # Pkarr signs the BEP 44 sequence and DNS wire message, excluding the key.
    name = b"\x05_iroh" + bytes([len(LABEL)]) + LABEL.encode() + b"\x00"
    txt = ("addr=" + address).encode("ascii")
    dns = struct.pack("!6H", 0, 0x8000, 0, 1, 0, 0)
    dns += name + struct.pack("!HHIH", 16, 1, 30, len(txt) + 1) + bytes([len(txt)]) + txt
    stamp = time.time_ns() // 1000
    with TemporaryDirectory() as tmp:
        key = Path(tmp, "fixture-key.der")
        key.write_bytes(bytes.fromhex("302e020100300506032b657004220420") + bytes([42]) * 32)
        message = Path(tmp, "signed-data")
        message.write_bytes(f"3:seqi{stamp}e1:v{len(dns)}:".encode() + dns)
        signature = subprocess.check_output(("openssl", "pkeyutl", "-sign", "-rawin", "-keyform", "DER",
                                             "-inkey", key, "-in", message))
    return signature + struct.pack("!Q", stamp) + dns


def pkarr_source(stack, address, gate):
    class HeldPacket(PkarrRelay):
        def do_GET(self):
            gate()
            super().do_GET()

    server = HTTPServer(("127.0.0.1", 0), HeldPacket)
    server.packet = signed_address(address)
    port = stack.enter_context(serve(server))
    return f"http://127.0.0.1:{port}/pkarr?token=test"


def check_ticket_discovery(client, fixture, host, mode, relay="", peer_relay="", pkarr=False):
    # Release the discovery reply only after the original socket emits its Initial.
    command = (fixture, mode, peer_relay) if relay else (fixture, mode)
    supplied = "listen" if mode == "listen6" else "listen6"
    with process(*command) as server, ExitStack() as stack:
        port = read_address(server)
        real = ip_ticket(ticket([], SERVER_KEY), mode, [port])
        stale = silent_socket(stack, supplied)
        changed = ip_ticket(real, supplied, [stale.getsockname()[1]])
        first, discovered = [], []

        def after_initial(*_):
            first.append(initial_ids(stale.recv(65535)))
            return True

        if relay:
            _, source = dns_proxy(stack, 0, after_initial, relay_url=peer_relay)
        else:
            release = Event()
            release.set()
            forwarded, _ = stack.enter_context(supplied_route(real, mode, release, discovered))
            _, (_, proxy_port) = direct_ticket(forwarded, mode, 1)
            address = f"[{host}]:{proxy_port}" if mode == "listen6" else f"{host}:{proxy_port}"
            if pkarr:
                source = pkarr_source(stack, address, after_initial)
            else:
                _, source = dns_proxy(stack, 0, after_initial, address=address)
        route = "relay" if relay else "direct"
        subprocess.run((client, "lookup-ticket", changed, route, host, str(port), source), timeout=10, check=True)
        require_exchange(server)
        if not first or (not relay and (not discovered or initial_ids(discovered[0]) != first[0])):
            raise AssertionError("The discovered multipath route did not continue the original handshake")
        protocol = "signed Pkarr" if pkarr else "DNS"
        print(f"PASS {supplied} ticket adopted {protocol} {route} for {mode} and used two paths", flush=True)


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


def check_routed_nat(client, fixture, host, mode, relay, peer_relay):
    with process(fixture, mode, peer_relay) as server:
        read_address(server)
        subprocess.run((client, host, "0", "0", relay, "auto"), timeout=20, check=True)
        transcript, _ = server.communicate(timeout=5)
        print(transcript.decode(), end="", flush=True)
        if server.returncode:
            raise RuntimeError(f"Iroh rejected the automatic NAT path on {host}")
        print(f"PASS default routed dial promoted an authenticated NAT candidate on {host}", flush=True)


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
    tickets = flags == ["--tickets"]
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
        if flags == ["--single-path"]:
            check_single_path_peer(client, fixture, host, mode)
            continue
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
        if tickets:
            check_ticket_identity(client, fixture, host, mode)
            check_ticket_paths(client, fixture, host, mode, both_live=False)
            check_ticket_paths(client, fixture, host, mode, both_live=True)
            check_ticket_discovery(client, fixture, host, mode)
            check_ticket_discovery(client, fixture, host, mode, pkarr=True)
            if relay:
                check_ticket_discovery(client, fixture, host, mode, relay, peer_relay)
            continue
        check(client, fixture, host, mode, family, "", "")
        if os.environ.get("CHECK_BINARY_ALPN") == "1":
            check(client, fixture, host, mode, family, "", "", binary=True)
        if relay:
            check(client, fixture, host, mode, family, relay, peer_relay)
            check_routed(client, fixture, host, mode, family, relay, peer_relay)
            check_routed_nat(client, fixture, host, mode, relay, peer_relay)
