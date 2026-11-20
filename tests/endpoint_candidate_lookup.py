"""Exercise supplied and discovered routes during a single live QUIC handshake."""

import base64
import socket
import subprocess
from contextlib import ExitStack, contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Event, Thread

from endpoint_lookup_race import dns_proxy, relay_proxy, serve
from endpoint_ticket_urls import ticket as relay_ticket, varint


def decoded(ticket):
    text = ticket.removeprefix("endpoint").upper()
    return base64.b32decode(text + "=" * (-len(text) % 8))


def direct_ticket(ticket, family, proxy_port):
    data = decoded(ticket)
    af, tag, size = (socket.AF_INET, 0, 4) if family == "listen" else (socket.AF_INET6, 1, 16)
    if data[33:36] != bytes((1, 1, tag)):
        raise ValueError("Expected an Iroh ticket with one direct address in the requested family")
    ip = socket.inet_ntop(af, data[36:36 + size])
    port = sum((b & 127) << (7 * i) for i, b in enumerate(data[36 + size:]))
    proxy = data[:36 + size] + varint(proxy_port)
    return "endpoint" + base64.b32encode(proxy).decode().rstrip("=").lower(), (ip, port)


@contextmanager
def supplied_route(ticket, family, release, observed=None):
    af, host = (socket.AF_INET, "127.0.0.1") if family == "listen" else (socket.AF_INET6, "::1")
    done = Event()
    with socket.socket(af, socket.SOCK_DGRAM) as proxy:
        proxy.bind((host, 0))
        proxy.settimeout(0.05)
        changed, target = direct_ticket(ticket, family, proxy.getsockname()[1])
        first_packet = Event()

        def forward():
            client = None
            while not done.is_set():
                try:
                    packet, addr = proxy.recvfrom(65535)
                except TimeoutError:
                    continue
                if addr[:2] == target:
                    if client is not None:
                        proxy.sendto(packet, client)
                else:
                    client = addr
                    if observed is not None and not first_packet.is_set():
                        observed.append(packet)
                    first_packet.set()
                    if release.wait(2) and not done.is_set():
                        proxy.sendto(packet, target)

        thread = Thread(target=forward)
        thread.start()
        try:
            yield changed, first_packet
        finally:
            done.set()
            release.set()
            thread.join()


def check_supplied_route(client, ticket, peer, pkarr, dns_port, family, kind):
    active = Event()
    release = Event()
    with ExitStack() as stack:
        changed, first_packet = stack.enter_context(supplied_route(ticket, family, active))

        def hold_reply(*_):
            first_packet.wait(2)
            active.set()
            release.wait(4)
            return False

        if kind == "pkarr":
            args = relay_proxy(stack, pkarr, hold_reply)
        else:
            args = dns_proxy(stack, dns_port, hold_reply)
        try:
            result = subprocess.run([client, "lookup-ticket", changed, *args], capture_output=True, timeout=5)
            if result.returncode or not first_packet.is_set() or not active.is_set():
                raise AssertionError(f"{family} supplied route and {kind} lookup failed to overlap: {result.stderr!r}")
            peer.communicate(timeout=3)
            if peer.returncode:
                raise AssertionError("Iroh did not complete the exchange on the supplied direct route")
        finally:
            release.set()
    print(f"PASS {family} supplied direct handshake with {kind} lookup pending", flush=True)

def initial_ids(packet):
    if len(packet) < 1200 or packet[0] & 0xf0 != 0xc0 or int.from_bytes(packet[1:5], "big") != 1:
        raise AssertionError("Expected a QUIC v1 Initial")
    start = 6 + packet[5]
    return packet[6:start], packet[start+1:start+1+packet[start]]


def run_at_barrier(client, ticket, providers, connected):
    with socket.socket() as gate:
        gate.bind(("127.0.0.1", 0))
        gate.listen()
        gate.settimeout(5)
        command = [client, "lookup-ticket-racing-barrier", str(gate.getsockname()[1]), ticket, *providers]
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as bend:
            try:
                with gate.accept()[0] as barrier:
                    connected()
                    barrier.sendall(b"1")
                _, error = bend.communicate(timeout=5)
                if bend.returncode:
                    raise AssertionError(f"Ticket exchange after dial failed: {error!r}")
            finally:
                if bend.poll() is None:
                    bend.kill()
                    bend.communicate()


def check_discovered_route(client, ticket, peer, pkarr, dns_port, family, kind, cross_family=False, migrate=False):
    ipv6 = family == "listen6"
    observed, original, losing_socket = [], [], []
    released = Event()
    with ExitStack() as stack:
        supplied = ("listen" if ipv6 else "listen6") if cross_family else family
        stale = silent_socket(stack, supplied)
        changed = ip_ticket(ticket, supplied, [stale.getsockname()[1]])

        def after_initial(*_):
            packet, client_address = stale.recvfrom(65535)
            losing_socket.append(client_address)
            original.append(initial_ids(packet))
            released.set()
            return True

        if kind == "dns":
            ready = Event()
            ready.set()
            forwarded, _ = stack.enter_context(supplied_route(ticket, family, ready, observed))
            _, (host, port) = direct_ticket(forwarded, family, 1)
            address = f"[{host}]:{port}" if ipv6 else f"{host}:{port}"
            args = dns_proxy(stack, dns_port, after_initial, address=address)
        else:
            args = relay_proxy(stack, pkarr.rstrip("/"), after_initial)
        # The supplied address holds its packet for the full 12-second deadline.
        # Discovery must complete the authenticated exchange while it is silent.
        if migrate:
            result = subprocess.run([client, "lookup-ticket-migrate", changed, *args], capture_output=True, timeout=6)
            if result.returncode:
                raise AssertionError(f"Migration from the discovered path failed: {result.stderr!r}")
        else:
            def check_losing_socket():
                # The connection is still alive and the supplied handshake has
                # twelve seconds to run. Its unused socket must be released.
                with socket.socket(stale.family, socket.SOCK_DGRAM) as reopened:
                    reopened.bind(losing_socket[0])

            run_at_barrier(client, changed, args, check_losing_socket)
        if not released.is_set():
            raise AssertionError(f"Discovered {kind} route was never released")
        require_exchange(peer)
        if kind == "dns" and (not observed or initial_ids(observed[0]) != original[0]):
            raise AssertionError("The discovered path started a separate QUIC connection")
    detail = " and migrates to another local port" if migrate else ""
    print(f"PASS {family} discovered {kind} route connects during the {supplied} handshake{detail}", flush=True)

def ip_ticket(ticket, family, ports):
    ipv6 = family == "listen6"
    ip = socket.inet_pton(socket.AF_INET6 if ipv6 else socket.AF_INET, "::1" if ipv6 else "127.0.0.1")
    routes = b"".join(bytes((1, int(ipv6))) + ip + varint(port) for port in sorted(ports))
    wire = decoded(ticket)[:33] + varint(len(ports)) + routes
    return "endpoint" + base64.b32encode(wire).decode().rstrip("=").lower()


def silent_socket(stack, family):
    ipv6 = family == "listen6"
    sock = stack.enter_context(socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM))
    sock.bind(("::1" if ipv6 else "127.0.0.1", 0))
    sock.settimeout(3)
    return sock


def require_exchange(peer):
    transcript, _ = peer.communicate(timeout=4)
    if peer.returncode:
        raise AssertionError(f"Iroh rejected the ticket exchange: {transcript!r}")


def check_supplied_addresses(client, ticket, family, peer):
    release, observed = Event(), []
    with ExitStack() as stack:
        stale = silent_socket(stack, family)
        forwarded, _ = stack.enter_context(supplied_route(ticket, family, release, observed))
        _, (_, good_port) = direct_ticket(forwarded, family, 1)
        changed = ip_ticket(ticket, family, [good_port, stale.getsockname()[1]])
        with subprocess.Popen([client, "dial-ticket", changed, "direct"], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as bend:
            try:
                initial = initial_ids(stale.recv(65535))
                release.set()
                _, error = bend.communicate(timeout=5)
                if bend.returncode or not observed or initial != initial_ids(observed[0]):
                    raise AssertionError(f"Supplied addresses did not share one handshake: {error!r}")
                require_exchange(peer)
            finally:
                release.set()
                if bend.poll() is None:
                    bend.kill()
                    bend.communicate()
    print(f"PASS {family} two supplied addresses share one QUIC handshake", flush=True)


def check_discovered_relay(client, ticket, family, peer, relay_url):
    with ExitStack() as stack:
        stale = silent_socket(stack, family)
        changed = ip_ticket(ticket, family, [stale.getsockname()[1]])
        discovered = Event()

        def received_initial(*_):
            initial_ids(stale.recv(65535))
            discovered.set()
            return True

        args = dns_proxy(stack, 0, received_initial, relay_url=relay_url)
        result = subprocess.run([client, "lookup-ticket-racing-relay", changed, *args], capture_output=True, timeout=6)
        if result.returncode or not discovered.is_set():
            raise AssertionError(f"Could not adopt the discovered relay: {result.stderr!r}")
        require_exchange(peer)
    print(f"PASS {family} DNS supplies a working relay during the direct handshake", flush=True)


def check_pending_relay(client, ticket, family, peer):
    started, release = Event(), Event()

    class Pending(BaseHTTPRequestHandler):
        def do_GET(self):
            started.set()
            release.wait(8)

        def log_message(self, *_):
            pass

    with ExitStack() as stack:
        hold = stack.enter_context(serve(HTTPServer(("127.0.0.1", 0), Pending)))
        changed = relay_ticket([f"http://127.0.0.1:{hold}/"], decoded(ticket)[1:33])
        _, (host, port) = direct_ticket(ticket, family, 1)
        address = f"[{host}]:{port}" if family == "listen6" else f"{host}:{port}"
        args = dns_proxy(stack, 0, lambda *_: started.wait(3), address=address)
        def check_upgrade():
            if not started.is_set():
                raise AssertionError("The supplied relay never started its WebSocket upgrade")
            release.set()

        try:
            run_at_barrier(client, changed, args, check_upgrade)
            require_exchange(peer)
        finally:
            release.set()
    print(f"PASS {family} DNS supplies a working direct path during a relay upgrade", flush=True)
