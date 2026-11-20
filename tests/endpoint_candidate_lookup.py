"""Exercise supplied and discovered routes during a single live QUIC handshake."""

import base64
import socket
import subprocess
from contextlib import ExitStack, contextmanager
from threading import Event, Thread

from endpoint_lookup_race import dns_proxy, relay_proxy
from endpoint_ticket_urls import varint


def direct_ticket(ticket, family, proxy_port):
    text = ticket.removeprefix("endpoint").upper()
    data = base64.b32decode(text + "=" * (-len(text) % 8))
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


def check_discovered_route(client, ticket, peer, pkarr, dns_port, family, kind):
    ipv6 = family == "listen6"
    observed, original = [], []
    released = Event()
    with ExitStack() as stack:
        stale = stack.enter_context(socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM))
        stale.bind(("::1" if ipv6 else "127.0.0.1", 0))
        stale.settimeout(3)
        changed, _ = direct_ticket(ticket, family, stale.getsockname()[1])

        def after_initial(*_):
            packet = stale.recv(65535)
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
        result = subprocess.run([client, "lookup-ticket-racing", changed, *args], capture_output=True, timeout=6)
        if result.returncode or not released.is_set():
            raise AssertionError(f"Discovered {kind} route did not win: {result.stderr!r}")
        transcript, _ = peer.communicate(timeout=3)
        if peer.returncode:
            raise AssertionError(f"Iroh rejected the discovered {kind} exchange: {transcript!r}")
        if kind == "dns" and (not observed or initial_ids(observed[0]) != original[0]):
            raise AssertionError("The discovered path started a separate QUIC connection")
    print(f"PASS {family} discovered {kind} route connects during the supplied handshake", flush=True)
