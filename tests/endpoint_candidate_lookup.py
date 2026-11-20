"""Hold the supplied UDP route until the configured address lookup starts."""

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
def supplied_route(ticket, family, release):
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
