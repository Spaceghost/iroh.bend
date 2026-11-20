"""Dial upstream-issued tickets through DNS and signed Pkarr address lookup."""

import subprocess
import sys
from contextlib import ExitStack, contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Event, Thread
from urllib.request import Request, urlopen

from endpoint_candidate_lookup import check_discovered_route, check_supplied_route
from endpoint_lookup_events import check_events
from endpoint_lookup_race import check_race, check_stale_record, dns_proxy
from endpoint_ticket_dial import read_ticket
from quic_rebind import process


class InvalidSignature(BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.requests.append(self.path)
        packet = self.server.packet
        self.send_response(200)
        self.send_header("Content-Length", str(len(packet)))
        self.end_headers()
        self.wfile.write(packet)
        self.server.sent.set()

    def log_message(self, *_):
        pass


@contextmanager
def invalid_relay():
    with HTTPServer(("127.0.0.1", 0), InvalidSignature) as server:
        server.requests = []
        server.sent = Event()
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
        thread.start()
        try:
            yield server
        finally:
            server.shutdown()
            thread.join()


def check(client, fixture, family, mode, source, pkarr, dns_port, invalid=None, expected_error=None):
    with process(fixture, family, mode) as peer, ExitStack() as stack:
        ticket, label, payload = read_ticket(peer).split()
        packet = bytes.fromhex(payload)
        request = Request(f"{pkarr.rstrip('/')}/{label}", data=packet, method="PUT",
                          headers={"Content-Type": "application/octet-stream"})
        with urlopen(request, timeout=5) as response:
            if response.status != 204:
                raise RuntimeError(f"Pkarr publication failed with HTTP {response.status}")

        if source in ("discovered-dns", "discovered-pkarr"):
            check_discovered_route(client, ticket, peer, pkarr, dns_port, family, source.removeprefix("discovered-"))
            return
        if source in ("supplied-dns", "supplied-pkarr"):
            check_supplied_route(client, ticket, peer, pkarr, dns_port, family, source.removeprefix("supplied-"))
            return
        if source == "stale-record":
            check_stale_record(client, ticket, peer, pkarr, dns_port, family)
            print(f"PASS {family} failed resolved DNS address followed by authenticated Pkarr address", flush=True)
            return
        if isinstance(source, tuple):
            check_race(client, ticket, peer, pkarr, dns_port, *source)
            print(f"PASS {family} authenticated {source[1]} exchange with {source[0]} pending", flush=True)
            return

        base = pkarr
        if invalid:
            invalid.requests.clear()
            invalid.sent.clear()
            invalid.packet = bytes([packet[0] ^ 1]) + packet[1:]
            base = f"http://127.0.0.1:{invalid.server_port}/pkarr"
        if source == "stream":
            check_events(client, ticket, pkarr, dns_port, base, family)
            return
        if invalid and source == "pkarr-dns":
            _, dns_port = dns_proxy(stack, dns_port, lambda *_: invalid.sent.wait(4))
        args = {"dns": ("dns", dns_port), "pkarr": ("pkarr", base), "pkarr-dns": ("pkarr", base, "dns", dns_port)}
        result = subprocess.run((client, "lookup-ticket", ticket, *args[source]),
                                capture_output=True, timeout=15)
        if expected_error:
            if result.returncode == 0 or expected_error not in result.stderr:
                raise RuntimeError(f"Expected {expected_error!r}, got {result}")
        else:
            if result.returncode:
                raise RuntimeError(f"Bend {mode} ticket via {source}: {result.stderr.decode()}")
            transcript, _ = peer.communicate(timeout=12)
            if peer.returncode:
                raise RuntimeError(f"Iroh rejected the {mode} ticket exchange: {transcript!r}")
        if invalid:
            expected_requests = [f"/pkarr/{label}"]
            # A fast supplied path may win before the HTTP request reaches the server.
            if invalid.requests != expected_requests and (mode != "direct" or invalid.requests):
                raise AssertionError(f"Unexpected lookup requests: {invalid.requests}")
    detail = expected_error.decode() if expected_error else "authenticated exchange"
    if invalid and mode == "direct":
        detail = "supplied route usable during lookup"
    elif invalid and source == "pkarr-dns":
        detail = "authenticated DNS route after signature rejection"
    print(f"PASS {family} {mode} ticket via {source} ({detail})", flush=True)


def main(client, fixture, pkarr, dns_port):
    with invalid_relay() as invalid:
        for family in ("listen", "listen6"):
            check(client, fixture, family, "id-only", "stream", pkarr, dns_port, invalid)
            check(client, fixture, family, "id-only", "stale-record", pkarr, dns_port)
            for source in ("dns", "pkarr"):
                for mode in ("id-only", "stale"):
                    check(client, fixture, family, mode, source, pkarr, dns_port)
                check(client, fixture, family, "wrong-id", source, pkarr, dns_port,
                      expected_error=b"peer endpoint key mismatch")
            for kind in ("supplied-dns", "supplied-pkarr", "discovered-dns", "discovered-pkarr"):
                check(client, fixture, family, "direct", kind, pkarr, dns_port)
            check(client, fixture, family, "direct", "pkarr", pkarr, dns_port, invalid)
            check(client, fixture, family, "id-only", "pkarr", pkarr, dns_port, invalid,
                  expected_error=b"invalid signed Pkarr endpoint packet")
            check(client, fixture, family, "id-only", "pkarr-dns", pkarr, dns_port, invalid)
            for slow, fast in (("dns", "pkarr"), ("pkarr", "dns"), ("dns", "dns"), ("pkarr", "pkarr"),
                               ("dns-tcp", "pkarr"), ("pkarr", "dns-tcp"), ("dns-tcp-body", "pkarr")):
                check(client, fixture, family, "id-only", (slow, fast), pkarr, dns_port)


if __name__ == "__main__":
    main(*sys.argv[1:])
