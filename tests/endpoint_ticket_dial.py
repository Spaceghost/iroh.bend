"""Drive the Bend endpoint with tickets printed by an upstream Iroh listener."""

import base64
import selectors
import subprocess
import sys

from urllib.parse import urlsplit, urlunsplit

from endpoint_ticket_urls import ticket as encode_relays
from quic_rebind import process


def read_ticket(server):
    with selectors.DefaultSelector() as ready:
        ready.register(server.stdout, selectors.EVENT_READ)
        if not ready.select(12):
            raise TimeoutError("Iroh did not print its endpoint ticket")
        ticket = server.stdout.readline().strip().decode("ascii")
    if not ticket.startswith("endpoint"):
        raise ValueError(f"Expected an Iroh endpoint ticket, got {ticket!r}")
    return ticket


def reject(client, ticket, expected):
    result = subprocess.run((client, "dial-ticket", ticket, "direct"), capture_output=True, timeout=10)
    if result.returncode == 0 or expected not in result.stderr:
        raise RuntimeError(f"Expected {expected!r}, got exit {result.returncode} and {result.stderr!r}")


def relay_alias(ticket, relay_url):
    body = ticket.removeprefix("endpoint").upper()
    raw = base64.b32decode(body + "=" * (-len(body) % 8))
    key = raw[1:33]
    parts = urlsplit(relay_url)
    path = parts.path.rstrip("/") + "/"
    canonical = urlunsplit((parts.scheme, parts.netloc, path, parts.query, parts.fragment))
    if ticket != encode_relays([canonical], key):
        raise ValueError("Expected one relay URL in the Iroh fixture's ticket")
    alias = urlunsplit((parts.scheme.upper(), parts.netloc, path + "%2e/unused/..", "x=1", "fragment"))
    return encode_relays([alias], key)


def check(client, fixture, family, mode, relay_url=None, error=None, alternate_spelling=False):
    args = (fixture, family, mode)
    if relay_url:
        args += (relay_url,)
    with process(*args) as server:
        ticket = read_ticket(server)
        if alternate_spelling:
            ticket = relay_alias(ticket, relay_url)
        if error:
            reject(client, ticket, error)
        else:
            route = "relay" if mode in ("fallback", "relay") else "direct"
            subprocess.run((client, "dial-ticket", ticket, route), timeout=16, check=True)
            transcript, _ = server.communicate(timeout=12)
            print(transcript.decode(), end="", flush=True)
            if server.returncode:
                raise RuntimeError(f"Iroh rejected the {family} {mode} ticket exchange")
    label = "noncanonical relay" if alternate_spelling else mode
    print(f"PASS {family} {label} ticket", flush=True)


def main(client, fixture, relay_url):
    reject(client, "endpointaaaaaa", b"invalid endpoint ticket")
    for mode in ("id-only", "custom-only"):
        check(client, fixture, "listen", mode, error=b"no usable direct address or relay")
    for family in ("listen", "listen6"):
        check(client, fixture, family, "wrong-id", error=b"peer endpoint key mismatch")
        check(client, fixture, family, "direct")
        check(client, fixture, family, "custom-direct")
        if relay_url:
            for mode in ("mixed", "relay", "fallback"):
                check(client, fixture, family, mode, relay_url)
            check(client, fixture, family, "relay", relay_url, alternate_spelling=True)


if __name__ == "__main__":
    main(*sys.argv[1:])
