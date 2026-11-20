"""Drive the Bend endpoint with tickets printed by an upstream Iroh listener."""

import selectors
import subprocess
import sys

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


def check(client, fixture, family, mode, relay_url=None, error=None):
    args = (fixture, family, mode)
    if relay_url:
        args += (relay_url,)
    with process(*args) as server:
        ticket = read_ticket(server)
        if error:
            reject(client, ticket, error)
        else:
            route = "relay" if mode in ("fallback", "relay") else "direct"
            subprocess.run((client, "dial-ticket", ticket, route), timeout=16, check=True)
            transcript, _ = server.communicate(timeout=12)
            print(transcript.decode(), end="", flush=True)
            if server.returncode:
                raise RuntimeError(f"Iroh rejected the {family} {mode} ticket exchange")
    print(f"PASS {family} {mode} ticket", flush=True)


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


if __name__ == "__main__":
    main(*sys.argv[1:])
