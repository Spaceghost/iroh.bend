"""Exercise the concurrent lookup stream's item, error and terminal semantics."""

import selectors
import subprocess
from contextlib import ExitStack
from threading import Event

from endpoint_lookup_race import dns_proxy

BAD_PKARR = "error pkarr 1 invalid signed Pkarr endpoint packet"
BAD_DNS = "error dns 3 endpoint DNS lookup returned an error"


def lines(client, ticket, *sources):
    reply = subprocess.run((client, "lookup-events", ticket, *sources),
                           capture_output=True, text=True, timeout=8, check=True)
    return reply.stdout.splitlines()


def ordered(client, ticket, slow, fast, release, expected):
    with subprocess.Popen((client, "lookup-events", ticket, *slow, *fast), bufsize=0,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
        try:
            with selectors.DefaultSelector() as ready:
                ready.register(child.stdout, selectors.EVENT_READ)
                if not ready.select(5):
                    raise TimeoutError("The first lookup result waited for the second service")
                first = child.stdout.readline().decode().strip()
            if first != expected[0]:
                raise AssertionError((first, expected[0]))
            release.set()
            tail, errors = child.communicate(timeout=4)
            if child.returncode or tail.decode().splitlines() != expected[1:]:
                raise AssertionError((first, tail, errors))
        finally:
            release.set()
            if child.poll() is None:
                child.kill()
                child.communicate()


def check_events(client, ticket, pkarr, dns_port, invalid_url, family):
    if lines(client, ticket) != ["no service", "end"]:
        raise AssertionError("Empty service list did not yield its terminal error once")
    print(f"PASS {family} empty lookup stream", flush=True)

    valid = lines(client, ticket, "pkarr", pkarr, "dns", dns_port)
    if sorted(valid[:2]) != ["item dns", "item pkarr"] or valid[2:] != ["finished", "end"]:
        raise AssertionError(valid)
    print(f"PASS {family} both address records retain provider and endpoint ID", flush=True)

    for early_error in (True, False):
        release = Event()
        with ExitStack() as stack:
            slow = dns_proxy(stack, dns_port, lambda *_: release.wait(5), rcode=0 if early_error else 3)
            fast = ("pkarr", invalid_url if early_error else pkarr)
            sequence = [BAD_PKARR, "item dns"] if early_error else ["item pkarr", BAD_DNS]
            ordered(client, ticket, slow, fast, release, sequence + ["finished", "end"])
        print(f"PASS {family} {'error before item' if early_error else 'item before error'} and clean end", flush=True)

    with ExitStack() as stack:
        negative = dns_proxy(stack, dns_port, lambda *_: True, rcode=3)
        providers = ("pkarr", invalid_url, *negative, "pkarr", invalid_url)
        events = lines(client, ticket, *providers)
        inline = events[:3]
        expected = inline + ["no results"] + [s.replace("error ", "buffered ", 1) for s in inline] + ["end"]
        if sorted(inline) != sorted([BAD_PKARR, BAD_DNS, BAD_PKARR]) or events != expected:
            raise AssertionError(events)
        print(f"PASS {family} all three provider failures retained in arrival order", flush=True)

        dial = subprocess.run((client, "lookup-ticket", ticket, *providers),
                              capture_output=True, text=True, timeout=6)
        if (not dial.returncode or dial.stderr.count("invalid signed Pkarr endpoint packet") != 2
                or "endpoint DNS lookup returned an error" not in dial.stderr):
            raise AssertionError(dial)
        print(f"PASS {family} failed dial reports all providers", flush=True)
