"""Translate the Iroh 1.5.0 pre-route checks in Endpoint::connect_with_opts."""

import select
import socket
import subprocess
import sys


EXPECTED = {
    "self": "Connecting to ourself is not supported",
    "empty": "Invalid ALPN",
    "both": "Connecting to ourself is not supported",
}


def message(command):
    result = subprocess.run(command, text=True, capture_output=True, timeout=8)
    if result.returncode:
        raise RuntimeError(f"{command} exited {result.returncode}: {result.stderr}")
    return result.stdout.strip()


def main(client, backend, upstream):
    modes = ("routes", "stream", "dns", "lookup") if backend == "endpoint" else (
        "address", "routes", "dns", "nat-direct", "nat-relay"
    )
    with socket.socket(type=socket.SOCK_DGRAM) as udp, socket.socket() as tcp:
        udp.bind(("127.0.0.1", 0))
        host, port = udp.getsockname()
        tcp.bind((host, port))
        tcp.listen()
        for choice, expected in EXPECTED.items():
            if upstream and message((upstream, choice, f"{host}:{port}")) != expected:
                raise AssertionError(f"Iroh returned a different error for {choice}")
            for mode in modes:
                got = message((client, "options", mode, choice, str(port)))
                if got != expected:
                    raise AssertionError(f"{backend} {mode} {choice}: expected {expected!r}, got {got!r}")
                if select.select([udp, tcp], [], [], 0)[0]:
                    raise AssertionError(f"{backend} {mode} {choice} started network I/O")
            print(f"PASS {backend} {choice}: {expected} before network I/O", flush=True)


if __name__ == "__main__":
    main(*sys.argv[1:])
