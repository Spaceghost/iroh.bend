import socket
import subprocess
import sys

from quic_rebind import process, read_address


def check(client, fixture, host, mode, family, relay, peer_relay):
    command = (fixture, mode, peer_relay) if relay else (fixture, mode)
    with process(*command) as server:
        port = read_address(server)
        with socket.socket(family, socket.SOCK_DGRAM) as blackhole:
            blackhole.bind((host, 0))
            args = (client, host, str(port))
            if relay:
                args += (str(blackhole.getsockname()[1]), relay)
            subprocess.run(args, timeout=18, check=True)
        transcript, _ = server.communicate(timeout=5)
        print(transcript.decode(), end="", flush=True)
        if server.returncode:
            raise RuntimeError("Iroh rejected the multipath route exchange")


if __name__ == "__main__":
    client, fixture, relay, peer_relay = sys.argv[1:]
    if bool(relay) != bool(peer_relay):
        raise SystemExit("Set both RELAY_URL and UPSTREAM_IROH_RELAY_URL for relay cases")
    for host, mode, family in (
        ("127.0.0.1", "listen", socket.AF_INET),
        ("::1", "listen6", socket.AF_INET6),
    ):
        check(client, fixture, host, mode, family, "", "")
        if relay:
            check(client, fixture, host, mode, family, relay, peer_relay)
