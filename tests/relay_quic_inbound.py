import selectors
import subprocess
import sys

from quic_rebind import process


def check(native, client, relay, origin):
    with process(native, "listen-relay-identity", relay) as server:
        with selectors.DefaultSelector() as ready:
            ready.register(server.stdout, selectors.EVENT_READ)
            if not ready.select(10) or server.stdout.readline() != b"relay identity listener ready\n":
                raise RuntimeError("Bend relay listener failed to register")
        subprocess.run((client, origin), timeout=22, check=True)
        output, _ = server.communicate(timeout=8)
        print(output.decode(), end="", flush=True)
        if server.returncode:
            raise RuntimeError("Bend relay listener did not complete both exchanges")


if __name__ == "__main__":
    check(*sys.argv[1:])
