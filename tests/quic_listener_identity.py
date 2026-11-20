import os
import subprocess
import sys

from quic_multipath_early_listener import address
from quic_rebind import process, read_address


def check(listener, client, host):
    with process(listener, host, "identity") as server:
        listen = address(host, read_address(server))
        for seed in ("73", "74"):
            subprocess.run(
                (client, "dial", listen),
                env={**os.environ, "IROH_TEST_SEED": seed},
                check=True,
                timeout=20,
            )
        output, _ = server.communicate(timeout=5)
        print(output.decode(), end="", flush=True)
        if server.returncode:
            raise RuntimeError(f"listener peer identity check failed on {host}")


if __name__ == "__main__":
    listener, client = sys.argv[1:]
    for host in ("127.0.0.1", "::1"):
        check(listener, client, host)
