import subprocess
import sys

from quic_multipath_early_listener import address
from quic_rebind import process, read_address


def check(bend, iroh, host, bend_listens):
    mode = "listen6" if host == "::1" else "listen"
    with process(*((bend, host, "0") if bend_listens else (iroh, mode))) as listener:
        port = read_address(listener)
        client = (iroh, "dial", address(host, port)) if bend_listens else (bend, host, str(port))
        subprocess.run(client, check=True, timeout=20)
        output, _ = listener.communicate(timeout=5)
        print(output.decode(), end="", flush=True)
        if listener.returncode:
            raise RuntimeError(f"stream cancellation listener exited {listener.returncode}")
    role = "listener" if bend_listens else "dialer"
    print(f"PASS Bend {role} interoperated with Iroh on {host}", flush=True)


if __name__ == "__main__":
    bend, iroh = sys.argv[1:]
    for host in ("127.0.0.1", "::1"):
        for bend_listens in (False, True):
            check(bend, iroh, host, bend_listens)
