import subprocess
import sys
from contextlib import ExitStack

from quic_rebind import process, read_address


def address(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def check(listener, client, host, rotate):
    with ExitStack() as stack:
        warm = stack.enter_context(process(listener, host, "warm" if rotate else "reuse"))
        warm_addr = address(host, read_address(warm))
        if rotate:
            fresh = stack.enter_context(process(listener, host, "fresh"))
            target = address(host, read_address(fresh))
            command = (client, "dial-rotated", warm_addr, target)
        else:
            command = (client, "dial", warm_addr)
        subprocess.run(command, timeout=20, check=True)
        for server in (warm, fresh) if rotate else (warm,):
            output, _ = server.communicate(timeout=5)
            print(output.decode(), end="", flush=True)
            if server.returncode:
                raise RuntimeError(f"multipath resumption listener failed on {host}")


if __name__ == "__main__":
    for host in ("127.0.0.1", "::1"):
        for rotate in (False, True):
            check(*sys.argv[1:], host, rotate)
