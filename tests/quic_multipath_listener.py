import subprocess
import sys

from quic_rebind import process, read_address


def check(listener, fixture, host, mode):
    with process(fixture, mode) as iroh:
        read_address(iroh)
        with process(listener, host, "0") as bend:
            port = read_address(bend)
            address = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            iroh.stdin.write(f"{address}\n".encode())
            output, _ = bend.communicate(timeout=25)
            print(output.decode(), end="", flush=True)
            report, _ = iroh.communicate(timeout=5)
            print(report.decode(), end="", flush=True)
            if bend.returncode or iroh.returncode:
                raise SystemExit(f"multipath listener interop failed on {host}")


def check_affinity(listener, dialer, host):
    with process(listener, host, "1") as bend:
        port = read_address(bend)
        subprocess.run((dialer, host, str(port)), timeout=16, check=True)
        output, _ = bend.communicate(timeout=6)
        print(output.decode(), end="", flush=True)
        if bend.returncode:
            raise SystemExit(f"bidirectional multipath failed on {host}")


if __name__ == "__main__":
    listener, fixture, dialer = sys.argv[1:]
    check(listener, fixture, "127.0.0.1", "dial")
    check_affinity(listener, dialer, "127.0.0.1")
    check(listener, fixture, "::1", "dial6")
    check_affinity(listener, dialer, "::1")
