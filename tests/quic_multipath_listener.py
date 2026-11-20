import os
import selectors
import subprocess
import sys

from quic_rebind import process, read_address


def check(listener, fixture, host, mode, listener_mode="0"):
    command = (fixture, mode)
    if listener_mode == "2":
        command = ("env", "IROH_MULTIPATH_BINARY_ALPN=1", *command)
    if listener_mode == "3":
        command = ("env", "IROH_MULTIPATH_MULTIPLE_ALPNS=1", *command)
    if listener_mode == "4":
        command = ("env", "IROH_MULTIPATH_LIVE_ALPNS=1", *command)
    with process(*command) as iroh:
        read_address(iroh)
        with process(listener, host, listener_mode) as bend:
            port = read_address(bend)
            address = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            iroh.stdin.write(f"{address}\n".encode())
            if listener_mode == "4":
                with selectors.DefaultSelector() as ready:
                    ready.register(bend.stdout, selectors.EVENT_READ)
                    for expected in (b"SWITCHED\n", b"PAUSED\n"):
                        if not ready.select(10) or bend.stdout.readline() != expected:
                            raise RuntimeError(f"Bend did not reach {expected.strip().decode()} on {host}")
                        iroh.stdin.write(expected)
            output, _ = bend.communicate(timeout=25)
            print(output.decode(), end="", flush=True)
            report, _ = iroh.communicate(timeout=5)
            print(report.decode(), end="", flush=True)
            if bend.returncode or iroh.returncode:
                raise SystemExit(f"multipath listener interop failed on {host}")
            if listener_mode == "2":
                print(f"PASS Bend accepted Iroh with a 255-byte binary ALPN on {host}", flush=True)
            if listener_mode == "3":
                print(f"PASS Bend selected its preferred ALPN and the text fallback on {host}", flush=True)


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
    for host, mode in (("127.0.0.1", "dial"), ("::1", "dial6")):
        check(listener, fixture, host, mode)
        check_affinity(listener, dialer, host)
        if os.environ.get("CHECK_BINARY_ALPN") == "1":
            check(listener, fixture, host, mode, "2")
        if os.environ.get("CHECK_MULTIPLE_ALPNS") == "1":
            check(listener, fixture, host, mode, "3")
        if os.environ.get("CHECK_LIVE_ALPNS") == "1":
            check(listener, fixture, host, mode, "4")
