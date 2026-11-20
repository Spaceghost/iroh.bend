import os
import selectors
import socket
import subprocess
import sys
import time
from contextlib import ExitStack

from quic_rebind import bind, process, read_address


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


def check_affinity(listener, dialer, host, mode="1", *args):
    with process(listener, host, mode) as bend:
        port = read_address(bend)
        subprocess.run((dialer, host, str(port), *args), timeout=16, check=True)
        output, _ = bend.communicate(timeout=6)
        print(output.decode(), end="", flush=True)
        if bend.returncode:
            raise SystemExit(f"bidirectional multipath failed on {host}")


def check_off_path(listener, fixture, host, mode, drop_first=False, automatic=False):
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with ExitStack() as stack:
        gate = bind(stack, host, family) if drop_first else None
        gate_port = gate.getsockname()[1] if gate else None
        listener_mode = "8" if automatic else str(gate_port) if gate else "6"
        bend = stack.enter_context(process(listener, host, listener_mode))
        target = host, read_address(bend)
        iroh = stack.enter_context(process(fixture, mode))
        direct_port = read_address(iroh)
        entrance = bind(stack, host, family)
        proxy_port = entrance.getsockname()[1]
        address = f"[{host}]:{proxy_port}" if family == socket.AF_INET6 else f"{host}:{proxy_port}"
        iroh.stdin.write(f"{address}\n".encode())

        ready = stack.enter_context(selectors.DefaultSelector())
        ready.register(entrance, selectors.EVENT_READ)
        ready.register(iroh.stdout, selectors.EVENT_READ)
        ready.register(bend.stdout, selectors.EVENT_READ)
        peers = {}
        gate_sends = []
        if gate:
            ready.register(gate, selectors.EVENT_READ)
        response_prefix = b"PASS Iroh returned an authenticated PATH_RESPONSE from port "
        response_port = None
        open_outputs = 2
        deadline = time.monotonic() + 25
        while open_outputs:
            events = ready.select(max(0, deadline - time.monotonic()))
            if not events:
                raise TimeoutError(f"off-path NAT probe stalled on {host}")
            for key, _ in events:
                source = key.fileobj
                if source == entrance:
                    packet, peer = entrance.recvfrom(65536)
                    if peer not in peers:
                        peers[peer] = bind(stack, host, family)
                        ready.register(peers[peer], selectors.EVENT_READ, peer)
                    peers[peer].sendto(packet, target)
                elif source == gate:
                    packet, peer = gate.recvfrom(65536)
                    if peer[:2] == target:
                        gate_sends.append(time.monotonic())
                        if len(gate_sends) > 1:
                            gate.sendto(packet, (host, direct_port))
                    elif peer[:2] == (host, direct_port):
                        gate.sendto(packet, target)
                elif source in (bend.stdout, iroh.stdout):
                    line = source.readline()
                    if not line:
                        ready.unregister(source)
                        open_outputs -= 1
                    elif source == bend.stdout and line.startswith(response_prefix):
                        response_port = int(line.removeprefix(response_prefix))
                else:
                    packet, _ = source.recvfrom(65536)
                    entrance.sendto(packet, key.data)
            if time.monotonic() >= deadline:
                raise TimeoutError(f"off-path NAT probe stalled on {host}")
        if bend.wait(timeout=2) or iroh.wait(timeout=2):
            raise RuntimeError(f"off-path NAT probe fixture failed on {host}")
        upstream_ports = {peer.getsockname()[1] for peer in peers.values()}
        expected_port = gate_port if gate else direct_port
        if response_port != expected_port or not upstream_ports or expected_port in upstream_ports:
            raise RuntimeError(f"expected an authenticated response on candidate port {expected_port}")
        if gate:
            if len(gate_sends) < 2 or gate_sends[1] - gate_sends[0] < 0.02:
                raise RuntimeError(f"expected a delayed NAT probe retry on {host}")
            print(f"PASS Bend recovered after the first off-path probe was dropped on {host}", flush=True)
        else:
            driver = "automatic listener" if automatic else "manual listener"
            print(f"PASS {driver} validated Iroh’s off-path UDP candidate on {host}", flush=True)


if __name__ == "__main__":
    listener, fixture, dialer = sys.argv[1:]
    for host, mode in (("127.0.0.1", "dial"), ("::1", "dial6")):
        check(listener, fixture, host, mode)
        check_affinity(listener, dialer, host)
        check_affinity(listener, dialer, host, "5", "bend-nat-offer")
        check_affinity(listener, dialer, host, "7", "bend-nat-dial")
        check(listener, fixture, host, mode, "6")
        check_off_path(listener, fixture, host, mode)
        check_off_path(listener, fixture, host, mode, drop_first=True)
        check_off_path(listener, fixture, host, mode, automatic=True)
        if os.environ.get("CHECK_BINARY_ALPN") == "1":
            check(listener, fixture, host, mode, "2")
        if os.environ.get("CHECK_MULTIPLE_ALPNS") == "1":
            check(listener, fixture, host, mode, "3")
        if os.environ.get("CHECK_LIVE_ALPNS") == "1":
            check(listener, fixture, host, mode, "4")
