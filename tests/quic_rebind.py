import selectors
import socket
import subprocess
import sys
import time
from contextlib import ExitStack, contextmanager, suppress


@contextmanager
def process(*command):
    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
    try:
        yield child
    finally:
        if child.poll() is None:
            child.kill()
        child.communicate()


def bind(stack, host, family):
    sock = stack.enter_context(socket.socket(family, socket.SOCK_DGRAM))
    sock.bind((host, 0))
    return sock


def read_address(listener):
    with selectors.DefaultSelector() as ready:
        ready.register(listener.stdout, selectors.EVENT_READ)
        if not ready.select(10):
            raise TimeoutError("QUIC listener did not print its address")
        return int(listener.stdout.readline().rsplit(b":", 1)[-1])


def check(binary, fixture, host, family, mode):
    with ExitStack() as stack:
        server = stack.enter_context(process(binary, mode))
        target = (host, read_address(server))
        entrance = bind(stack, host, family)
        original = bind(stack, host, family)
        rebound = bind(stack, host, family)
        original.connect(target)
        rebound.connect(target)
        port = entrance.getsockname()[1]
        address = f"[{host}]:{port}" if family == socket.AF_INET6 else f"{host}:{port}"
        client = stack.enter_context(process(fixture, "dial-rebind", address))
        ready = stack.enter_context(selectors.DefaultSelector())
        for source in (entrance, original, client.stdout):
            ready.register(source, selectors.EVENT_READ)

        upstream = original
        client_address = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            for key, _ in ready.select(max(0, deadline - time.monotonic())):
                if key.fileobj == entrance:
                    payload, sender = entrance.recvfrom(65536)
                    if client_address is None:
                        client_address = sender
                    if sender == client_address:
                        with suppress(ConnectionRefusedError):
                            upstream.send(payload)
                elif key.fileobj == upstream:
                    with suppress(ConnectionRefusedError):
                        entrance.sendto(upstream.recv(65536), client_address)
                elif key.fileobj == client.stdout:
                    line = client.stdout.readline().strip()
                    if line == b"REBIND" and upstream == original:
                        ready.unregister(original)
                        upstream = rebound
                        ready.register(rebound, selectors.EVENT_READ)
                        client.stdin.write(b"READY\n")
                        client.stdin.flush()
                    elif line == b"PASS Iroh streams and datagrams survived UDP rebinding" and upstream == rebound:
                        if client.wait(timeout=3) or server.wait(timeout=3):
                            raise RuntimeError("QUIC rebinding fixture failed")
                        print(f"PASS Iroh streams and datagrams survived UDP rebinding on {host}")
                        return
                    else:
                        raise RuntimeError(f"unexpected Iroh rebinding fixture output: {line!r}")
        raise TimeoutError(f"QUIC rebinding stalled on {host}")


if __name__ == "__main__":
    bend, iroh = sys.argv[1:]
    check(bend, iroh, "127.0.0.1", socket.AF_INET, "listen")
    check(bend, iroh, "::1", socket.AF_INET6, "listen6")
