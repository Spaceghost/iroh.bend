"""Hold one address provider open until an independent Iroh peer confirms the exchange."""

import socket
import subprocess
from contextlib import ExitStack, contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import BaseRequestHandler, UDPServer
from threading import Event, Thread
from urllib.request import urlopen


@contextmanager
def serve(server):
    with server:
        thread = Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
        thread.start()
        try:
            yield str(server.server_address[1])
        finally:
            server.shutdown()
            thread.join()


def relay_proxy(stack, pkarr, gate):
    class Proxy(BaseHTTPRequestHandler):
        def do_GET(self):
            if gate():
                with urlopen(pkarr + self.path, timeout=4) as response:
                    packet = response.read()
                self.send_response(200)
                self.send_header("Content-Length", str(len(packet)))
                self.end_headers()
                self.wfile.write(packet)

        def log_message(self, *_):
            pass

    port = stack.enter_context(serve(HTTPServer(("127.0.0.1", 0), Proxy)))
    return "pkarr", f"http://127.0.0.1:{port}"


def dns_proxy(stack, dns_port, gate):
    class Proxy(BaseRequestHandler):
        def handle(self):
            packet, server = self.request
            if gate():
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(4)
                    sock.sendto(packet, ("127.0.0.1", int(dns_port)))
                    reply, _ = sock.recvfrom(65535)
                server.sendto(reply, self.client_address)

    return "dns", stack.enter_context(serve(UDPServer(("127.0.0.1", 0), Proxy)))


def check_race(client, ticket, peer, pkarr, dns_port, slow_kind, fast_kind):
    started, released = Event(), Event()

    def slow():
        started.set()
        return released.wait(12)

    def fast():
        return started.wait(5)

    with ExitStack() as stack:
        def provider(kind, gate):
            if kind == "pkarr":
                return relay_proxy(stack, pkarr.rstrip("/"), gate)
            return dns_proxy(stack, dns_port, gate)

        first = provider(slow_kind, slow)
        second = provider(fast_kind, fast)
        with subprocess.Popen((client, "lookup-ticket", ticket, *first, *second),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as bend:
            try:
                transcript, _ = peer.communicate(timeout=9)
                if peer.returncode or not started.is_set():
                    raise AssertionError(f"Missing authenticated exchange: {transcript!r}")
            finally:
                released.set()
                try:
                    _, errors = bend.communicate(timeout=4)
                except subprocess.TimeoutExpired:
                    bend.kill()
                    bend.communicate()
                    raise
            if bend.returncode:
                raise RuntimeError(f"Bend lookup failed: {errors!r}")
