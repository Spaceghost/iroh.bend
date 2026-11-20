"""Hold a resolver open through an authenticated exchange and observe its cancellation."""

import socket
import subprocess
from contextlib import ExitStack, contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import BaseRequestHandler, TCPServer, UDPServer
from threading import Event, Thread
from urllib.request import urlopen

from discovery_tcp import reply


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
            if gate(self.connection, self.client_address):
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


def resolver_reply(query, dns_port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(4)
        sock.sendto(query, ("127.0.0.1", int(dns_port)))
        packet, _ = sock.recvfrom(65535)
        return packet


def dns_proxy(stack, dns_port, gate, tcp=False):
    class TcpProxy(BaseRequestHandler):
        def handle(self):
            with self.request.makefile("rb") as stream:
                prefix = stream.read(2)
                query = stream.read(int.from_bytes(prefix, "big"))
                if len(prefix) == 2 and gate(self.request, self.client_address):
                    packet = resolver_reply(query, dns_port)
                    self.request.sendall(len(packet).to_bytes(2, "big") + packet)

    class UdpProxy(BaseRequestHandler):
        def handle(self):
            query, server = self.request
            if tcp:
                server.sendto(reply(query, 0x8380), self.client_address)
            elif gate(None, self.client_address):
                server.sendto(resolver_reply(query, dns_port), self.client_address)

    port = int(stack.enter_context(serve(TCPServer(("127.0.0.1", 0), TcpProxy)))) if tcp else 0
    return "dns", stack.enter_context(serve(UDPServer(("127.0.0.1", port), UdpProxy)))


def check_race(client, ticket, peer, pkarr, dns_port, slow_kind, fast_kind):
    started, released, closed = Event(), Event(), Event()

    query_source = []

    def slow(connection, address):
        query_source.append(address)
        started.set()
        if connection is None:
            released.wait(12)
        else:
            connection.settimeout(0.1)
            while not released.is_set():
                try:
                    if not connection.recv(1):
                        closed.set()
                        break
                except TimeoutError:
                    continue
                except ConnectionResetError:
                    closed.set()
                    break
        return False

    def fast(*_):
        return started.wait(5)

    with ExitStack() as stack:
        def provider(kind, gate):
            if kind == "pkarr":
                return relay_proxy(stack, pkarr.rstrip("/"), gate)
            return dns_proxy(stack, dns_port, gate, tcp=kind == "dns-tcp")

        first = provider(slow_kind, slow)
        second = provider(fast_kind, fast)
        gate = stack.enter_context(socket.socket())
        gate.bind(("127.0.0.1", 0))
        gate.listen()
        gate.settimeout(8)
        command = (client, "lookup-ticket-barrier", str(gate.getsockname()[1]), ticket, *first, *second)
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as bend:
            try:
                # Each service has a 20-second deadline. Bend connects to this
                # barrier immediately after its public dial returns and holds the
                # QUIC session open while we examine the losing provider.
                with gate.accept()[0] as barrier:
                    if not started.is_set():
                        raise AssertionError(f"The {slow_kind} request never arrived")
                    if slow_kind == "dns":
                        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reopened:
                            reopened.bind(query_source[0])
                    elif not closed.wait(1):
                        raise AssertionError(f"The outstanding {slow_kind} connection stayed open")
                    barrier.sendall(b"1")
                _, errors = bend.communicate(timeout=7)
                if bend.returncode:
                    raise RuntimeError(f"Bend lookup failed: {errors!r}")
                transcript, _ = peer.communicate(timeout=4)
                if peer.returncode:
                    raise AssertionError(f"Missing authenticated exchange: {transcript!r}")
            finally:
                released.set()
                if bend.poll() is None:
                    bend.kill()
                    bend.communicate()
