"""Hold a resolver open through an authenticated exchange and observe its cancellation."""

import select
import socket
import subprocess
from contextlib import ExitStack, contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import BaseRequestHandler, TCPServer, UDPServer
from threading import Event, Thread
from urllib.request import urlopen

from discovery_tcp import record, reply


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


def dns_proxy(stack, dns_port, gate, tcp=False, rcode=0, address=None):
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
                if address:
                    txt = ("addr=" + address).encode("ascii")
                    answer = reply(query, 0x8180, [record(16, bytes([len(txt)]) + txt)])
                elif rcode:
                    answer = reply(query, 0x8180 | rcode)
                else:
                    answer = resolver_reply(query, dns_port)
                server.sendto(answer, self.client_address)

    port = int(stack.enter_context(serve(TCPServer(("127.0.0.1", 0), TcpProxy)))) if tcp else 0
    return "dns", stack.enter_context(serve(UDPServer(("127.0.0.1", port), UdpProxy)))


def check_race(client, ticket, peer, pkarr, dns_port, slow_kind, fast_kind):
    started, released, closed = Event(), Event(), Event()

    query_source = []

    def slow(connection, address):
        query_source.append(address)
        partial = slow_kind == "dns-tcp-body"
        if partial:
            # A long frame delivers bytes inside every individual read timeout.
            connection.sendall(b"\xff\xff\x00")
        started.set()
        if connection is None:
            released.wait(12)
        else:
            while not released.is_set():
                try:
                    if select.select([connection], [], [], 0.005 if partial else 0.1)[0]:
                        if not connection.recv(1):
                            closed.set()
                            break
                    elif partial:
                        connection.sendall(b"\x00")
                except (BrokenPipeError, ConnectionResetError):
                    closed.set()
                    break
        return False

    def fast(*_):
        return started.wait(5)

    with ExitStack() as stack:
        def provider(kind, gate):
            if kind == "pkarr":
                return relay_proxy(stack, pkarr.rstrip("/"), gate)
            return dns_proxy(stack, dns_port, gate, tcp=kind.startswith("dns-tcp"))

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


def check_stale_record(client, ticket, peer, pkarr, dns_port, family):
    ipv6 = family == "listen6"
    with socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET, socket.SOCK_DGRAM) as stale, ExitStack() as stack:
        stale.bind(("::1" if ipv6 else "127.0.0.1", 0))
        stale.settimeout(5)
        host, port, *_ = stale.getsockname()
        address = f"[{host}]:{port}" if ipv6 else f"{host}:{port}"
        bad = dns_proxy(stack, dns_port, lambda *_: True, address=address)
        # Release the signed record only after QUIC has tried the address from DNS.
        good = relay_proxy(stack, pkarr.rstrip("/"), lambda *_: bool(stale.recv(65535)))
        result = subprocess.run((client, "lookup-ticket", ticket, *bad, *good),
                                capture_output=True, timeout=10)
        if result.returncode:
            raise RuntimeError(f"Dial after stale record failed: {result.stderr!r}")
        transcript, _ = peer.communicate(timeout=4)
        if peer.returncode:
            raise AssertionError(transcript)
