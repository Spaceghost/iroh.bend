"""Exercise Pkarr HTTP transfers through the public Bend API."""

from http.server import BaseHTTPRequestHandler, HTTPServer
from subprocess import run
from sys import argv
from threading import Thread

LABEL = "df9sse9bp1nuftim3yhxiuk6w6r5hddsskjygpydux7esxjstioo"
PATH = f"/pkarr/{LABEL}?token=test"
MEDIA_TYPE = "application/x-pkarr-signed-packet"


class Relay(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, body=b""):
        self.send_response(status)
        self.send_header("Content-Type", MEDIA_TYPE)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):
        if self.path != PATH or self.headers.get("Content-Type") != MEDIA_TYPE:
            self.reply(400)
            return
        payload = self.rfile.read(int(self.headers["Content-Length"]))
        if payload[64:72] != bytes([255]) * 8 or payload[72:76] != b"\x00\x00\x80\x00":
            self.reply(400)
            return
        self.server.packet = payload
        self.reply(204)

    def do_GET(self):
        if self.path != PATH:
            self.reply(400)
        elif self.server.packet is None:
            self.reply(404)
        else:
            self.reply(200, self.server.packet)


def invoke(program, mode, url, error=None):
    result = run([program, mode, url], text=True, capture_output=True, timeout=5)
    if error:
        assert result.returncode != 0 and error in result.stdout + result.stderr, result
    else:
        assert result.returncode == 0, result
    print(f"PASS Pkarr HTTP {mode}" + (f" ({error})" if error else ""))


def check(program):
    with HTTPServer(("127.0.0.1", 0), Relay) as server:
        server.packet = None
        worker = Thread(target=server.serve_forever)
        worker.start()
        try:
            origin = f"http://127.0.0.1:{server.server_port}/pkarr"
            url = origin + "?token=test"
            invoke(program, "missing", url)
            invoke(program, "publish", url)
            invoke(program, "resolve", origin + "/?token=test#discarded")
            server.packet = bytes([server.packet[0] ^ 1]) + server.packet[1:]
            invoke(program, "tampered", url)
            server.packet = bytes(1073)
            invoke(program, "resolve", url, "response exceeds 1072 bytes")
        finally:
            server.shutdown()
            worker.join()


if __name__ == "__main__":
    check(argv[1])
