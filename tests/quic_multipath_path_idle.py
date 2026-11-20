import concurrent.futures
import os
import queue
import socket
import subprocess
import sys
import threading
import time


class Peer:
    def __init__(self, *args):
        self.proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        self.events = queue.Queue()
        self.lines = []
        self.reader = threading.Thread(target=self.read)
        self.reader.start()

    def read(self):
        for line in self.proc.stdout:
            line = line.rstrip()
            self.lines.append(line)
            self.events.put((time.monotonic(), line))
        self.events.put(None)

    def match(self, predicate, timeout=12):
        deadline = time.monotonic() + timeout
        try:
            while (entry := self.events.get(timeout=max(0, deadline - time.monotonic()))) is not None:
                if predicate(entry[1]):
                    return entry
        except queue.Empty:
            pass
        raise AssertionError(f"{self.proc.args}: expected output, got {self.lines}")

    def expect(self, line, timeout=12):
        return self.match(lambda observed: observed == line, timeout)[0]

    def port(self):
        return int(self.match(str.isdecimal, 5)[1])

    def done(self):
        assert self.proc.wait(timeout=3) == 0, (self.proc.args, self.lines)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        self.reader.join(timeout=2)
        self.proc.stdout.close()


class AlternateRoute:
    def __init__(self, host, port, traffic):
        self.backend = (host, port)
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.socket = socket.socket(family, socket.SOCK_DGRAM)
        self.socket.bind((host, 0))
        self.socket.settimeout(0.05)
        self.port = self.socket.getsockname()[1]
        self.traffic = traffic
        self.seen = 0
        self.forwarded = 0
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.forward)
        self.thread.start()

    def forward(self):
        client = None
        while not self.stop.is_set():
            try:
                data, source = self.socket.recvfrom(65536)
            except TimeoutError:
                continue
            if source[:2] == self.backend:
                if client is not None and self.traffic == "both":
                    self.socket.sendto(data, client)
            else:
                client = source
                self.seen += 1
                if self.traffic in ("both", "out"):
                    self.socket.sendto(data, self.backend)
                    self.forwarded += 1

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(timeout=2)
        self.socket.close()


def address(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def remote_abandoned(lines):
    return any(
        "Abandoned { id: PathId(1), reason: RemoteAbandoned" in line
        and "15990" in line for line in lines
    )


def dial(bend, reference, host, traffic, limit_ms, earliest, latest, validated=False):
    with Peer(reference, "listen", host) as upstream:
        port = upstream.port()
        with AlternateRoute(host, port, traffic) as alternate:
            with Peer(bend, host, str(port), str(alternate.port), str(limit_ms),
                      "validated" if validated else "pending") as local:
                start = local.expect("CANDIDATE 1")
                if validated:
                    alternate.traffic = "none"
                elapsed = local.expect("EXPIRED 1") - start
                assert earliest <= elapsed <= latest, (elapsed, earliest, latest, local.lines)
                _, result = upstream.match(lambda line: line.startswith("SURVIVOR "))
                local.expect("SURVIVOR 0")
                _, frames, _ = result.split()
                assert alternate.seen > 0 and int(frames) > 0, (alternate.seen, upstream.lines)
                if traffic == "none":
                    assert not any("Abandoned" in line for line in upstream.lines), upstream.lines
                    assert result.endswith(" false"), upstream.lines
                else:
                    assert alternate.forwarded > 0 and remote_abandoned(upstream.lines), upstream.lines
                local.done()
                upstream.done()
    view = "no path event for unknown ID" if traffic == "none" else "RemoteAbandoned(15990)"
    print(f"PASS {host} Bend dialer {traffic} {limit_ms} ms, path 1 expired at {elapsed:.3f}s, "
          f"Noq saw {view}, fresh data on path 0")


def listen(bend, reference, host):
    with Peer(bend, host, "1500") as local:
        port = local.port()
        with AlternateRoute(host, port, "both") as alternate:
            with Peer(reference, "dial", address(host, port), address(host, alternate.port), "0", "validated") as upstream:
                start = local.expect("CANDIDATE 1")
                upstream.expect("CANDIDATE 1")
                alternate.traffic = "none"
                elapsed = local.expect("EXPIRED 1") - start
                assert 1.4 <= elapsed <= 2.5, (elapsed, local.lines)
                upstream.match(lambda line: line.startswith("SURVIVOR "))
                local.expect("SURVIVOR 0")
                assert remote_abandoned(upstream.lines), upstream.lines
                local.done()
                upstream.done()
    print(f"PASS {host} Bend listener, path 1 expired at {elapsed:.3f}s, "
          "Noq saw RemoteAbandoned(15990), fresh data on path 0")


def last_path(bend, reference, host):
    with Peer(reference, "listen", host) as upstream:
        with Peer(bend, host, str(upstream.port()), "last") as local:
            start = local.expect("LAST PATH 0")
            elapsed = local.expect("SURVIVOR 0") - start
            upstream.expect("SURVIVOR 0 false")
            local.done()
            upstream.done()
    assert elapsed >= 1.5, elapsed
    print(f"PASS {host} the last local path stayed open through its idle deadline")


def single_path(bend, reference, host):
    with Peer(reference, "listen-base", host) as upstream:
        with Peer(bend, host, str(upstream.port()), "base") as local:
            start = local.expect("SINGLE PATH")
            elapsed = local.expect("CONNECTION TIMED OUT") - start
            local.done()
    assert 1.0 <= elapsed <= 2.0, elapsed
    print(f"PASS {host} base QUIC used the 1200 ms connection idle timer")


def main():
    bend, reference = map(os.path.abspath, sys.argv[1:])
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        cases = []
        for host in ("127.0.0.1", "::1"):
            cases.extend((
                pool.submit(dial, bend, reference, host, "none", 8000, 7.9, 9.5),
                pool.submit(dial, bend, reference, host, "out", 8000, 7.9, 9.5),
                pool.submit(dial, bend, reference, host, "both", 1500, 1.4, 2.5, True),
                pool.submit(dial, bend, reference, host, "none", 25, 0.70, 1.50),
                pool.submit(listen, bend, reference, host),
                pool.submit(last_path, bend, reference, host),
                pool.submit(single_path, bend, reference, host),
            ))
        for case in cases:
            case.result()


if __name__ == "__main__":
    main()
