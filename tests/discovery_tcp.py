"""Exercise DNS truncation and TCP framing through the discovery public API."""

from concurrent.futures import ThreadPoolExecutor
from socket import AF_INET, IPPROTO_TCP, SOCK_DGRAM, SOCK_STREAM, TCP_NODELAY, socket
from struct import pack
from subprocess import run
from sys import argv
from time import sleep


def reply(query, flags, answers=()):
    header = query[:2] + pack("!5H", flags, 1, len(answers), 0, 0)
    return header + query[12:] + b"".join(answers)


def record(kind, data):
    return b"\xc0\x0c" + pack("!HHIH", kind, 1, 30, len(data)) + data


def tcp_reply(query):
    values = (
        b"addr=192.168.96.145:60165",
        b"addr=213.208.157.87:60165",
        b"relay=https://euw1-1.relay.iroh.network./",
    )
    records = [record(16, bytes([len(value)]) + value) for value in values]
    # An unknown record makes this reply exceed the UDP limit. The TXT values
    # must still be returned, and the complete frame must be consumed.
    padding = 65535 - len(reply(query, 0x8180, records)) - 12
    records.append(record(65000, b"\x00" * padding))
    return reply(query, 0x8180, records)


def serve(tcp, udp, scenario):
    query, client = udp.recvfrom(4096)
    udp.sendto(reply(query, 0x8380), client)
    conn, _ = tcp.accept()
    with conn:
        conn.settimeout(5)
        conn.setsockopt(IPPROTO_TCP, TCP_NODELAY, 1)
        with conn.makefile("rb") as stream:
            prefix = stream.read(2)
            assert len(prefix) == 2, prefix
            assert stream.read(int.from_bytes(prefix, "big")) == query

        answer = tcp_reply(query)
        if scenario == "wrong-id":
            answer = bytes([answer[0] ^ 1]) + answer[1:]
        if scenario == "short-length":
            conn.sendall(pack("!H", 11))
            return

        size = pack("!H", len(answer))
        conn.sendall(size[:1])
        sleep(0.03)
        conn.sendall(size[1:] + answer[:9])
        if scenario == "read-timeout":
            sleep(2.65)
            return
        if scenario == "early-eof":
            return
        sleep(0.03)
        conn.sendall(answer[9:])


def check(executable, scenario, failure):
    with socket(AF_INET, SOCK_STREAM) as tcp, socket(AF_INET, SOCK_DGRAM) as udp:
        tcp.bind(("127.0.0.1", 0))
        tcp.listen()
        host, port = tcp.getsockname()
        udp.bind((host, port))
        tcp.settimeout(5)
        udp.settimeout(5)
        with ThreadPoolExecutor(max_workers=1) as pool:
            server = pool.submit(serve, tcp, udp, scenario)
            client = run([executable, str(port)], text=True, capture_output=True, timeout=6)
            server.result()
    if failure:
        assert client.returncode == 1 and failure in client.stdout + client.stderr, client
    else:
        assert client.returncode == 0, client
    print(f"PASS DNS TCP {scenario}")


if __name__ == "__main__":
    check(argv[1], "fragmented", None)
    check(argv[1], "wrong-id", "FAIL Iroh endpoint TXT lookup")
    check(argv[1], "short-length", "invalid DNS TCP frame length")
    check(argv[1], "early-eof", "DNS TCP reply ended early")
    check(argv[1], "read-timeout", "DNS TCP read timed out")
