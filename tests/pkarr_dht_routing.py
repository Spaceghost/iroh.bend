"""Exercise DHT referrals, verification, and replication on loopback."""

from contextlib import ExitStack
from hashlib import sha1
from selectors import DefaultSelector, EVENT_READ
from socket import AF_INET, AF_INET6, SOCK_DGRAM, inet_pton, socket
from struct import pack
from subprocess import PIPE, Popen
from sys import argv
from time import monotonic

KEY = bytes.fromhex("197f6b23e16c8532c6abc838facd5ea789be0c76b2920334039bfa8b3d368d61")
TARGET = sha1(KEY).digest()
NODE_ID = b"bend-test-node-00001"
HOSTS = {AF_INET: "127.0.0.1", AF_INET6: "::1"}


def encode(value):
    if type(value) is int:
        return f"i{value}e".encode()
    if type(value) is bytes:
        return str(len(value)).encode() + b":" + value
    return b"d" + b"".join(encode(key) + encode(value[key]) for key in sorted(value)) + b"e"


def node_id(distance):
    return TARGET[:-1] + bytes([TARGET[-1] ^ distance])


class Testnet:
    def __init__(self, context, families):
        self.poll = context.enter_context(DefaultSelector())
        self.nodes = [context.enter_context(socket(family, SOCK_DGRAM)) for family in families]
        self.foreign = {family: context.enter_context(socket(family, SOCK_DGRAM)) for family in set(families)}
        self.ids = [node_id(distance) for distance in (255, 20, 5, 1)]
        self.links = [[1, 3, 1], [], [0], [2]]
        self.packet = [None] * len(self.nodes)
        for index, node in enumerate(self.nodes):
            node.bind((HOSTS[node.family], 0))
            self.poll.register(node, EVENT_READ, index)

    def compact(self, index):
        family = self.nodes[index].family
        return self.ids[index] + inet_pton(family, HOSTS[family]) + pack("!H", self.nodes[index].getsockname()[1])

    def invoke(self, executable, mode, seq):
        get, put, issued = [], [], {}
        port = str(self.nodes[0].getsockname()[1])
        host = HOSTS[self.nodes[0].family]
        with Popen([executable, mode, port, host], stdout=PIPE, stderr=PIPE, text=True) as child:
            deadline = monotonic() + 6
            try:
                while child.poll() is None and monotonic() < deadline:
                    for ready, _ in self.poll.select(0.05):
                        node = ready.fileobj
                        index = ready.data
                        message, peer = node.recvfrom(2048)
                        assert message[-16:-11] == b"1:t4:" and message.endswith(b"1:y1:qe"), message
                        tx = message[-11:-7]
                        token = b"test-write-token" + bytes([index])
                        response = {b"id": self.ids[index]}
                        request = {b"y": b"q", b"t": tx, b"ro": 1}
                        # Validate the complete GET, including the SHA-1 target, and
                        # distinguish it from PUT using the fixed top-level suffix.
                        expected_get = encode({**request, b"q": b"get",
                                               b"a": {b"id": NODE_ID, b"target": TARGET}})
                        if message == expected_get:
                            get.append(index)
                            issued[index] = peer
                            if len(get) == 1:
                                wrong_source = {b"id": self.ids[index], b"token": b"wrong-source-token"}
                                self.foreign[node.family].sendto(encode({b"y": b"r", b"t": tx, b"r": wrong_source}), peer)
                            response[b"token"] = token
                            for family, field in ((AF_INET, b"nodes"), (AF_INET6, b"nodes6")):
                                response[field] = b"".join(
                                    self.compact(i) for i in self.links[index] if self.nodes[i].family == family
                                )
                            response.update(self.packet[index] or {})
                        else:
                            assert message[:-16].endswith(b"e1:q3:put2:roi1e"), message
                            assert peer == issued[index], (peer, issued)
                            assert seq is not None
                            prefix = b"d1:ad2:id" + encode(NODE_ID) + b"1:k" + encode(KEY)
                            prefix += b"3:seq" + encode(seq) + b"3:sig64:"
                            assert message.startswith(prefix), message
                            signature = message[len(prefix):len(prefix) + 64]
                            start = len(prefix) + 64
                            boundary = b"5:token" + encode(token) + b"1:v"
                            assert message[start:].startswith(boundary), message
                            size, tail = message[start + len(boundary):].split(b":", 1)
                            value = tail[:int(size)]
                            fields = {b"k": KEY, b"sig": signature, b"seq": seq, b"v": value}
                            exact = encode({**request, b"q": b"put",
                                            b"a": {**fields, b"id": NODE_ID, b"token": token}})
                            assert message == exact, message
                            put.append(index)
                            self.packet[index] = fields
                        reply = encode({b"y": b"r", b"t": tx, b"r": response})
                        node.sendto(reply, peer)
            finally:
                if child.poll() is None:
                    child.kill()
                out, err = child.communicate()
            assert child.returncode == 0, (mode, out, err)
        return get, put


def check(executable, families):
    with ExitStack() as context:
        network = Testnet(context, families)
        assert network.invoke(executable, "publish-old", 41) == ([0], [0])
        older = network.packet[0]
        assert network.invoke(executable, "search-publish", 42) == ([0, 3, 2, 1], [3, 2, 1, 0])
        network.packet[0] = older
        network.packet[1] = older
        network.packet[3] = {**network.packet[3], b"seq": 99}
        assert network.invoke(executable, "search-resolve", None) == ([0, 3, 2, 1], [])
        assert network.invoke(executable, "search-stale", None) == ([0, 3, 2, 1], [])
    versions = "/".join(version for family, version in ((AF_INET, "IPv4"), (AF_INET6, "IPv6")) if family in families)
    print(f"PASS {versions} DHT referral deduplication, nearest-first replication, and verified freshness")


if __name__ == "__main__":
    check(argv[1], [AF_INET] * 4)
    check(argv[1], [AF_INET6] * 4)
    check(argv[1], [AF_INET, AF_INET6, AF_INET, AF_INET6])
