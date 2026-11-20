import asyncio
import sys
from contextlib import asynccontextmanager
from urllib.parse import urlsplit


async def copy(src, dst):
    while block := await src.read(65536):
        dst.write(block)
        await dst.drain()


class RelayProxy:
    def __init__(self, relay):
        self.target = (relay.hostname, relay.port or (443 if relay.scheme == "wss" else 80))
        self.connections = set()
        self.forward = True
        self.attempts = asyncio.Queue()

    async def expect_attempt(self, forwarded):
        if await self.attempts.get() != forwarded:
            raise RuntimeError("relay connection did not follow the configured proxy state")

    async def handle(self, source, client):
        self.attempts.put_nowait(self.forward)
        if not self.forward:
            client.close()
            return
        self.connections.add(client)
        relay = None
        transfers = []
        try:
            upstream, relay = await asyncio.open_connection(*self.target)
            self.connections.add(relay)
            transfers = [asyncio.create_task(copy(source, relay)),
                         asyncio.create_task(copy(upstream, client))]
            await asyncio.wait(transfers, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in transfers:
                task.cancel()
            await asyncio.gather(*transfers, return_exceptions=True)
            for writer in (client, relay):
                if writer is not None:
                    self.connections.discard(writer)
                    writer.close()

    def disconnect(self):
        self.forward = False
        for connection in self.connections:
            connection.close()


@asynccontextmanager
async def child(*command):
    process = await asyncio.create_subprocess_exec(
        *command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE)
    try:
        yield process
    finally:
        if process.returncode is None:
            process.kill()
        await process.communicate()


async def expect(process, expected):
    line = await process.stdout.readline()
    if line.strip() != expected:
        raise RuntimeError(f"expected {expected!r}, received {line!r}")


async def check(native, reference, url, origin):
    relay = urlsplit(url)
    proxy = RelayProxy(relay)
    async with await asyncio.start_server(proxy.handle, "127.0.0.1", 0) as listener:
        port = listener.sockets[0].getsockname()[1]
        bridge = relay._replace(netloc=f"{relay.hostname}:{port}").geturl()
        async with asyncio.timeout(25):
            async with child(native, "listen-relay-reconnect", bridge) as server:
                await expect(server, b"relay identity listener ready")
                await proxy.expect_attempt(True)
                async with child(reference, origin, "reconnect") as client:
                    await expect(client, b"READY to disconnect the relay")
                    proxy.disconnect()
                    for _ in range(2):
                        await proxy.expect_attempt(False)
                    proxy.forward = True
                    await proxy.expect_attempt(True)
                    client.stdin.write(b"RESUME\n")
                    await client.stdin.drain()
                    await expect(server, b"PASS Bend served an established QUIC connection after relay reconnect")
                    await expect(client, b"PASS Iroh kept its established QUIC connection across relay reconnect")
                    client.stdin.write(b"FINISH\n")
                    await client.stdin.drain()
                    if await client.wait() or await server.wait():
                        raise RuntimeError("relay reconnect fixture exited with an error")
    print(f"PASS established Iroh QUIC connection survived {relay.scheme} relay loss and two failed registrations")


if __name__ == "__main__":
    asyncio.run(check(*sys.argv[1:]))
