"""Test the relay's receive limit with a fragmented WebSocket message."""

import asyncio
import ssl
import sys
from os import urandom


async def frame(reader):
    first, size = await reader.readexactly(2)
    masked = bool(size & 128)
    size &= 127
    extended = await reader.readexactly({126: 2, 127: 8}.get(size, 0))
    length = int.from_bytes(extended, "big") if extended else size
    mask = await reader.readexactly(4) if masked else b""
    data = await reader.readexactly(length)
    payload = unmask(data, mask) if masked else data
    encoded = bytes([first, size | (128 if masked else 0)]) + extended + mask + data
    return first, payload, encoded


def unmask(data, mask):
    return bytes(byte ^ mask[i % 4] for i, byte in enumerate(data))


def fragment(opcode, payload):
    mask = urandom(4)
    return bytes([opcode, 128 | len(payload)]) + mask + unmask(payload, mask)


async def main():
    port, client = int(sys.argv[1]), sys.argv[2]
    tls = ssl.create_default_context(cafile=sys.argv[3]) if len(sys.argv) == 4 else None
    fragmented = False
    observed = False

    async def bridge(reader, writer):
        nonlocal fragmented, observed
        upstream, upstream_writer = await asyncio.open_connection("127.0.0.1", port, ssl=tls)
        noticed = asyncio.Event()

        async def requests():
            nonlocal fragmented, observed
            while True:
                opcode, payload, encoded = await frame(reader)
                if not fragmented and opcode == 0x82 and len(payload) == 114:
                    fragmented = True
                    noticed.clear()
                    # The masked proof spends 104 of the 124 tokens.
                    # The masked 14-byte prefix spends the remaining 20.
                    upstream_writer.write(fragment(0x02, payload[:14]))
                    await upstream_writer.drain()
                    await asyncio.wait_for(noticed.wait(), 2)
                    observed = True
                    encoded = fragment(0x80, payload[14:])
                upstream_writer.write(encoded)
                await upstream_writer.drain()

        async def responses():
            while True:
                opcode, payload, encoded = await frame(upstream)
                if opcode == 0x82 and payload == b"\x0d\x02":
                    noticed.set()
                writer.write(encoded)
                await writer.drain()

        tasks = []
        try:
            upstream_writer.write(await reader.readuntil(b"\r\n\r\n"))
            await upstream_writer.drain()
            writer.write(await upstream.readuntil(b"\r\n\r\n"))
            await writer.drain()
            tasks = [asyncio.create_task(requests()), asyncio.create_task(responses())]
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            writer.close()
            upstream_writer.close()

    listener = await asyncio.start_server(bridge, "127.0.0.1", 0)
    async with listener:
        proxy_port = listener.sockets[0].getsockname()[1]
        process = await asyncio.create_subprocess_exec(
            client, f"ws://127.0.0.1:{proxy_port}/relay", "rate-paced",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(process.communicate(), 10)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise
        assert process.returncode == 0, (out, err)
        assert observed, "relay did not report the limit before the final fragment"
    print("PASS relay charged masked framing before receiving the rest of the message")


if __name__ == "__main__":
    asyncio.run(main())
