"""Send repeated custom fields through the raw relay's live access policy."""

import asyncio
import sys

from relay_server_headers import copy


async def check(port, client, query, headers, allowed):
    async def bridge(reader, writer):
        upstream_writer = None
        copies = []
        try:
            request = await reader.readuntil(b"\r\n\r\n")
            start, fields = request.split(b"\r\n", 1)
            method, path, version = start.split(b" ")
            upstream, upstream_writer = await asyncio.open_connection("127.0.0.1", port)
            upstream_writer.write(
                b" ".join((method, path + b"?" + query, version))
                + b"\r\n" + headers + fields
            )
            await upstream_writer.drain()
            copies = [
                asyncio.create_task(copy(reader, upstream_writer)),
                asyncio.create_task(copy(upstream, writer)),
            ]
            await asyncio.wait(copies, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in copies:
                task.cancel()
            await asyncio.gather(*copies, return_exceptions=True)
            writer.close()
            if upstream_writer:
                upstream_writer.close()

    listener = await asyncio.start_server(bridge, "127.0.0.1", 0)
    async with listener:
        proxy_port = listener.sockets[0].getsockname()[1]
        child = await asyncio.create_subprocess_exec(
            client, f"http://127.0.0.1:{proxy_port}",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(child.communicate(), 12)
        except asyncio.TimeoutError:
            child.kill()
            await child.wait()
            raise
    if allowed:
        assert child.returncode == 0 and b"batched datagram" in out, (out, err)
    else:
        assert child.returncode != 0 and b"not authorized" in err.lower(), (out, err)


async def main(port, client):
    fields = b"X-Fix:\tone\t\r\nx-fix:\r\nX-FIX: two\r\n"
    await check(port, client, b"token=ok%3Dgo", fields, True)
    await check(port, client, b"token%3Dok%3Dgo", fields, False)
    await check(port, client, b"token=ok%3Dgo", b"x-fix: two\r\nx-fix:\r\nx-fix: one\r\n", False)
    print("PASS authenticated access policy received ordered repeated headers and the exact query token")


if __name__ == "__main__":
    asyncio.run(main(int(sys.argv[1]), sys.argv[2]))
