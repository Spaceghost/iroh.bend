"""Exercise authenticated header policies through a loopback upgrade relay."""

import asyncio
import ssl
import sys


async def copy(reader, writer):
    while block := await reader.read(65536):
        writer.write(block)
        await writer.drain()


async def run_case(port, client, context, headers, expected):
    async def bridge(reader, writer):
        upstream_writer = None
        copies = []
        try:
            request = await reader.readuntil(b"\r\n\r\n")
            upstream_reader, upstream_writer = await asyncio.open_connection(
                "127.0.0.1", port, ssl=context
            )
            upstream_writer.write(request[:-2] + headers + b"\r\n")
            await upstream_writer.drain()
            copies = [
                asyncio.create_task(copy(reader, upstream_writer)),
                asyncio.create_task(copy(upstream_reader, writer)),
            ]
            await asyncio.wait(copies, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in copies:
                task.cancel()
            await asyncio.gather(*copies, return_exceptions=True)
            writer.close()
            if upstream_writer is not None:
                upstream_writer.close()

    listener = await asyncio.start_server(bridge, "127.0.0.1", 0)
    async with listener:
        proxy_port = listener.sockets[0].getsockname()[1]
        process = await asyncio.create_subprocess_exec(
            client,
            f"ws://127.0.0.1:{proxy_port}/relay",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            out, err = await asyncio.wait_for(process.communicate(), 8)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise
    if expected is None:
        assert process.returncode == 0, (out, err)
        assert b"exchanged a datagram" in out, out
    else:
        assert process.returncode == 1, (process.returncode, out, err)
        assert expected in err, err


async def main():
    port, client = int(sys.argv[1]), sys.argv[2]
    context = ssl.create_default_context(cafile=sys.argv[3]) if len(sys.argv) == 4 else None
    custom = b"X-Fix:\t value \t\r\n"
    standard = b"Accept-Language: one \r\naccept-language:\ttwo\t\r\n"
    await run_case(port, client, context, custom + standard, None)
    await run_case(port, client, context, custom + standard + b"x-fix: another\r\n", b"ambiguous header")
    await run_case(port, client, context, custom + b"Accept-Language: two\r\n", b"not authorized")
    print("PASS case-insensitive custom header, ordered standard values, and ambiguous header rejection")


if __name__ == "__main__":
    asyncio.run(main())
