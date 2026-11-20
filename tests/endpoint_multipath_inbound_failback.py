import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from relay_quic_reconnect import child, expect


TABLE = "iroh_test_failback"


def cut_udp(address):
    if ":" in address:
        matches = ["meta nfproto ipv6 meta l4proto udp"]
    else:
        matches = ["ip saddr 127.0.0.3 meta l4proto udp", "ip daddr 127.0.0.3 meta l4proto udp"]
    rules = "\n".join(f"add rule inet {TABLE} input {match} counter drop" for match in matches)
    subprocess.run(["nft", "-f", "-"], input=f"""
add table inet {TABLE}
add chain inet {TABLE} input {{ type filter hook input priority 0; policy accept; }}
{rules}
""", text=True, check=True)


def dropped_packets():
    rules = json.loads(subprocess.check_output(["nft", "-j", "list", "table", "inet", TABLE]))
    return sum(expr.get("counter", {}).get("packets", 0)
               for item in rules["nftables"] if "rule" in item
               for expr in item["rule"]["expr"])


async def check(native, reference, origin, relay_url, address):
    async with asyncio.timeout(70):
        async with child(native, relay_url, address) as server:
            prefix = b"inbound NAT listener ready "
            line = await server.stdout.readline()
            if not line.startswith(prefix):
                raise RuntimeError(f"Bend NAT listener failed to bind: {line!r}")
            port = int(line[len(prefix):])
            direct = f"[{address}]:{port}" if ":" in address else f"{address}:{port}"
            async with child(reference, origin, direct, "cut-direct") as iroh:
                await expect(iroh, b"READY to drop direct UDP")
                cut_udp(address)
                try:
                    iroh.stdin.write(b"RESUME\n")
                    await iroh.stdin.drain()
                    await expect(server, b"PASS Bend finished the original accepted stream")
                    await expect(iroh, b"PASS Iroh finished the original stream over the relay")
                    count = dropped_packets()
                    if count == 0:
                        raise RuntimeError("no direct UDP packets were dropped")
                finally:
                    subprocess.run(["nft", "delete", "table", "inet", TABLE], check=True)
                iroh.stdin.write(b"FINISH\n")
                await iroh.stdin.drain()
                if await iroh.wait() or await server.wait():
                    raise RuntimeError("inbound fallback fixture exited with an error")
    print(f"PASS accepted Iroh stream returned to {relay_url.split(':', 1)[0]} after {count} UDP drops at {address}", flush=True)


async def run(native, reference, relay, scheme, config):
    env = os.environ.copy()
    env["RUST_LOG"] = "info"
    env["NO_COLOR"] = "1"
    process = await asyncio.create_subprocess_exec(
        relay, "--config-path", config, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT, env=env)
    try:
        pattern = b"HTTPS/WSS" if scheme == "wss" else b"HTTP/WS"
        async with asyncio.timeout(10):
            while line := await process.stdout.readline():
                if pattern in line and (match := re.search(rb"relay: serving on (127\.0\.0\.1:[0-9]+)", line)):
                    address = match[1].decode()
                    break
            else:
                raise RuntimeError("local Iroh relay did not start")
        origin = "https" if scheme == "wss" else "http"
        for ip in ("127.0.0.2", "::1"):
            await check(native, reference, f"{origin}://{address}", f"{scheme}://{address}/relay", ip)
    finally:
        if process.returncode is None:
            process.kill()
        await process.communicate()


def inside(namespace, native, reference, relay, scheme, config=""):
    if int(namespace) == os.stat("/proc/self/ns/net").st_ino:
        raise RuntimeError("the test must run in a new network namespace")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    os.environ["NO_PROXY"] = "127.0.0.1,::1,localhost"
    if config:
        asyncio.run(run(native, reference, relay, scheme, config))
    elif scheme == "ws":
        with tempfile.TemporaryDirectory(prefix="iroh-failback-") as temporary:
            plain = Path(temporary) / "relay.toml"
            plain.write_text('http_bind_addr = "127.0.0.1:0"\nenable_metrics = false\nenable_quic_addr_discovery = false\n')
            asyncio.run(run(native, reference, relay, scheme, str(plain)))
    else:
        raise ValueError("WSS requires a relay configuration and trusted certificate")


if __name__ == "__main__":
    if sys.argv[1] == "--inside":
        inside(*sys.argv[2:])
    else:
        namespace = str(os.stat("/proc/self/ns/net").st_ino)
        subprocess.run(["unshare", "-Urn", sys.executable, "-B", __file__, "--inside", namespace, *sys.argv[1:]], check=True)
