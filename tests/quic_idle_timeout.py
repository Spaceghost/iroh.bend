"""Compare idle expiry and default heartbeats on authenticated loopback Iroh connections."""
import argparse
import asyncio
from contextlib import ExitStack, asynccontextmanager
from threading import Event

from endpoint_lookup_race import dns_proxy

from relay_quic_reconnect import child, expect


class LoopbackRoute(asyncio.DatagramProtocol):
    def __init__(self, host, port):
        self.server = (host, port)
        self.client = None
        self.block_from_server = None
        self.dropped = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        sender = address[:2]
        from_server = sender == self.server
        if not from_server:
            if self.client is None:
                self.client = sender
            if self.client != sender:
                return
        if from_server == self.block_from_server:
            self.dropped += 1
        elif destination := (self.client if from_server else self.server):
            self.transport.sendto(data, destination)


@asynccontextmanager
async def route_to(host, port, routed):
    if not routed:
        yield port, None
        return
    route = LoopbackRoute(host, port)
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: route, local_addr=(host, 0))
    try:
        yield transport.get_extra_info("sockname")[1], route
    finally:
        transport.close()


async def signal(process, command):
    process.stdin.write(command + b"\n")
    await process.stdin.drain()


async def check(bend, reference, case, host, bend_listens, control):
    def args(listener, port):
        tested = listener == bend_listens
        if tested and not control:
            return [bend, host, str(port), case]
        address = f"[{host}]:{port}" if host == "::1" else f"{host}:{port}"
        mode = ["listen6" if host == "::1" else "listen"] if listener else ["dial", address]
        return [reference, *mode, case, *(["control"] if tested else [])]

    routed = case in ("one-way", "defaults")
    marker = f"PASS {case} kept alive".encode() if case in ("defaults", "wide", "no-limit") else f"PASS {case} timed out".encode()
    context = f"{case} {host} {'listener' if bend_listens else 'dialer'}"
    async with asyncio.timeout(18 if case == "defaults" else 10):
        async with child(*args(True, 0)) as server:
            port = int((await server.stdout.readline()).rsplit(b":", 1)[-1])
            async with route_to(host, port, routed) as (dial_port, route):
                async with child(*args(False, dial_port)) as client:
                    if routed:
                        observer = client if bend_listens else server
                        await asyncio.gather(expect(server, b"READY"), expect(client, b"READY"))
                        # Defaults isolates the tested peer's heartbeat from incoming traffic.
                        # One-way delivers the observer's datagram and discards its reply.
                        # Let handshake ACKs and initial MTU probes drain before measuring silence.
                        await asyncio.sleep(1.5 if case == "defaults" else 0.1)
                        route.block_from_server = not bend_listens if case == "defaults" else bend_listens
                        await signal(observer, b"START")
                        if case == "defaults":
                            await expect(observer, b"PING")
                            route.block_from_server = None
                            await signal(observer, b"RESUME")
                    outputs = await asyncio.gather(server.communicate(), client.communicate())
                    for name, proc, (output, _) in zip(("listener", "dialer"), (server, client), outputs):
                        if proc.returncode or marker not in output.splitlines():
                            raise RuntimeError(f"{context} {name} exited {proc.returncode}: {output!r}")
                    if case == "one-way" and route.dropped == 0:
                        raise RuntimeError(f"{context} did not drop a reply")
    print(f"PASS idle timeout {context}", flush=True)


async def listeners(bend, reference, host):
    async with asyncio.timeout(15):
        async with child(bend, host, "idle-listeners") as server:
            def address(port):
                return f"[{host}]:{port}" if host == "::1" else f"{host}:{port}"

            wide_port = int(await server.stdout.readline())
            short_port = int(await server.stdout.readline())
            if wide_port == short_port:
                raise RuntimeError("two listeners received the same UDP port")
            async with child(reference, "dial", address(wide_port), "wide", "pair") as wide:
                async with child(reference, "dial", address(short_port), "configured", "pair") as short:
                    processes = (server, wide, short)
                    outputs = await asyncio.gather(*(process.communicate() for process in processes))
                    markers = (b"PASS independent listener idle timeouts", b"PASS wide kept alive",
                               b"PASS configured timed out")
                    for process, (output, _), marker in zip(processes, outputs, markers):
                        if process.returncode or marker not in output.splitlines():
                            raise RuntimeError(f"{host} expected {marker!r}, got {output!r}, exit {process.returncode}")
    print(f"PASS concurrent listener configurations {host}", flush=True)


async def endpoint_route(bend, reference, case, *, host=None, relay=None, lookup=False):
    marker = f"PASS {case} kept alive".encode()
    listener = (["listen-relay", relay[1]] if relay else
                ["listen6" if host == "::1" else "listen"])
    queried = Event()

    def answer_query(*_):
        queried.set()
        return True

    async with asyncio.timeout(20):
        async with child(reference, *listener, case, "route") as observer:
            if relay:
                await expect(observer, b"READY relay")
                target = relay[0]
                command = [target, "relay-idle", case]
            else:
                target = (await observer.stdout.readline()).decode().strip()
                port = int(target.rsplit(":", 1)[-1])
                command = [host, str(port), "route-idle", case]
            with ExitStack() as services:
                if lookup:
                    _, dns_port = dns_proxy(services, None, answer_query,
                                            address=None if relay else target,
                                            relay_url=relay[1] if relay else None)
                    command = ["127.0.0.1", dns_port, "dns-idle", case]
                async with child(bend, *command) as client:
                    outputs = await asyncio.gather(client.communicate(), observer.communicate())
                    for proc, (out, _) in zip((client, observer), outputs):
                        if proc.returncode or marker not in out.splitlines():
                            raise RuntimeError(f"{case} {target} exited {proc.returncode}: {out!r}")
                if lookup and not queried.is_set():
                    raise RuntimeError(f"the endpoint never queried DNS for {target}")
    print(f"PASS endpoint idle timeout {case} {target} via {'DNS' if lookup else 'supplied route'}", flush=True)


async def run(args):
    if args.relay or args.routes:
        for case in args.cases:
            for lookup in (False, True):
                if args.relay:
                    await endpoint_route(args.bend, args.reference, case, relay=args.relay, lookup=lookup)
                else:
                    await asyncio.gather(*(endpoint_route(args.bend, args.reference, case, host=host, lookup=lookup)
                                           for host in ("127.0.0.1", "::1")))
        return
    if args.listeners:
        await asyncio.gather(*(listeners(args.bend, args.reference, host) for host in ("127.0.0.1", "::1")))
        return
    for case in args.cases:
        await asyncio.gather(*(check(args.bend, args.reference, case, host, listens, args.control)
                               for host in ("127.0.0.1", "::1") for listens in (True, False)))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bend")
    parser.add_argument("reference")
    parser.add_argument("--control", action="store_true")
    parser.add_argument("--relay", nargs=2, metavar=("WEBSOCKET_URL", "IROH_ORIGIN"))
    parser.add_argument("--listeners", action="store_true", help="exercise two live listeners in one Bend process")
    parser.add_argument("--routes", action="store_true", help="dial through the public endpoint route API")
    cases = ("idle", "activity", "one-way", "defaults")
    parser.add_argument("--cases", nargs="+", choices=(*cases, "configured", "wide", "no-limit", "peer-limit"), default=cases)
    asyncio.run(run(parser.parse_args()))
