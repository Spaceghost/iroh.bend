import selectors
import socket
import sys
import time
from contextlib import ExitStack

from quic_multipath_early_listener import address
from quic_rebind import process, read_address


def check(sender, iroh, host, family, sender_listens, kind, control_port):
    label = "FIN" if kind == "finish" else "RESET"
    hold_marker = f"HOLD_{label}".encode()
    pending_marker = f"{label}_PENDING".encode()
    mode = "listen6" if host == "::1" else "listen"
    with ExitStack() as stack:
        front = stack.enter_context(socket.socket(family, socket.SOCK_DGRAM))
        front.bind((host, control_port or 0))
        port = front.getsockname()[1]
        proxy = address(host, port)
        if control_port is not None:
            listen = (sender, mode, "control")
            dial = (sender, "dial", proxy, "control")
        else:
            listen = (sender, host, "0", kind)
            dial = (sender, host, str(port), kind)
        server = stack.enter_context(process(*(listen if sender_listens else (iroh, mode))))
        server_addr = (host, read_address(server))
        client = stack.enter_context(process(*((iroh, "dial", proxy) if sender_listens else dial)))
        writer, reader = (server, client) if sender_listens else (client, server)
        events = stack.enter_context(selectors.DefaultSelector())
        for channel in (server.stdout, client.stdout, front):
            events.register(channel, selectors.EVENT_READ)

        caller = None
        held = pending = False
        losses = []
        deadline = time.monotonic() + 18
        while time.monotonic() < deadline:
            for key, _ in events.select(0.05):
                channel = key.fileobj
                if channel is front:
                    packet, source = front.recvfrom(65535)
                    from_server = source[:2] == server_addr
                    if not from_server:
                        if caller is None:
                            caller = source
                        elif source != caller:
                            continue
                    if held and from_server == sender_listens:
                        losses[-1] += 1
                    elif from_server:
                        if caller is not None:
                            front.sendto(packet, caller)
                    else:
                        front.sendto(packet, server_addr)
                else:
                    line = channel.readline()
                    if not line:
                        events.unregister(channel)
                    elif line.strip() == hold_marker and channel is reader.stdout:
                        if held or len(losses) == 2:
                            raise AssertionError(f"unexpected {label} loss round")
                        held = True
                        pending = False
                        losses.append(0)
                        reader.stdin.write(b"ARMED\n")
                        reader.stdin.flush()
                    elif line.strip() == pending_marker and channel is writer.stdout:
                        if not held or pending:
                            raise AssertionError(f"unexpected {label} acknowledgement report")
                        pending = True
                    else:
                        print(line.decode().strip(), flush=True)
                if held and pending and losses[-1]:
                    held = False
            if any(p.poll() not in (None, 0) for p in (server, client)):
                raise RuntimeError(f"QUIC {label} peer exited with status {server.poll()}, {client.poll()}")
            if all(p.poll() is not None for p in (server, client)) and len(events.get_map()) == 1:
                break
        else:
            raise TimeoutError(f"{label} exchange timed out, dropped packets {losses}, pending {pending}")

        if len(losses) != 2 or not all(losses) or held:
            raise AssertionError(f"two completed {label} loss rounds required, saw {losses}")
        role = "listener" if sender_listens else "dialer"
        print(f"PASS {role} on {host} waited for both {label} acknowledgements after packet loss {losses}", flush=True)


if __name__ == "__main__":
    sender, iroh, *options = sys.argv[1:]
    kind = options.pop(0) if options and options[0] in ("finish", "reset-ack") else "finish"
    if options and (len(options) != 2 or options[0] != "control"):
        sys.exit("usage: quic_stream_finish.py SENDER IROH [finish|reset-ack] [control PROXY_PORT]")
    control_port = int(options[1]) if options else None
    for host, family in (("127.0.0.1", socket.AF_INET), ("::1", socket.AF_INET6)):
        for listener in (False, True):
            check(sender, iroh, host, family, listener, kind, control_port)
