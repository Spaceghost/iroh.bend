"""Run Iroh 1.5.0's graceful-close exchange in both directions on each loopback family."""
import argparse
from contextlib import ExitStack

from quic_rebind import process, read_address


def command(binary, is_reference, host, port, operation, example, control=False):
    if is_reference:
        address = f"[{host}]:{port}" if host == "::1" else f"{host}:{port}"
        mode = ["dial", address] if port else ["listen6" if host == "::1" else "listen"]
        return [binary, *mode, operation, str(example), *(["control"] if control else [])]
    return [binary, host, str(port), operation, str(example)]


def check(binary, reference, host, example, bend_listens, bend_sends, controls):
    server_ref = controls or not bend_listens
    client_ref = controls or bend_listens
    server_op = "send" if bend_listens == bend_sends else "receive"
    client_op = "receive" if server_op == "send" else "send"
    server = binary if bend_listens else reference
    client = reference if bend_listens else binary
    with ExitStack() as stack:
        listener = stack.enter_context(process(*command(server, server_ref, host, 0, server_op, example,
                                                         control=controls and bend_listens)))
        port = read_address(listener)
        dialer = stack.enter_context(process(*command(client, client_ref, host, port, client_op, example,
                                                       control=controls and not bend_listens)))
        for child in (dialer, listener):
            output = child.communicate(timeout=18)[0].decode()
            if child.returncode or "PASS close" not in output:
                raise RuntimeError(f"{child.args} exited {child.returncode}: {output}")
    print(f"PASS close {example} {host} {'listener' if bend_listens else 'dialer'} "
          f"{'send' if bend_sends else 'receive'}", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("reference")
    parser.add_argument("--control", action="store_true")
    parser.add_argument("--examples", type=int, nargs="+", default=range(8), choices=range(8))
    args = parser.parse_args()
    for example in args.examples:
        for host in ("127.0.0.1", "::1"):
            for listens in (True, False):
                for sends in (True, False):
                    check(args.binary, args.reference, host, example, listens, sends, args.control)


if __name__ == "__main__":
    main()
