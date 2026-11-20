import subprocess
import sys

from quic_rebind import process, read_address


def check(server, reference, cert, key, tls_name, roots, host):
    with process(server, host, cert, key) as listener:
        port = read_address(listener)
        peer = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        with process(reference, peer, tls_name, roots) as first:
            subprocess.run((reference, peer, tls_name, roots), timeout=14, check=True)
            transcript, _ = first.communicate(timeout=14)
            print(transcript.decode(), end="", flush=True)
            if first.returncode:
                raise RuntimeError(f"Iroh rejected the first QAD exchange on {host}")
        wrong_name = subprocess.run(
            (reference, peer, "invalid.iroh.example", roots), timeout=10, capture_output=True
        )
        if wrong_name.returncode == 0 or b"certificate not valid for name" not in wrong_name.stderr:
            raise RuntimeError(f"unexpected QAD TLS verification result on {host}: {wrong_name.stderr!r}")


if __name__ == "__main__":
    server, reference, cert, key, tls_name, roots = sys.argv[1:]
    for host in ("127.0.0.1", "::1"):
        check(server, reference, cert, key, tls_name, roots, host)
