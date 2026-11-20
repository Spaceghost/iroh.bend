"""Check Iroh CustomAddr text and binary conversions through the Bend ticket API."""

import argparse
import subprocess


def address_cases():
    text = []
    raw = []
    ids = [0, 1, 42, 255, 0xDEADBEEF, 2**32 - 1, 2**32, 0x123456789ABCDEF0, 2**63, 2**64 - 1]
    for tag in ids:
        for length in [0, 1, 6, 29, 30, 31, 32, 127, 255, 256]:
            data = bytes((tag + offset * 37) & 255 for offset in range(length))
            wire = (tag.to_bytes(8, "little") + data).hex()
            address = f"{tag:x}_{data.hex()}"
            expected = f"{address} {wire}"
            text.append((address, expected))
            text.append((f"+{tag:020X}_{data.hex()}", expected))
            raw.append((wire, address))
    text.extend([
        ("", "missing '_' separator"), ("f", "missing '_' separator"),
        ("_00", "invalid id"), ("+_", "invalid id"), ("++1_00", "invalid id"),
        ("0x2a_", "invalid id"), (" 1_00", "invalid id"), ("10000000000000000_", "invalid id"),
        ("1_1", "invalid data"), ("1_FF", "invalid data"), ("1_ff_", "invalid data"),
    ])
    raw.extend((bytes(range(n)).hex(), "data too short") for n in range(8))
    return [("custom-address", text), ("custom-bytes", raw)]


def check(binary, mode, cases):
    for offset in range(0, len(cases), 16):
        batch = cases[offset:offset + 16]
        args = [value for value, _ in batch]
        result = subprocess.run([binary, mode, *args], capture_output=True, text=True, timeout=30, check=True)
        lines = result.stdout.splitlines()
        if len(lines) != len(batch):
            raise ValueError(f"{binary} returned {len(lines)} lines for {len(batch)} {mode} cases")
        for (value, expected), actual in zip(batch, lines):
            if actual != expected:
                raise ValueError(f"{binary} {mode} {value!r} returned {actual!r}, expected {expected!r}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bend")
    parser.add_argument("--upstream", help="Iroh CustomAddr fixture accepting custom-address and custom-bytes")
    args = parser.parse_args()
    for mode, cases in address_cases():
        if args.upstream:
            check(args.upstream, mode, cases)
        check(args.bend, mode, cases)
        print(f"PASS {len(cases)} {mode} cases" + (" against Iroh" if args.upstream else ""))


if __name__ == "__main__":
    main()
