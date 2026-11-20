"""Compare both public ticket codec directions with canonical RelayUrl wire bytes."""
import argparse
import base64
import json
import subprocess
from pathlib import Path

# The first cases translate the serialization and domain examples in
# iroh-base 1.5.0's src/relay_url.rs.
CASES = [
    ("https://example.com", "https://example.com/"),
    ("https://example.com.", "https://example.com./"),
    ("https://example.com./", "https://example.com./"),
    ("https://example.com/", "https://example.com/"),
    ("https://example.com/prefix", "https://example.com/prefix/"),
    ("https://example.com/a/b?x=1", "https://example.com/a/b/?x=1"),
    ("https://example.com/prefix/", "https://example.com/prefix/"),
    ("HTTPS:relay.Example:443/prefix?x#f", "https://relay.example/prefix/?x#f"),
    ("Ws://user:@EXAMPLE.net:80/a", "ws://user@example.net/a/"),
    ("https://u@v:p@ExAmPle.com/a /ü?x='#[]", "https://u%40v:p@example.com/a%20/%C3%BC/?x=%27#[]"),
    ("file://localhost/C|/x/../y", "file:///C:/y/"),
    ("file:////example/path", "file:///example/path/"),
    ("foo://MiXeD/a/..", "foo://MiXeD/"),
    ("foo:/a/..//b", "foo:/.//b/"),
    ("foo:opaque path?q#frag", "foo:opaque path?q#frag"),
    ("foo://b./c?áö", "foo://b./c/?%C3%A1%C3%B6"),
    ("http://0177.1", "http://127.0.0.1/"),
    ("http://0x7f000001", "http://127.0.0.1/"),
    ("http://0x", "http://0.0.0.0/"),
    ("http://1.2.3.4.", "http://1.2.3.4/"),
    ("ftp://LOCALHOST:21/f", "ftp://localhost/f/"),
    ("http://[0:0:1:0:0:1:0:0]", "http://[::1:0:0:1:0:0]/"),
    ("http://[::ffff:192.0.2.7]:80/a", "http://[::ffff:c000:207]/a/"),
    ("http://example.com////../..", "http://example.com//"),
    ("http://h/a//.", "http://h/a//"),
    ("https://r./a%2Fb/./x/..", "https://r./a%2Fb/"),
    ("https://localhost:0000", "https://localhost:0/"),
    ("x://", "x:///"),
    ("\t ws://Example.org/a\nb \r", "ws://example.org/ab/"),
    ("https://a/b^c", "https://a/b^c/"),
    ("http://a\\b\\c", "http://a/b/c/"),
    ("https://foo..bar/path", "https://foo..bar/path/"),
    ("http://%41%2e%42/", "http://a.b/"),
    ("http://a%2Fb", None),
    ("http://[::1%25eth0]", None),
    ("http://1.2.3.256", None),
    ("http://[1:2:3:4:5:6:7:8:9]", None),
    ("http://%FF", None),
    ("file://localhost:1/a", None),
    ("https://r:65536/", None),
    ("https://r:%38%30/", None),
    ("https://", None),
    ("", None),
    ("//host/path", None),
    (b"https://\xff.invalid/", None),
]

KEY = bytes.fromhex("ae58ff8833241ac82d6ff7611046ed67b5072d142c588d0063e942d9a75502b6")


def octets(value):
    return value if isinstance(value, bytes) else value.encode("utf-8")


def varint(value):
    result = bytearray()
    while value >= 128:
        result.append(128 | (value & 127))
        value >>= 7
    result.append(value)
    return result


def ticket(urls, key=KEY):
    data = bytearray(b"\x00" + key + varint(len(urls)))
    for url in map(octets, urls):
        data.extend(b"\x00" + varint(len(url)) + url)
    return "endpoint" + base64.b32encode(data).decode("ascii").rstrip("=").lower()


def output(program, *args):
    return subprocess.check_output([program, *args], text=True, timeout=60).splitlines()


def check(batch, actual, expected, direction):
    for raw, got, wanted in zip(batch, actual, expected, strict=True):
        if got != wanted:
            raise AssertionError(f"{direction} for {raw!r}\nexpected {wanted}\nreceived {got}")


def check_urls(program, oracle, urls, canonical=None):
    for offset in range(0, len(urls), 12):
        batch = urls[offset:offset + 12]
        packets = [ticket([url]) for url in batch]
        if canonical is None:
            expected = output(oracle, *packets)
        else:
            expected = ["invalid" if url is None else ticket([url]) for url in canonical[offset:offset + 12]]
            if oracle:
                check(batch, output(oracle, *packets), expected, "upstream fixture")
        check(batch, output(program, *packets), expected, "decode and encode")
        check(batch, output(program, "build-relays", *[octets(raw).hex() for raw in batch]), expected, "construct")
        stable = [value for value in expected if value != "invalid"]
        if stable:
            check(stable, output(program, *stable), stable, "canonical round trip")
    print(f"PASS {len(urls)} relay URLs through ticket construction and decoding", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("program", type=Path)
    parser.add_argument("--upstream", type=Path, help="Iroh ticket decoder that prints the re-encoded ticket or invalid")
    parser.add_argument("--url-testdata", type=Path, help="url crate's tests/urltestdata.json, compared as absolute URLs")
    args = parser.parse_args()
    program = args.program.resolve()
    raw, canonical = zip(*CASES)
    check_urls(program, args.upstream, raw, canonical)
    aliases = ["https://Z.EXAMPLE:443/p", "http://127.1", "http://0x7f000001/", "https://z.example/p/"]
    distinct = ticket(["http://127.0.0.1/", "https://z.example/p/"])
    for urls, expected in [(aliases, distinct), ([*aliases, "relative"], "invalid")]:
        packet = ticket(urls)
        check([urls], output(program, "build-set", *[url.encode().hex() for url in urls]), [expected], "construct set")
        check([urls], output(program, packet), [expected], "decode set")
        if args.upstream:
            check([urls], output(args.upstream, packet), [expected], "upstream set")
    if args.url_testdata:
        if not args.upstream:
            parser.error("--url-testdata requires --upstream")
        rows = json.loads(args.url_testdata.read_text())
        check_urls(program, args.upstream, list(dict.fromkeys(row["input"] for row in rows if isinstance(row, dict))))


if __name__ == "__main__":
    main()
