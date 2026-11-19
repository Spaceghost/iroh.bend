# iroh.bend

A Rust-free implementation targeting the Iroh 1.5.0 wire protocol. Bend
implements relay framing, authentication transcripts, client state, and DNS
and Pkarr discovery packets.
Nelua binds OpenSSL for direct QUIC and Ed25519, and libcurl for WebSocket
transport and Pkarr HTTP. The build generates native C from Bend and Nelua. Upstream Iroh
runs separately as a compatibility reference.

## Build and verify

Use Bend 2.0.39 and Clang. The native networking tests also use Nelua and
`pkg-config`. Direct QUIC requires OpenSSL 3.5 or later. The live relay
client requires a libcurl build with WebSocket support.

1. Run `make check` for the relay wire snapshots, malformed input, handshake
   framing, BLAKE3 challenge vectors, and DNS query and TXT vectors.
   Run `make check-dns-tcp` with Python 3 for the loopback DNS fallback test.
2. Run `make check-relay-auth` and `make check-pkarr` for Ed25519 relay proofs,
   canonical Pkarr signing, and rejection of tampered packets and wrong keys.
   Run `make check-pkarr-http` with libcurl and Python 3 for Pkarr relay
   publishing, resolution, and error handling. Run
   `make check-pkarr-http-live PKARR_URL=http://127.0.0.1:8080/pkarr` against
   a local upstream Iroh DNS server with a disposable store.
3. Run `make check-direct UPSTREAM=/path/to/upstream-peer` for mixed-peer
   QUIC. The peer fixture accepts `listen` and `dial ADDRESS`, uses the
   ALPN, identity seeds, and echo payload in [tests/direct.bend](tests/direct.bend),
   and prints its bound address. Set `UPSTREAM_IPV6` to a peer fixture whose
   listener binds to `::1` to exercise Bend dialing upstream over IPv6.
4. Run `make check-relay-live RELAY_URL=ws://127.0.0.1:3340/relay` against
   an upstream `iroh-relay` in development mode on the loopback interface.
   Both relay protocol versions are exercised. For a local TLS relay, use a
   `wss://` URL and set `CURL_CA_BUNDLE` to the trusted CA file.
5. Set `CUDA_HOME` for your compiler, select a GPU with `CUDA_VISIBLE_DEVICES`,
   and run `make check-gpu` to decode 16,384 relay ping frames on the device.

Set `BEND`, `NELUA`, and `BUILD` to override the compilers and build output.

## Library interfaces

- [Relay codec](src/relay.bend) reads and writes v1/v2 WebSocket payloads.
  It handles frame direction, QUIC varint tags, wire size limits, v1 UTF-8
  health messages, and datagram ECN and segment size.
- [Relay client](src/relay_client.bend) upgrades a `ws://` or `wss://`
  connection, negotiates v1/v2, and authenticates with an Ed25519 challenge
  response. It sends datagrams and reads relay frames. A caller receiving
  a relay ping sends the given payload back through `pong`.
- [Direct QUIC](src/direct.bend) opens one IPv4 or IPv6 connection with one
  bidirectional stream. It pins both peers to explicitly supplied Ed25519
  keys, negotiates the caller's ALPN, and exchanges bounded binary messages.
  Listener, stream, and relay connection values are affine.
- [Discovery](src/discovery.bend) looks up Iroh TXT attributes through an
  caller-supplied IPv4 DNS resolver. It validates the UDP source, transaction
  ID, and question, expands compressed DNS names, and retries truncated
  responses over TCP. The timeout is per socket read or TCP write. Connection
  establishment uses the operating system's TCP timeout.
  [Pkarr](src/pkarr.bend) signs and verifies endpoint TXT packets. The caller
  supplies a timestamp when signing and applies its freshness policy when
  verifying. [Pkarr HTTP](src/pkarr_http.bend) publishes envelopes produced
  by `Pkarr.sign` and verifies resolved packets against the requested key.
  Pass a base URL such as `https://dns.iroh.link/pkarr` and a transfer timeout
  in milliseconds. For a local HTTPS relay, set `CURL_CA_BUNDLE` to the
  trusted CA file.


## Conformance scope

The target is the [Iroh 1.5.0 release](https://github.com/n0-computer/iroh/releases/tag/v1.5.0)
at `ea3bbb6ab41fa23816d7f9e3220ab77d444435b2`. The reference implementations
for the wire tests are the upstream [relay message codec](https://github.com/n0-computer/iroh/blob/v1.5.0/iroh-relay/src/protos/relay.rs)
and [authentication handshake](https://github.com/n0-computer/iroh/blob/v1.5.0/iroh-relay/src/protos/handshake.rs).

| Iroh behavior | Evidence or remaining work |
| --- | --- |
| Ed25519 endpoint identity, ALPN, direct QUIC | One authenticated request/response stream with upstream Iroh over IPv4 and IPv6 in both directions |
| v1/v2 relay payloads | 13 upstream byte snapshots and additional direction, version, malformed-input, and size checks |
| Relay authentication and transport | Challenge-authenticated clients exchange datagrams through upstream Iroh over WS and WSS. Untrusted TLS certificates are rejected. The TLS-exporter shortcut and native relay server are pending. |
| Public endpoint lifecycle and QUIC features | Concurrent streams, native QUIC datagrams, 0-RTT, multipath, and stream affinity are pending. |
| DNS and Pkarr discovery | UDP lookup and TCP fallback passed against a local upstream Iroh DNS server after Pkarr publication. TCP also passes fragmented maximum-length frame and error tests. Signed Pkarr packets pass byte-for-byte and tamper tests. Pkarr HTTP publish and resolve passed against the upstream Iroh DNS server. Pkarr DHT transport is pending. |
| Connectivity | NAT traversal, automatic relay fallback, and path migration are pending. |
