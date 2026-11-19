# iroh.bend

A Rust-free implementation targeting the Iroh 1.5.0 wire protocol. Bend
implements relay framing, authentication transcripts, client state, and DNS
and Pkarr discovery packets.
Nelua binds OpenSSL for direct QUIC and Ed25519, and libcurl for WebSocket
transport and Pkarr HTTP. The relay server binds libwebsockets for HTTP upgrades,
WebSocket framing, and TLS. The build generates native C from Bend and Nelua. Upstream Iroh
runs separately as a compatibility reference.

## Build and verify

Use Bend 2.0.39 and Clang. The native networking tests also use Nelua and
`pkg-config`. Direct QUIC requires OpenSSL 3.5 or later. The live relay
client requires a libcurl build with WebSocket support.

1. Run `make check` for the relay wire snapshots, malformed input, handshake
   framing, BLAKE3 challenge vectors, and DNS query and TXT vectors.
   Run `make check-dns-tcp` with Python 3 for the loopback DNS fallback test.
2. Run `make check-relay-auth` and `make check-pkarr` for Ed25519 challenge and TLS-exporter proofs,
   canonical Pkarr signing, and rejection of tampered packets and wrong keys.
   Run `make check-pkarr-http` with libcurl and Python 3 for Pkarr relay
   publishing, resolution, and error handling. Run
   `make check-pkarr-http-live PKARR_URL=http://127.0.0.1:8080/pkarr` against
   a local upstream Iroh DNS server with a disposable store. Run
   `make check-pkarr-dht` with Python 3 for BEP 44 wire and loopback routing tests.
3. Run `make check-direct UPSTREAM=/path/to/upstream-peer` for mixed-peer
   QUIC. The peer fixture accepts `listen` and `dial ADDRESS`, uses the
   ALPN, identity seeds, and echo payload in [tests/direct.bend](tests/direct.bend),
   and prints its bound address. Set `UPSTREAM_IPV6` to a peer fixture whose
   listener binds to `::1` to exercise Bend dialing upstream over IPv6.
   Run `make check-quic-streams` for overlapping streams and listener reuse
   over IPv4 and IPv6.
   Set `UPSTREAM_STREAMS` to an Iroh peer that implements the exchange in
   [tests/quic_streams.bend](tests/quic_streams.bend) and accepts `listen`,
   `listen6`, and `dial ADDRESS` for mixed-peer checks.
4. Run `make check-relay-live RELAY_URL=ws://127.0.0.1:3340/relay` against
   an upstream `iroh-relay` in development mode on the loopback interface.
   Both relay protocol versions are exercised. For a local TLS relay, use a
   `wss://` URL and set `CURL_CA_BUNDLE` to the trusted CA file. With libcurl
   using OpenSSL, upstream Iroh logs `authentication succeeded via keying material`
   at trace level for successful TLS-exporter authentication.
   Run `make check-relay-server` with libwebsockets built with OpenSSL and
   custom HTTP header support, Python 3, and the OpenSSL CLI to test the
   Bend server with WS and WSS. Set
   `UPSTREAM_RELAY_CLIENT` to an Iroh client fixture that accepts a relay
   base URL and an optional CA certificate in DER format.
5. Set `CUDA_HOME` for your compiler, select a GPU with `CUDA_VISIBLE_DEVICES`,
   and run `make check-gpu` to decode 16,384 relay ping frames on the device.

Set `BEND`, `NELUA`, and `BUILD` to override the compilers and build output.

## Library interfaces

- [Relay codec](src/relay.bend) reads and writes v1/v2 WebSocket payloads.
  It handles frame direction, QUIC varint tags, wire size limits, v1 UTF-8
  health messages, and datagram ECN and segment size.
- [Relay client](src/relay_client.bend) upgrades a `ws://` or `wss://`
  connection and negotiates v1/v2. It uses TLS-exporter authentication on
  WSS when libcurl uses the linked OpenSSL major version. It answers a fresh
  Ed25519 challenge on WS or when asked by the relay. It sends datagrams and
  reads relay frames. A caller receiving a relay ping sends the given payload
  back through `pong`.
- [Relay server](src/relay_server.bend) accepts v1/v2 WebSocket upgrades,
  authenticates clients with TLS-exporter proofs or fresh Ed25519 challenges, and routes datagrams
  using the authenticated sender identity. It answers relay pings and
  replaces duplicate endpoint sessions. Supply certificate and private key
  paths for WSS, or two empty strings for WS. Drive `step` regularly and
  release the listener with `stop`.
- [Direct QUIC](src/direct.bend) pins each peer to an explicitly supplied
  Ed25519 key and negotiates the caller's ALPN over IPv4 or IPv6.
  `quic_connect` and `quic_accept_connection` return persistent connections
  with independently owned bidirectional and unidirectional streams. Stream
  operations are nonblocking. Retry on `Wait` and call `quic_tick` while
  otherwise idle. Queue and flush writes before sending FIN.
  `quic_try_accept_connection` retains the listener across accepts and
  surfaces a connection once its pinned handshake succeeds. Closing the
  listener stops new handshakes. Active connections retain the shared
  UDP socket until they and their streams close.
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
- [Pkarr DHT](src/pkarr_dht.bend) resolves or publishes a signed packet at a
  specified IPv4 DHT peer over UDP. Supply the local 20-byte DHT node ID.
  Publishing obtains the peer's write token on the same UDP socket and
  requires a sequence in the nonnegative signed 64-bit range.
  [DHT search](src/pkarr_dht_search.bend) accepts IPv4 bootstrap peers,
  follows referrals in XOR-distance order, and selects the newest verified
  record. A search makes up to 64 sequential queries. Publishing returns the
  count of acknowledgements from distinct peers, up to eight.


## Conformance scope

The target is the [Iroh 1.5.0 release](https://github.com/n0-computer/iroh/releases/tag/v1.5.0)
at `ea3bbb6ab41fa23816d7f9e3220ab77d444435b2`. The reference implementations
for the wire tests are the upstream [relay message codec](https://github.com/n0-computer/iroh/blob/v1.5.0/iroh-relay/src/protos/relay.rs)
and [authentication handshake](https://github.com/n0-computer/iroh/blob/v1.5.0/iroh-relay/src/protos/handshake.rs).

| Iroh behavior | Evidence or remaining work |
| --- | --- |
| Ed25519 endpoint identity, ALPN, direct QUIC | Single-stream exchange and overlapping bidirectional and unidirectional streams pass with upstream Iroh over IPv4 and IPv6 in both directions. |
| v1/v2 relay payloads | 13 upstream byte snapshots and additional direction, version, malformed-input, and size checks |
| Relay authentication and transport | Both Bend relay clients and servers interoperate with Iroh v1/v2 using TLS-exporter authentication. A TLS-terminating proxy triggers challenge fallback and preserves datagram exchange. Untrusted TLS certificates are rejected. The Bend server passes mixed v1/v2 routing, batched datagrams, and ping/pong. Replayed proofs and invalid signatures fall back to the challenge, and malformed proofs are rejected. Relay-generated keepalives, endpoint departure notifications, and production access and rate controls are pending. |
| Public endpoint lifecycle and QUIC features | Persistent connections support concurrent streams. One reusable listener accepted overlapping Bend and Iroh connections over IPv4 and IPv6. Native QUIC datagrams, 0-RTT, multipath, and stream affinity are pending. |
| DNS and Pkarr discovery | UDP lookup and TCP fallback passed against a local upstream Iroh DNS server after Pkarr publication. TCP also passes fragmented maximum-length frame and error tests. Signed Pkarr packets pass byte-for-byte and tamper tests. Pkarr HTTP publish and resolve passed against the upstream Iroh DNS server. Single-peer and iterative IPv4 BEP 44 lookup and publishing interoperate with upstream mainline. The upstream Iroh DNS fallback resolves the replicated Bend publication. IPv6 DHT routing and automatic republishing are pending. |
| Connectivity | NAT traversal, automatic relay fallback, and path migration are pending. |
