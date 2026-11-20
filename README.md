# iroh.bend

A Rust-free implementation targeting the Iroh 1.5.0 wire protocol. Bend
implements relay framing, authentication transcripts, client state, and DNS
and Pkarr discovery packets.
Nelua binds OpenSSL for direct QUIC and Ed25519, ngtcp2 for shared QUIC
streams and datagrams, and libcurl for WebSocket
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
   publishing, resolution, retries, automatic refresh, and shutdown. Run
   `make check-pkarr-http-live PKARR_URL=http://127.0.0.1:8080/pkarr` against
   a local upstream Iroh DNS server with a disposable store. Use the same
   URL with `make check-pkarr-publisher-live` to exercise automatic publication.
   Run
   `make check-pkarr-dht` with Python 3 for BEP 44 wire tests and loopback
   routing on IPv4, IPv6, and mixed networks.
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
   Run `make check-quic-datagram UPSTREAM_DATAGRAM_V4=/path/to/ipv4-peer
   UPSTREAM_DATAGRAM_V6=/path/to/ipv6-peer` with ngtcp2 1.25 or later and
   its OpenSSL crypto backend. Use the Iroh direct-test listener fixtures.
   The test checks packet acknowledgments, oversized payload rejection,
   and incorrect endpoint pins on both address families.
   Set `UPSTREAM_DATAGRAM_ECHO` to an Iroh 1.5.0 fixture to verify application
   delivery and exact reply bytes. The fixture accepts `listen` for IPv4 and
   `listen6` for IPv6, prints its bound address, and uses the same identity keys
   and ALPN as the direct fixture. After checking the dialer's key, it reads
   `00 62 65 6e 64 ff` and replies with `ff 00 11 80 01`. It reads and replies
   with an empty datagram, then reads `01` and replies with 24 datagrams
   containing `0e ff`. It exits successfully when the client closes QUIC.
   Set `UPSTREAM_QUIC_SHARED` to an Iroh 1.5.0 fixture that performs the same
   datagram exchange and keeps the connection open. It reads the incoming
   unidirectional stream `0c 00 ff` to FIN, replies to datagram `02` with
   `03`, then opens a unidirectional stream carrying `07 00 ff` and FIN.
   It reads 16,384 bytes of `11` followed by `00 ff` to FIN on the incoming
   bidirectional stream and sends 70,000 bytes of `12` with FIN in reply.
   Set `UPSTREAM_QUIC_SHARED_DIAL` to an Iroh 1.5.0 fixture accepting
   `dial ADDRESS` to test the Bend listener. It checks TLS rejection for
   seed 74 and an incorrect ALPN, then opens two connections using the
   direct fixture credentials and one Iroh endpoint. For labels `29` and
   `2a`, it sends a datagram, uni stream, and bidi stream containing
   `label kind ff` with kinds `00`, `01`, and `02` respectively. It reads
   each `label ff kind` reply to completion and confirms it with datagram
   `label 03`.
   Set `UPSTREAM_QUIC_EARLY` to an Iroh 1.5.0 resumption fixture. It
   prints two addresses on one line, issues a session ticket on the
   first connection, and uses the direct-test keys and ALPN.
   `listen` and `listen6` reuse the listener for the second connection and
   verify a 0-RTT stream `07 00 ff` and datagram `04 00 ff`. The
   `listen-rotated` and `listen6-rotated` variants use a second listener
   with the same identity to reject resumption and verify the explicit
   1-RTT retries `08 00 ff` on the stream and `06 00 ff` as a datagram.
   Both paths reply with `09 00 ff` and `05 00 ff` respectively.
   `listen-mismatch` serves only the initial connection.
   Set `UPSTREAM_QUIC_EARLY_DIAL` to test Bend ticket issuance with an
   Iroh client. It accepts `dial ADDRESS` or `dial-rotated WARM TARGET`.
   The warm connection exchanges datagrams `0d` and `0e` before closing.
   On the next connection, the client sends stream `11 00 ff` and
   datagram `0f 00 ff` in 0-RTT. If the target is a fresh listener it
   expects rejection and retries with `12 00 ff` and `10 00 ff`.
   It expects stream reply `13 00 ff` and datagram reply `14 00 ff`,
   then sends datagram `15` to confirm delivery.
   Run `make check-quic-rebind UPSTREAM_QUIC_REBIND=/path/to/peer` for
   IPv4 and IPv6 UDP source-port changes on established connections.
   The Iroh 1.5.0 fixture accepts `dial-rebind ADDRESS` and opens the
   same two connections and uses the same payloads as the shared dial
   fixture. It skips the key and ALPN rejection probes. After reading
   the datagram reply for label `29`, it prints `REBIND` to stdout
   and waits for `READY` on stdin before continuing. The proxy switches
   its source port before replying. After both connections close
   successfully, the fixture prints
   `PASS Iroh streams and datagrams survived UDP rebinding`.
   Run `make check-quic-migration UPSTREAM_QUIC_MIGRATION=/path/to/peer`
   to test Bend-initiated migration and rollback over IPv4 and IPv6.
   The Iroh 1.5.0 fixture accepts `listen` or `listen6`, prints its
   address, and accepts one connection with the direct-test credentials.
   It reads datagram `0a 00 ff` and three bidi stream bytes `14 00 ff`,
   then writes `15 00 ff` on that stream and replies with datagram
   `0b 00 ff`. It reads datagram `0c 00 ff` and the remaining stream
   bytes `16 00 ff` to FIN, writes `17 00 ff` with FIN on that same
   stream, then sends datagram `0d 00 ff`. It expects confirmation
   `0e 00 ff` and a successful QUIC close.
   Run `make check-quic-route-migration` with `RELAY_URL`,
   `UPSTREAM_IROH_RELAY_URL`, and `UPSTREAM_QUIC_ROUTE_MIGRATION` to
   exercise migration between an upstream relay and a direct route.
   Give the same Iroh fixture a relay origin as its second argument.
   It connects to the relay before printing its direct address, then
   performs the same exchange. For a local TLS relay, trust its CA in
   both clients. The test removes the old route before sending the
   second half of the existing stream.
   Run `make check-picoquic-multipath` to exercise the candidate
   Picoquic backend against Iroh before endpoint integration. Set
   `PICOQUIC_SOURCE`, `PICOTLS_SOURCE`, and `PICOQUIC_BUILD` to the
   source and CMake build directories. Build Picoquic with picotls and
   its OpenSSL provider. If CMake fetched picotls, the target looks in
   `PICOQUIC_BUILD/_deps/picotls-build` for its static libraries. Set
   `PICOTLS_BUILD` if they are elsewhere. The verified revisions are
   Picoquic `5609e9a5fb1d64f363a0c58d93b501887eff6b28` and picotls
   `e999a3d9980843905b6c3b0f519c8a59fa45efdb`.
   Set `UPSTREAM_QUIC_MULTIPATH` to an Iroh 1.5.0 multipath listener. It
   takes `listen` or `listen6`, prints its address, and uses the
   direct-test keys and ALPN. It reads `0b` and `16` from the first
   two bidirectional streams, confirms Iroh received STREAM frames
   on both open IP paths, and echoes the bytes on the matching streams.
   A separate dial must fail the pinned raw public key check before
   becoming ready.
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
   Run `make check-relay-quic` with the same `RELAY_URL` and the ngtcp2
   dependencies above to exercise QUIC through the relay. An optional fixture at
   `UPSTREAM_RELAY_QUIC` accepts `listen RELAY_URL` and `dial RELAY_URL` and
   uses the identity keys and ALPN from [the direct test](tests/direct.bend).
   Set `UPSTREAM_QUIC_SHARED` and `UPSTREAM_QUIC_SHARED_DIAL` to test the
   endpoint API over direct paths and the relay. Set `PKARR_URL` and
   `DISCOVERY_DNS_PORT` to exercise publication and dialing through an Iroh
   DNS server configured for `irohdns.example.`
5. Set `CUDA_HOME` for your compiler, select a GPU with `CUDA_VISIBLE_DEVICES`,
   and run `make check-gpu` to decode 16,384 relay ping frames on the device.

Set `BEND`, `NELUA`, and `BUILD` to override the compilers and build output.

## Library interfaces

- [Relay codec](src/relay.bend) reads and writes v1/v2 WebSocket payloads.
  It handles frame direction, QUIC varint tags, wire size limits, v1 UTF-8
  health messages, and datagram ECN and segment size.
- [Direct QUIC with streams and datagrams](src/quic_datagram.bend) connects to a
  numeric IPv4 or IPv6 address with a pinned Ed25519 peer key and one ALPN.
  Call `step_quic_datagram` regularly to process incoming packets and
  timers. Retry a write that returns zero after stepping. Use
  `read_quic_datagram` to drain the receive queue and
  `drop_quic_datagram` to release the connection. The receive queue uses
  Iroh's default byte budget and evicts its oldest items when full.
  The peer's QUIC
  acknowledgments report packet receipt. Application delivery requires
  an application-level response.
- The same connection can open and accept unidirectional and bidirectional
  streams. Pass the connection and returned stream ID to the stream methods.
  Queue up to 64 KiB per write, flush until the stack accepts it, and
  keep stepping until the next write is ready. A write can carry FIN,
  including an empty write. Stream reads report data, FIN, or that more
  packets are needed.
- Use `bind_shared_quic` on a concrete IPv4 or IPv6 address to accept
  connections with the same stream and datagram methods. Call
  `try_accept_shared_quic` to drive handshakes. It returns connections after
  verifying the client key and ALPN. `close_shared_quic` stops accepting
  while existing connections retain the UDP socket.
- The QUIC client can take an opaque session ticket with
  `take_quic_session` after stepping the connection. Use it once with
  `start_quic_resume` and the original local key, peer key, and ALPN.
  Enable early data to use `open_early_quic_stream` or
  `write_early_datagram` before the handshake. Only send replay-safe
  operations. Check `quic_resumption_status` after authentication. If the
  peer rejected early data, release any rejected stream handles and retry
  explicitly on the authenticated connection.
- `bind_resumable_quic` and `Endpoint.bind_resumable` opt a listener into
  tickets and early data. Each listener has its own OpenSSL replay
  protection cache, scoped to one peer key and ALPN. Accept returns the
  connection after authentication. Buffered early data is then available
  through the regular stream and datagram methods.
- `start_quic_migration` validates a new numeric local UDP address for a
  direct dial to the same peer address. Use port zero for an ephemeral
  port. A successful call returns the candidate port, or zero if QUIC
  needs more time or an unused connection ID. Keep stepping the
  connection and use `quic_migration_status` to read the outcome.
  Streams and datagrams use the existing connection throughout validation.
- `start_quic_path_migration` also takes a numeric peer address.
  `Endpoint.start_path_migration` exposes it on an endpoint connection
  and retains its relay bridge during validation. To move to a new relay,
  start a bridge for the same peer and use its loopback address as the
  candidate. Keep the active bridge running until validation succeeds.
  The candidate can use a different address family from the original path.
- [Relay client](src/relay_client.bend) upgrades a `ws://` or `wss://`
  connection and negotiates v1/v2. It uses TLS-exporter authentication on
  WSS when libcurl uses the linked OpenSSL major version. It answers a fresh
  Ed25519 challenge on WS or when asked by the relay. It sends datagrams and
  reads relay frames. `try_receive` waits up to the caller's deadline and
  returns the connection along with any complete frame. A caller receiving
  a relay ping sends the given payload back through `pong`. Use
  `connect_with_token` to supply an optional Bearer
  token. The returned handshake error includes the relay's denial reason.
- [Relay QUIC path](src/relay_quic.bend) carries QUIC between a loopback
  UDP socket and a pinned relay peer. For an incoming connection, pass the
  port from `Direct.bind` to `Path.start`. To dial, pass `0` and connect
  through the port `Path.start` returns. Call `Path.stop` to release the bridge.
  `Path.dial_with_fallback` tries a supplied direct address within the caller's
  handshake budget, then tries the supplied relay. Keep the returned bridge
  until the relayed QUIC connection closes.
- [Relay server](src/relay_server.bend) accepts v1/v2 WebSocket upgrades,
  authenticates clients with TLS-exporter proofs or fresh Ed25519 challenges,
  and routes datagrams using the authenticated sender identity. It probes
  idle connections and closes sessions that miss the pong deadline. It keeps
  duplicate sessions on standby, promotes them if the active session closes,
  and notifies datagram recipients when the last session for a sender closes.
  Supply certificate and private key paths for WSS, or two empty strings for
  WS. Drive `step` regularly and release the listener with `stop`.
- [Relay receive limits](src/relay_rate.bend) are configured through
  `Relay.bind_configured`. Set a rate of at least 10 bytes per second and
  an optional positive burst capacity. The default burst is one 100 ms
  refill. Bend charges authenticated binary WebSocket message payloads,
  pauses reads when a connection exhausts its bucket, and sends a single
  rate-limit notice to v2 clients. Use `Relay.set_client_rate_limit` between
  steps to replace the limit for existing and future clients. Pass
  `Rate.Unlimited{}` to remove it. A successful update releases paused
  reads and resets each bucket while preserving notice history. An invalid
  update returns the server handle with an error and keeps the active limit.
- [Relay access control](src/relay_access.bend) supplies endpoint allowlists,
  denylists, shared tokens, and custom callbacks through
  `Relay.bind_with_access`. The custom callback gets authenticated endpoint
  and connection IDs, the negotiated version, path, Authorization headers,
  and decoded query fragments. `Access.request_headers` lists HTTP fields,
  and `Access.header` looks them up by a case-insensitive byte name. Standard
  field values retain their request order. When a custom field repeats,
  `RepeatedCustomHeader` lets a policy decline the request. `Access.token`
  prefers a Bearer token to the first `token` query argument. An admitted
  connection generates one disconnect event. Each callback returns the next
  controller and runs in the relay's `step` or `stop` call.
  Call `Relay.disconnect` with an endpoint key and `Some{id}` to close a
  selected connection, or pass `None{}` to close all its admitted sessions.
  The next relay steps process the departures and deliver the callbacks.
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
- [Pkarr publisher](src/pkarr_publisher.bend) publishes endpoint updates in
  a background task. It signs a fresh packet for each attempt, publishes
  updates as they arrive, and refreshes unchanged records every five minutes
  by default. The default record TTL is 30 seconds. Use `stop` to close the
  update channel and wait for the task to finish.
- [Pkarr DHT](src/pkarr_dht.bend) resolves or publishes a signed packet at a
  specified IPv4 or IPv6 DHT peer over UDP. Supply the local 20-byte DHT node ID.
  Publishing obtains the peer's write token on the same UDP socket and
  requires a sequence in the nonnegative signed 64-bit range.
  [DHT search](src/pkarr_dht_search.bend) accepts bootstrap peers from both address families,
  follows referrals in XOR-distance order, and selects the newest verified
  record. A search makes up to 64 sequential queries. Publishing returns the
  count of acknowledgements from distinct peers, up to eight.
- [Endpoint](src/endpoint.bend) opens one connection for streams and
  datagrams. `connect` and `connect_routes` try the supplied direct
  addresses before relays. `lookup_and_connect` fetches endpoint records
  from a DNS resolver. `verify_and_connect` verifies a signed Pkarr envelope
  against the peer's key before using its routes. `use_connection` runs a
  QUIC operation while retaining the path. `disconnect` closes QUIC and
  releases the path. `bind` and `try_accept` return the same connection
  type for inbound direct connections. The stream-only `dial` interfaces
  remain available.


## Conformance scope

The target is the [Iroh 1.5.0 release](https://github.com/n0-computer/iroh/releases/tag/v1.5.0)
at `ea3bbb6ab41fa23816d7f9e3220ab77d444435b2`. The reference implementations
for the wire tests are the upstream [relay message codec](https://github.com/n0-computer/iroh/blob/v1.5.0/iroh-relay/src/protos/relay.rs)
and [authentication handshake](https://github.com/n0-computer/iroh/blob/v1.5.0/iroh-relay/src/protos/handshake.rs).

| Iroh behavior | Evidence or remaining work |
| --- | --- |
| Ed25519 endpoint identity, ALPN, direct QUIC | Single-stream exchange and overlapping bidirectional and unidirectional streams pass with upstream Iroh over IPv4 and IPv6 in both directions. |
| v1/v2 relay payloads | 13 upstream byte snapshots and additional direction, version, malformed-input, and size checks |
| Relay authentication and transport | Both Bend relay clients and servers interoperate with Iroh v1/v2 using TLS-exporter authentication. A TLS-terminating proxy triggers challenge fallback and preserves datagram exchange. Tests cover invalid certificates and proofs, mixed v1/v2 datagrams, keepalives, duplicate promotion, and endpoint departures. Admission controls support endpoint lists, shared tokens, and custom callbacks with denial reasons. Applications can disconnect individual sessions or every session for an endpoint. Callbacks can inspect standard headers and individual custom headers. Receive limits throttle each connection at the relay message layer, support live updates, and send v2 notices. Full values for repeated custom headers and transport-byte accounting are pending. |
| Public endpoint lifecycle and QUIC features | Bend and Iroh exchange RFC 9221 application datagrams alongside bidirectional and unidirectional streams on the same authenticated connection in both dialing directions over IPv4 and IPv6. The endpoint API exposes this connection for direct dialing, listening, and relay dialing. A Bend listener accepted two overlapping Iroh connections and kept both usable after it stopped accepting new connections. The direct Bend client resumed a pinned session with Iroh and sent 0-RTT streams and datagrams on both address families. A new Iroh listener rejected the prior ticket and the client retried after a pinned full handshake. An opted-in Bend listener accepted Iroh 0-RTT streams and datagrams on IPv4 and IPv6. A fresh Bend listener using the same identity rejected the prior ticket and accepted the 1-RTT retries. The Nelua/Picoquic client interop check verifies pinned raw-key TLS and affine streams across two simultaneous Iroh paths. Endpoint integration and incoming multipath connections are pending. |
| DNS and Pkarr discovery | UDP lookup and TCP fallback passed against a local upstream Iroh DNS server after Pkarr publication. TCP also passes fragmented maximum-length frame and error tests. Signed Pkarr packets pass byte-for-byte and tamper tests. Pkarr HTTP publish, resolve, and automatic refresh work with the upstream Iroh DNS server. Single-peer and iterative IPv4 BEP 44 lookup and publishing interoperate with upstream mainline. Loopback tests cover IPv6 referrals and mixed-family lookup and publishing. The upstream Iroh DNS fallback resolves the replicated Bend publication. |
| Connectivity | The endpoint exchanged streams and datagrams with Iroh 1.5.0 over the upstream WS and WSS relay using timed direct fallback, verified Pkarr records, and an upstream Iroh DNS resolver. Direct connections survive peer UDP source-port changes and Bend-initiated migration to a new local UDP address over IPv4 and IPv6. A blackholed candidate leaves the original path and open streams usable. Bend explicitly migrates an open connection in either direction between the upstream WS or WSS relay and a direct IPv4 or IPv6 route. Tests remove the old route and finish the existing stream over the new route. Automatic path selection and NAT traversal are pending. |
