# iroh.bend

A Rust-free implementation targeting the Iroh 1.5.0 wire protocol. Bend
implements relay framing, authentication transcripts, client state, and DNS
and Pkarr discovery packets.
Nelua binds OpenSSL for direct QUIC and Ed25519, ngtcp2 for shared QUIC
streams and datagrams, and libcurl for WebSocket
transport and Pkarr HTTP. The relay server uses libwebsockets for raw TCP and TLS.
Bend handles the server HTTP routes, upgrades, and WebSocket framing. The build
generates native C from Bend and Nelua. Upstream Iroh runs separately as a
compatibility reference.

## Build and verify

Use Bend 2.0.39 and Clang. The native networking tests also use Nelua and
`pkg-config`. Direct QUIC requires OpenSSL 3.5 or later. The live relay
client requires a libcurl build with WebSocket support.

1. Run `make check` for the relay wire snapshots, malformed input, handshake
   framing, BLAKE3 challenge vectors, and DNS query and TXT vectors. It also
   exercises the [Bend WebSocket codec](src/relay_websocket.bend) with partial
   reads, fragmented messages, interleaved control frames, and size limits.
   The [Bend HTTP parser](src/relay_http.bend) is checked against split
   upgrade requests, repeated fields, and coalesced WebSocket bytes.
   Run `make check-relay-http-accept` to check the RFC 6455 accept digest
   and Iroh subprotocol response with Nelua and OpenSSL. Run
   `make check-relay-raw-transport` to exercise the Bend codecs together on
   a raw TCP and TLS listener, including the read-byte events delivered
   before decoded frames.
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
   Run `make check-quic-multipath` to exercise the Bend multipath
   client against Iroh. Set
   `PICOQUIC_SOURCE`, `PICOTLS_SOURCE`, and `PICOQUIC_BUILD` to the
   source and CMake build directories. Build Picoquic with picotls and
   its OpenSSL provider. If CMake fetched picotls, the target looks in
   `PICOQUIC_BUILD/_deps/picotls-build` for its static libraries. Set
   `PICOTLS_BUILD` if they are elsewhere. The verified revisions are
   Picoquic `5609e9a5fb1d64f363a0c58d93b501887eff6b28` and picotls
   `e999a3d9980843905b6c3b0f519c8a59fa45efdb`.
   Set `UPSTREAM_QUIC_MULTIPATH` to an Iroh 1.5.0 multipath listener. It
   takes `listen` or `listen6`, prints its address, and uses the
   direct-test keys and ALPN. It replies to datagram `00 80 ff`
   with `ff 80 00` and replies to an empty datagram with an empty
   datagram. It reads `0b` and `16` from the first
   two bidirectional streams, confirms Iroh received STREAM frames
   on both open IP paths, and echoes the bytes on the matching streams.
   A separate dial must fail the pinned raw public key check before
   becoming ready.
   Run `make check-quic-multipath-session` with `UPSTREAM_QUIC_MULTIPATH_SESSION`
   set to an Iroh 1.5.0 fixture that accepts two pinned connections using
   the direct-test keys. It prints the initial and follow-up addresses on
   one line. Modes `listen` and `listen6` reuse one listener.
   `listen-rotated` and `listen6-rotated` use a fresh listener with the
   same endpoint key for the follow-up. `listen-mismatch` accepts only
   the initial dial. `listen-binary` uses the ALPN bytes for
   `\0iroh-bend/compat/1\xff`.
   Run `make check-quic-multipath-early` with the same fixture variable.
   Modes `listen-early` and `listen-early6` reuse one listener and
   receive datagrams `04 00 ff` and `06 00 ff` on the follow-up.
   Modes `listen-early-rotated` and `listen-early6-rotated` use a fresh
   listener with the same endpoint key and receive only `06 00 ff`.
   Run `make check-quic-multipath-listener` with the same build settings
   and `UPSTREAM_QUIC_MULTIPATH_DIAL` set to an Iroh 1.5.0 dialer fixture.
   The fixture accepts `dial` or `dial6`, prints its address, and reads
   the Bend listen address from stdin. It first verifies TLS rejection
   with seed 74 and a mismatched ALPN. It then uses the direct-test
   credentials to open two overlapping connections. Each exchanges
   the same binary and empty datagrams with the Bend listener and sends one
   unidirectional byte (`37` or `42`) and two bidirectional bytes
   (`0b`, `16` or `21`, `2c`), with one byte per stream. It checks
   the bidi echoes, sends `4d` on a new uni stream, and waits for close.
   The target also uses the Bend dialer to open a second path and checks
   that the listener can assign a reply stream to it.
   Run `make check-endpoint-multipath` with the same build settings, libcurl,
   and `UPSTREAM_ENDPOINT_MULTIPATH` set to an Iroh 1.5.0 listener fixture.
   It uses the same direct listener arguments and exchange as
   `UPSTREAM_QUIC_MULTIPATH`. To add relay cases, set `RELAY_URL` to the
   WS or WSS endpoint and `UPSTREAM_IROH_RELAY_URL` to its HTTP or HTTPS
   origin. The fixture takes that origin as a second argument, waits
   until the relay is online before printing its address, and verifies
   that both the direct and the relay path received STREAM frames.
   The Bend test starts with a blackholed direct candidate to verify
   fallback. It also tests automatic promotion with two initially blocked
   direct candidates. After the first unpinned stream is queued on the
   relay connection, the test opens UDP forwarding for the second
   candidate and sends another unpinned stream after promotion. For WSS,
   configure both peers to trust the relay CA.
   Set `CHECK_BINARY_ALPN=1` for the binary cases in
   `check-endpoint-multipath` and `check-quic-multipath-listener`.
   When a reference fixture receives `IROH_MULTIPATH_BINARY_ALPN=1`,
   its ALPN is `00 ff 0a` followed by 252 bytes of `80`.
   In this mode the Iroh dialer must reject an ALPN mismatch that
   differs only in the last byte, then complete its normal exchanges.
   Set `CHECK_MULTIPLE_ALPNS=1` for the list negotiation cases in
   `check-quic-multipath` and `check-quic-multipath-listener`. With
   `IROH_MULTIPATH_MULTIPLE_ALPNS=1`, the Iroh listener prefers the same
   255-byte binary ALPN over the direct-test text ALPN. The Iroh dialer
   offers the text ALPN first and the binary ALPN second on its first
   connection, then offers only the text ALPN on its second connection.
   It checks both negotiated values and exercises its usual rejection
   and stream and datagram tests.
   Set `CHECK_LIVE_ALPNS=1` for the live listener update case in
   `check-quic-multipath-listener`. With `IROH_MULTIPATH_LIVE_ALPNS=1`,
   the Iroh dialer connects using the text ALPN, then waits for
   `SWITCHED` on stdin. It checks that a new text dial fails and that
   the binary ALPN now works. After `PAUSED`, another binary dial must
   fail while both existing connections exchange streams and datagrams.
4. Run `make check-relay-live RELAY_URL=ws://127.0.0.1:3340/relay` against
   an upstream `iroh-relay` in development mode on the loopback interface.
   Both relay protocol versions are exercised. For a local TLS relay, use a
   `wss://` URL and set `CURL_CA_BUNDLE` to the trusted CA file. With libcurl
   using OpenSSL, upstream Iroh logs `authentication succeeded via keying material`
   at trace level for successful TLS-exporter authentication.
   Run `make check-relay-server` with libwebsockets built with OpenSSL and
   raw socket support, Python 3, and the OpenSSL CLI to test the
   Bend server with WS and WSS. Set
   `UPSTREAM_RELAY_CLIENT` to an Iroh client fixture that accepts a relay
   base URL and an optional CA certificate in DER format.
   Run `make check-relay-raw-server` with the same fixture to exercise
   authentication, datagram forwarding, and access policies through the
   Bend HTTP and WebSocket codecs.
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
- The optional [multipath client](src/quic_multipath.bend) uses Picoquic.
  Call `connect_multipath` with numeric peer addressing, the pinned
  Ed25519 keys, and a text ALPN. Use `connect_multipath_bytes` and
  `bind_multipath_bytes` for opaque ALPN identifiers of 1 to 255 bytes.
  Use `connect_multipath_alpns` to offer several identifiers and
  `bind_multipath_alpns` to configure a listener in preference order.
  Call `negotiated_multipath_alpn` on a ready connection to read the
  exact selected bytes.
  Use `set_multipath_alpns` to replace a live listener's preferences.
  An empty list pauses admission. Connections and handshakes that
  have already selected a protocol keep it.
  Call `probe_multipath` to open a second
  UDP path on the same connection. Drive progress with `step_multipath`.
  Once a path is available, use `assign_stream_path` on a locally
  opened stream. `clear_stream_path` restores Picoquic's scheduling.
  Build with the Picoquic and picotls settings used by `check-quic-multipath`.
- The Picoquic client exposes one TLS ticket at a time through
  `take_multipath_session` after the pinned handshake. Pass the independent
  handle to `start_multipath_resume` with the same local key, peer key, and
  ALPN bytes, or release it with `drop_multipath_session`. An attempted
  resume consumes the handle. If the server rejects the ticket, the client
  completes a full pinned handshake. After authentication,
  `multipath_resumption_status` reports whether TLS resumed.
- Use `start_multipath_early` to opt in to replayable 0-RTT datagrams
  with a saved session. Call `write_multipath_early_datagram` before
  stepping the connection. A return of `1` means it was packetized,
  and `0` means it was unable to be packetized as early data. Call
  `multipath_early_status` after authentication to check whether the
  peer accepted early data. Rejected early datagrams are discarded.
- `bind_multipath` listens on a concrete IP address and pins the remote
  endpoint key and ALPN. Poll `accept_multipath` to accept authenticated
  connections and `accept_multipath_stream` to accept their bidirectional
  or receive-only streams. Accepted connections remain usable after
  `close_multipath_listener`. The dialer opens new paths, which the
  listener can discover with `next_multipath_path`.
- `multipath_datagram_limit` reports the current safe payload size for
  the connection. `write_multipath_datagram` queues an unreliable
  message. `read_multipath_datagram` returns `Some{[]}` for a received
  empty message. A full send queue returns zero. A full receive queue
  discards the oldest message so it can accept the newest one.
- The optional [multipath endpoint](src/endpoint_multipath.bend) uses
  Picoquic with the endpoint route planner. Call `connect_routes` with
  explicit routes, `lookup_and_connect` with a DNS source, or
  `verify_and_connect` with a signed Pkarr packet. Route dialing passes
  the endpoint's ALPN bytes unchanged. Use `probe_direct` to add a
  direct path while keeping an existing relay path. Pass stream and
  datagram operations through `use_connection` to keep relay ownership
  with the QUIC connection. Call `disconnect` to close both.
- For automatic selection, call `connect_routed` with the route plan and
  drive `step_routes`. A connection established over a relay probes the
  published direct addresses and makes the relay a standby after a direct
  path validates. `step_routes` reports `PromotedPath` with the direct
  path ID. Use `use_routed_connection` for application streams and
  datagrams, and `close_routes` to close the connection and relay.
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
  The default bindings use the Bend HTTP and WebSocket codecs.
  Both listener modes serve the Iroh latency probe at `/ping`, the
  `/healthz` and `/robots.txt` routes, and the index. The HTTP listener
  also answers `/generate_204` captive portal challenges. Applications
  that need WSS and a cleartext captive portal probe can bind both modes
  on separate ports.
- [Relay receive limits](src/relay_rate.bend) are configured through
  `Relay.bind_configured`. Set a rate of at least 10 bytes per second and
  an optional positive burst capacity. The default burst is one 100 ms
  refill. Bend charges binary WebSocket data as it arrives, including the
  challenge proof and each fragment's mask and frame header. It also charges
  masked Pong frames. It carries the same bucket through authentication and
  can pause reads before a message finishes. A v2 client whose proof exhausts
  the bucket receives its rate-limit notice after confirmation, even before
  sending a datagram. Use `Relay.set_client_rate_limit` between steps to
  replace the limit for existing and future clients. Pass
  `Rate.Unlimited{}` to remove it. A successful update releases paused
  reads and resets each bucket while preserving notice history. An invalid
  update returns the server handle with an error and keeps the active limit.
- [Relay access control](src/relay_access.bend) supplies endpoint allowlists,
  denylists, shared tokens, and custom callbacks through
  `Relay.bind_with_access`. The custom callback gets authenticated endpoint
  and connection IDs, the negotiated version, path, Authorization headers,
  and decoded query fragments. `Access.request_headers` lists HTTP fields,
  and `Access.header` looks them up by a case-insensitive byte name. Standard
  and custom field values retain their request order. `Access.token`
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
| Relay authentication and transport | Both Bend relay clients and servers interoperate with Iroh v1/v2 using TLS-exporter authentication. A TLS-terminating proxy triggers challenge fallback and preserves datagram exchange. Tests cover invalid certificates and proofs, mixed v1/v2 datagrams, keepalives, duplicate promotion, and endpoint departures. Admission controls support endpoint lists, shared tokens, and custom callbacks with denial reasons. Applications can disconnect individual sessions or every session for an endpoint. Callbacks can inspect standard headers and individual custom headers. Receive limits charge challenge proofs, binary WebSocket data, fragment overhead, and masked Pong frames before message delivery. Tests cover post-confirmation notices before application traffic, notices on incomplete messages, and live updates. The HTTP and HTTPS relay routes pass the same latency, health, robots, and index checks as Iroh 1.5.0. Plain HTTP also passes the upstream captive portal challenge checks. The default listener uses Bend HTTP and WebSocket framing. It exposes ordered repeated custom headers and charges post-upgrade transport reads before decoding, including partial and control frames. Ordinary HTTP requests support reuse and pipelining on both cleartext and TLS connections. |
| Public endpoint lifecycle and QUIC features | Bend and Iroh exchange RFC 9221 application datagrams alongside bidirectional and unidirectional streams on the same authenticated connection in both dialing directions over IPv4 and IPv6. The endpoint API exposes this connection for direct dialing, listening, and relay dialing. A Bend listener accepted two overlapping Iroh connections and kept both usable after it stopped accepting new connections. The direct Bend client resumed a pinned session with Iroh and sent 0-RTT streams and datagrams on both address families. A new Iroh listener rejected the prior ticket and the client retried after a pinned full handshake. An opted-in Bend listener accepted Iroh 0-RTT streams and datagrams on IPv4 and IPv6. A fresh Bend listener using the same identity rejected the prior ticket and accepted the 1-RTT retries. The optional Picoquic client uses stream affinity on two simultaneous paths with Iroh. The Picoquic listener accepts peer-initiated uni and bidi streams from overlapping Iroh connections and passes a two-path affinity check with the Bend dialer. Both dialing directions exchange binary and empty datagrams alongside streams on IPv4 and IPv6. The optional multipath endpoint uses the same timed route planner for direct and relay dialing. In IPv4 and IPv6 tests, it fell back to Iroh's WS and WSS relay, opened a direct path on the same connection, and sent application stream data over both paths. The routed API can also validate an alternate published address and prefer it automatically with the relay retained as standby. Iroh received unpinned streams over the relay before promotion and over the direct path afterward. The Picoquic endpoint and listener accept opaque ALPN bytes. A 255-byte identifier with a leading NUL passes in both directions, and the listener rejects a final-byte mismatch. Picoquic dialers can offer several protocols and listeners choose in server preference order. IPv4 and IPv6 tests against Iroh verified the preferred binary protocol, text fallback, an unsupported offer, and exact selected bytes on overlapping connections. The listener can replace its ALPN list at runtime and pause admission with an empty list. Iroh tests on IPv4 and IPv6 confirmed that new dials follow the current list while existing connections keep their selected ALPN and continue exchanging streams and datagrams. The Picoquic client resumed authenticated TLS with Iroh over IPv4 and IPv6, including an opaque ALPN. A fresh listener with the same key rejected the ticket and the client performed a pinned full handshake. The Picoquic client sent 0-RTT datagrams to Iroh over IPv4 and IPv6. With a rotated ticket key, Iroh received only the datagram sent after authentication. Picoquic early stream data and server-side resumption are pending. |
| DNS and Pkarr discovery | UDP lookup and TCP fallback passed against a local upstream Iroh DNS server after Pkarr publication. TCP also passes fragmented maximum-length frame and error tests. Signed Pkarr packets pass byte-for-byte and tamper tests. Pkarr HTTP publish, resolve, and automatic refresh work with the upstream Iroh DNS server. Single-peer and iterative IPv4 BEP 44 lookup and publishing interoperate with upstream mainline. Loopback tests cover IPv6 referrals and mixed-family lookup and publishing. The upstream Iroh DNS fallback resolves the replicated Bend publication. |
| Connectivity | The endpoint exchanged streams and datagrams with Iroh 1.5.0 over the upstream WS and WSS relay using timed direct fallback, verified Pkarr records, and an upstream Iroh DNS resolver. Direct connections survive peer UDP source-port changes and Bend-initiated migration to a new local UDP address over IPv4 and IPv6. A blackholed candidate leaves the original path and open streams usable. Bend explicitly migrates an open connection in either direction between the upstream WS or WSS relay and a direct IPv4 or IPv6 route. Tests remove the old route and finish the existing stream over the new route. Automatic relaying after a connection that started direct loses connectivity, and peer-assisted NAT traversal are pending. |
