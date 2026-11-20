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
   Run `make check-quic-listener-identity` with both QUIC build configurations.
   Set `UPSTREAM_QUIC_IDENTITY_DIAL` to the early-data dialer with its local
   secret seed byte selectable through `IROH_TEST_SEED`. The test connects
   two peers to one listener and verifies their authenticated remote IDs
   on full handshakes and on 0-RTT resumption.
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
   second half of the existing stream. It also leaves an open stream idle
   on healthy UDP, drops all direct packets before migration starts, and
   verifies that automatic recovery skips an unusable relay and finishes
   the original stream through the upstream relay.
   Run `make check-quic-restore-direct` with an Iroh fixture that also
   handles `IROH_BASE_ROUTE_RESTORE=1`. After the same stream prefix,
   the fixture reads the next stream bytes `16`, `00`, and `ff` in
   separate stages. It acknowledges the first two with datagrams
   `0c 00 ff` and `10 00 ff`, then performs the usual final exchange
   after FIN. The test runs with both an initial direct connection and
   an initial relay connection.
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
   Run `make check-quic-multipath-early-streams` with
   `UPSTREAM_QUIC_EARLY` to verify the 0-RTT stream and datagram against
   the same resumption fixture used by `check-quic-datagram`.
   Run `make check-quic-multipath-early-uni` with the same fixture
   variable and listener modes suffixed with `-uni`. Those modes accept
   a unidirectional stream instead of a bidirectional stream and
   acknowledge it with datagram `05 00 ff`. The rotated modes verify
   that the new listener receives only the authenticated 1-RTT retry.
   Run `make check-quic-multipath-early-listener` with the same build settings
   and the `UPSTREAM_QUIC_EARLY_DIAL` fixture used by `check-quic-datagram`.
   This checks TLS resumption and early stream and datagram delivery over IPv4
   and IPv6, plus explicit 1-RTT retries after a fresh listener rejects a ticket.
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
   Run `make check-endpoint-multipath-recovery` with the same relay
   variables and an Iroh fixture that handles `IROH_RELAY_RECOVERY=1`.
   It reads `0b` on a bidirectional stream over UDP, sends datagram
   `0c`, then reads `16` on the same stream after the test cuts UDP.
   The fixture verifies that Iroh received the remaining STREAM data
   over the relay and replies on the stream with `17` and FIN.
   Run `make check-endpoint-multipath-restore-direct` with a fixture
   that also handles `IROH_RELAY_RECOVERY=2`. It acknowledges relay
   byte `16` with datagram `17` and restored UDP byte `21` with
   datagram `22`. After a second outage it reads relay byte `2c` and
   replies with stream byte `2d` and FIN. All four bytes arrive on the
   original bidirectional stream, and the fixture checks each route.
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
   Run `make check-relay-quic-inbound` with those relay URLs and Python
   3.11 or later. Set
   `UPSTREAM_RELAY_INBOUND` to an Iroh 1.5.0 dialer that takes the relay
   origin as its only argument. It uses seed bytes 73 and 74 to open two
   simultaneous relay-only connections to seed 42 with the direct fixture
   ALPN. Each sends datagram `seed 00 ff` and then stream `seed 01 ff`.
   It expects `ff 00 seed` and `ff 01 seed` as replies, confirms delivery with
   datagram `seed 02 ff`, then prints `PASS two overlapping Iroh peers exchanged streams and datagrams through one relay registration`.
   Keep the connections alive until the test sends `FINISH` on stdin.
   Run `make check-relay-quic-reconnect` with Python 3.11 or later and a
   loopback relay. The same fixture accepts a second argument, `reconnect`,
   for the single seed-73 exchange. After the first datagram reply, it prints
   `READY to disconnect the relay` and waits for `RESUME` on stdin before
   opening the stream on its existing connection. After the stream reply and
   final datagram, it prints `PASS Iroh kept its established QUIC connection across relay reconnect`
   and keeps the connection alive until it reads `FINISH` on stdin.
   Run `make check-relay-quic-direct-relay` with the same upstream reference
   and Python 3.11 or later. The fixture takes `ORIGIN direct-relay IPV4:PORT
   [IPV6]:PORT` and dials the seed-42 listener concurrently with seed 73 over
   relay, seed 74 over direct IPv4, and seed 75 over direct IPv6. Each uses the
   same datagram and stream exchange as the two-peer fixture. It prints
   `PASS Iroh peers exchanged data over direct IPv4, direct IPv6 and relay routes`
   after all three exchanges and keeps the connections alive until `FINISH`
   arrives on stdin. Run `make check-endpoint-multipath-listener` with the
   same fixture to exercise the Picoquic listener and verify that all three
   connections negotiate multipath.
   Run `make check-endpoint-multipath-inbound-nat` with the same relay
   URLs and set `UPSTREAM_INBOUND_NAT` to a fixture that takes the relay
   origin and the offered direct socket address. It connects via relay to
   seed 42 with seed 73, opens a bidirectional stream, sends `a`, and
   reads `b`. When it selects a direct path it prints
   `READY to disconnect the relay`. On `RESUME` it sends `c` and finishes
   the same stream, reads `d` and stream FIN, and sends datagram `ff`.
   After verifying incoming STREAM frames on direct UDP, it prints
   `PASS Iroh finished the original stream over direct UDP` and waits for
   `FINISH` before dropping the connection.
   Run `make check-endpoint-multipath-inbound-qad` with the same Iroh
   fixture and a loopback relay with authenticated QAD on UDP port 7842.
   Set `CURL_CA_BUNDLE` to the QAD server's CA. The Bend listener
   receives no explicit candidate. The test cuts its relay registration
   after Iroh selects direct UDP and verifies that the original stream finishes.
   Run `make check-endpoint-multipath-inbound-failback` with Linux user
   namespaces, `unshare`, `ip`, and `nft`. Set
   `UPSTREAM_INBOUND_FAILBACK_RELAY` to the local Iroh relay server
   executable. In this mode the Iroh fixture receives `cut-direct` as its
   third argument and binds to `127.0.0.3` or `::1` to match the candidate's
   family. Once direct is selected it sends `m` and reads `n` on
   the original stream. It verifies direct STREAM traffic and prints
   `READY to drop direct UDP`. On `RESUME` it completes the same `c`/`d`
   exchange, checks for additional relay STREAM traffic, and prints
   `PASS Iroh finished the original stream over the relay`.
   The default scheme is WS. For WSS set `INBOUND_FAILBACK_SCHEME=wss`,
   supply `INBOUND_FAILBACK_RELAY_CONFIG`, and point `CURL_CA_BUNDLE`
   and `IROH_QUIC_ROUTE_CA_DER` at the relay test CA. Set
   `INBOUND_FAILBACK_FAULT=send-error` to have the local socket reject
   direct-path sends and verify that the same stream completes over the relay.
   Run `make check-relay-quic-startup` with the same arguments to test
   startup during an outage. The fixture uses `relay-startup` in place of
   `direct-relay`, completes both direct exchanges, and prints
   `PASS Iroh reached Bend directly while its relay was unavailable`.
   It waits for `RESUME` on stdin, then dials over the relay and prints
   `PASS Iroh reached the same Bend listener over the restored relay`.
   It holds the connections until it reads `FINISH`.
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
- `Endpoint.bind_identity` and `bind_quic_identity` authenticate inbound
  Ed25519 peer keys independently. Read the accepted peer key with
  `Endpoint.remote_id` or `quic_remote_id`. Pass `1` for `early_data` to
  enable listener-scoped tickets and buffered 0-RTT.
- `Endpoint.bind_relay_identity` accepts peers through one authenticated
  relay registration. Poll with `Endpoint.try_accept_relay_identity`, then
  use the usual connection operations and `Endpoint.remote_id`. Keep the
  listener open while its accepted connections are in use. Close it with
  `Endpoint.close_relay_identity`. The bridge admits up to 64 peer routes and
  reclaims routes after two idle minutes. After a relay disconnect it retries
  registration with backoff, preserving each peer’s local UDP route so QUIC
  can recover on the same connection.
- `Endpoint.bind_direct_relay_identity` accepts direct IPv4 and IPv6 on one
  UDP port and registers the same identity with the relay in the background.
  Direct peers can connect as soon as binding succeeds. The listener retries
  failed registration and starts accepting relayed peers once it connects.
  Pass port zero to select an available port. Poll and close with the same
  relayed listener API. Both direct families and the relay share a QUIC
  accept queue and TLS context. Direct dialing peers need reachable IP
  addresses and the returned port in their endpoint address.
- `EndpointMultipath.bind_direct_relay_identity` opens the equivalent
  Picoquic listener with a server-ordered list of ALPN byte strings and an
  opt-in early-data flag. Poll with `EndpointMultipath.accept_listener`
  to get normal Picoquic connection handles. Keep the listener open while
  its relay connections are in use, then call `EndpointMultipath.close_listener`.
- `EndpointMultipath.bind_nat_listener` offers a NAT traversal limit on
  the shared Picoquic listener. `EndpointMultipath.accept_nat_listener`
  returns a connection and its NAT driver. The listener discovers public
  addresses on its shared IPv4 and IPv6 sockets through the relay host's
  TLS-authenticated QAD service on UDP port 7842. Poll `step_listener`
  alongside stream I/O to advertise the discovered addresses on each
  accepted connection. The listener retries discovery until each configured
  family has an authenticated observation. Use
  `advertise_listener` to add explicit addresses on individual connections.
  The binding uses the listener socket for the candidate family and the
  active QUIC path for NAT control messages. Accepted connections use
  one-second QUIC keepalives so path loss can be detected while applications
  wait for input. On an established multipath connection with a second
  path, a UDP send denied by the OS or rejected because its local address or
  interface went down enters QUIC loss recovery so streams can use the
  remaining path. Close
  the listener with `EndpointMultipath.close_nat_listener`.
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
- The base endpoint exposes automatic relay recovery through
  `Endpoint.connect_routed` and `Endpoint.step_routes`. A direct
  connection with published relays uses QUIC keepalives to check
  authenticated input. After at least 3.5 seconds and three QUIC probe
  timeouts without input, it tries the configured relays and reports
  `RelayRoute` once a relay path validates on the same connection.
  While relayed, the endpoint retries published direct routes. Once
  UDP validates, it releases the relay bridge, reports `DirectRoute`,
  and resumes direct-path monitoring for another outage.
  Use `Endpoint.use_routed_connection` for stream and datagram operations
  and `Endpoint.close_routes` to release the connection and bridge.
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
- `bind_resumable_multipath` opts a Picoquic listener into authenticated
  session tickets and 0-RTT. It requires OpenSSL 3.5 or later and takes an
  opaque ALPN and a pinned peer key. Each listener has its own OpenSSL
  session cache with single-use early-data tickets. The listener exposes
  buffered early streams and datagrams after the authenticated handshake.
  Check `multipath_resumption_status` and `multipath_early_status` on the
  accepted connection.
- `bind_multipath_identity` also accepts distinct authenticated Ed25519 peers
  on one listener and takes ALPNs in server preference order.
  `multipath_remote_id` returns the peer key after authentication, including
  when the peer reconnects with a session ticket.
- Use `start_multipath_early` to opt in to replayable 0-RTT application
  data with a saved session. Call `write_multipath_early_datagram` before
  stepping the connection. A return of `1` means it was packetized,
  and `0` means it was unable to be packetized as early data. Call
  `multipath_early_status` after authentication to check whether the
  peer accepted early data. Rejected early datagrams are discarded.
- Open a stream with `open_multipath_early_stream` and queue bytes with
  `write_multipath_early_stream` before stepping the connection. After
  authentication, `resolve_multipath_early_stream` returns the accepted
  stream's ordinary ID. A rejected stream returns `None` and its queued
  bytes are discarded. Open a new stream to retry explicitly.
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
  path ID. A connection established directly validates an advertised relay
  as standby. If the direct path stops acknowledging packets, the same
  connection continues over the relay and `step_routes` reports
  `RecoveredRelay` with its path ID. The endpoint keeps probing published
  direct routes and reports `PromotedPath` when a direct path validates
  again. It keeps the relay on standby for another outage. Use
  `use_routed_connection` for application streams and datagrams, and
  `close_routes` to close the connection and relay.
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


### NAT traversal

Use `connect_nat_direct` and `step_nat_direct` in
[`endpoint_multipath.bend`](src/endpoint_multipath.bend) to validate an Iroh
candidate and retrieve the new path ID on a connection bootstrapped over UDP.

The routed multipath endpoint (`connect_routed` and `step_routes`) negotiates
NAT traversal on a relay bootstrap. It first tries published direct addresses.
When none validate, it selects local UDP sockets through the OS routes to
authenticated peer candidates, one socket per address family. It keeps the
relay available while validating the new path, then prefers the direct path
and retains the relay for recovery.
This also works when discovery provides only the relay URL. The endpoint
uses the relay hostname and Iroh’s default QAD port, UDP 7842, to query the
public mapping of each probe socket. While the connection is driven, it
checks the mapping every 25 seconds and advertises a changed address in a
new reach-out round. An established direct path stays available during the
update. A relay without QAD still supports probing with local candidates.
Use `connect_nat_relay_observed` for a non-default QAD port.

Use `connect_nat_relay` to select the probe socket explicitly. Supply a reachable
local UDP address for the independent probe socket. Port zero requests an
ephemeral port. Poll `step_nat_relay` to learn when the peer’s candidate has
become a usable path on the same connection. `disconnect_nat_relay` closes both
the QUIC connection and its relay bridge. Run `make check-endpoint-multipath-nat`
with the relay and Iroh fixture settings from `check-endpoint-multipath`.

Use `connect_nat_relay_observed` when a relay exposes Iroh’s `/iroh-qad/0`
address discovery service. Supply the service’s numeric UDP address, TLS
server name, CA bundle, and timeout in `DiscoveryServer`. The endpoint
authenticates the service and advertises the observed address of its probe
socket. Run `make check-endpoint-multipath-qad` with the same relay fixture
settings plus `QAD_TEST_IP`, `QAD_TEST_PORT`, `QAD_TEST_TLS_NAME`, and
`QAD_TEST_CA_BUNDLE`.

To serve relay address discovery, use `bind_qad_server` in
[`quic_multipath.bend`](src/quic_multipath.bend) with a concrete UDP bind
address and the relay’s PEM certificate chain and key. Call `step_qad_server`
alongside the relay’s WS or WSS loop, then `close_qad_server` at shutdown.
Run `make check-relay-qad` with an Iroh 1.5.0 QAD client in
`UPSTREAM_QAD_CLIENT`, a PEM chain in `QAD_SERVER_CERT`, the PEM key in
`QAD_SERVER_KEY`, the certificate name in `QAD_TEST_TLS_NAME`, and
the test trust root in DER format in `QAD_TEST_CA_DER`.
The fixture receives the relay socket address, TLS server name, and DER root
file as arguments and verifies that the reported address equals its UDP
socket address.

Use `bind_listener` and `accept_listener` in
[`quic_multipath_nat.bend`](src/quic_multipath_nat.bend) to opt in on the
listener. Supply the ordered ALPN byte strings when binding. For each accepted
connection, use `advertise_listener` with a reachable address for that socket
and `withdraw_listener` when that address is no longer reachable. Poll
`step_listener` alongside application I/O. It sends candidate updates,
handles the peer’s reach-out requests, and returns a candidate when the peer
answers its authenticated challenge. `listener_updates_pending` reports
whether candidate updates still await acknowledgement.

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
| Inbound peer identity | A single listener accepts distinct Ed25519 identities and reports the authenticated key on each accepted connection. The ngtcp2 and Picoquic listeners passed IPv4 and IPv6 tests with two Iroh 1.5.0 peers per listener, including recovery of both remote IDs on 0-RTT resumption. |
| Inbound relay routing | Two overlapping Iroh 1.5.0 clients used one Bend relay registration to exchange bidirectional streams and binary datagrams. WS and WSS tests checked each connection's authenticated peer identity and its distinct payload. A second WS and WSS test cut the Bend relay connection, rejected two retry attempts, then verified that an established Iroh connection completed a stream and sent a datagram after re-registration. Run `make check-relay-quic-reconnect` with the reconnect-capable Iroh fixture and the same relay URLs. The combined listener also passed overlapping direct IPv4, direct IPv6, and relay-only exchanges against Iroh 1.5.0 on WS and WSS. With either relay transport blocked at startup, direct IPv4 and IPv6 clients completed their exchanges before the same listener registered and served a relay-only peer. The shared Picoquic listener negotiated multipath and exchanged streams and datagrams with three overlapping upstream Iroh peers over direct IPv4, direct IPv6, and relay-only routes on WS and WSS. With NAT traversal enabled, Iroh 1.5.0 opened a relayed stream, selected the advertised IPv4 or IPv6 direct path, and finished that same stream after the test severed WS or WSS and blocked relay reconnection. The reverse test completed the same accepted stream over WS and WSS after confirming direct STREAM traffic and dropping direct IPv4 or IPv6 UDP in an isolated namespace. The same four cases passed with local UDP sends returning `EPERM`. With no candidate supplied, the listener used the Iroh relay's authenticated QAD observation to advertise its bound UDP socket. The same stream survived the loss of the Bend relay connection for both UDP address families over WS and WSS. |
| Public endpoint lifecycle and QUIC features | Bend and Iroh exchange RFC 9221 application datagrams alongside bidirectional and unidirectional streams on the same authenticated connection in both dialing directions over IPv4 and IPv6. The endpoint API exposes this connection for direct dialing, listening, and relay dialing. A Bend listener accepted two overlapping Iroh connections and kept both usable after it stopped accepting new connections. The direct Bend client resumed a pinned session with Iroh and sent 0-RTT streams and datagrams on both address families. A new Iroh listener rejected the prior ticket and the client retried after a pinned full handshake. An opted-in Bend listener accepted Iroh 0-RTT streams and datagrams on IPv4 and IPv6. A fresh Bend listener using the same identity rejected the prior ticket and accepted the 1-RTT retries. The optional Picoquic client uses stream affinity on two simultaneous paths with Iroh. The Picoquic listener accepts peer-initiated uni and bidi streams from overlapping Iroh connections and passes a two-path affinity check with the Bend dialer. Both dialing directions exchange binary and empty datagrams alongside streams on IPv4 and IPv6. The optional multipath endpoint uses the same timed route planner for direct and relay dialing. In IPv4 and IPv6 tests, it fell back to Iroh's WS and WSS relay, opened a direct path on the same connection, and sent application stream data over both paths. The routed API can also validate an alternate published address and prefer it automatically with the relay retained as standby. Iroh received unpinned streams over the relay before promotion and over the direct path afterward. The Picoquic endpoint and listener accept opaque ALPN bytes. A 255-byte identifier with a leading NUL passes in both directions, and the listener rejects a final-byte mismatch. Picoquic dialers can offer several protocols and listeners choose in server preference order. IPv4 and IPv6 tests against Iroh verified the preferred binary protocol, text fallback, an unsupported offer, and exact selected bytes on overlapping connections. The listener can replace its ALPN list at runtime and pause admission with an empty list. Iroh tests on IPv4 and IPv6 confirmed that new dials follow the current list while existing connections keep their selected ALPN and continue exchanging streams and datagrams. The Picoquic client resumed authenticated TLS with Iroh over IPv4 and IPv6, including an opaque ALPN. A fresh listener with the same key rejected the ticket and the client performed a pinned full handshake. The Picoquic client sent 0-RTT bidirectional and unidirectional streams and datagrams to Iroh over IPv4 and IPv6. A fresh Iroh listener rejected the early handles and data. The client reused the initial stream ID for an explicit retry after the pinned full handshake in both stream directions. An opted-in Picoquic listener issued tickets to Iroh and received 0-RTT streams and datagrams over IPv4 and IPv6. An independently bound listener with the same key rejected the old ticket and received the explicit 1-RTT retries after a full authenticated handshake. |
| DNS and Pkarr discovery | UDP lookup and TCP fallback passed against a local upstream Iroh DNS server after Pkarr publication. TCP also passes fragmented maximum-length frame and error tests. Signed Pkarr packets pass byte-for-byte and tamper tests. Pkarr HTTP publish, resolve, and automatic refresh work with the upstream Iroh DNS server. Single-peer and iterative IPv4 BEP 44 lookup and publishing interoperate with upstream mainline. Loopback tests cover IPv6 referrals and mixed-family lookup and publishing. The upstream Iroh DNS fallback resolves the replicated Bend publication. |
| Connectivity | The endpoint exchanged streams and datagrams with Iroh 1.5.0 over the upstream WS and WSS relay using timed direct fallback, verified Pkarr records, and an upstream Iroh DNS resolver. Direct connections survive peer UDP source-port changes and Bend-initiated migration to a new local UDP address over IPv4 and IPv6. A blackholed candidate leaves the original path and open streams usable. Bend explicitly migrates an open connection in either direction between the upstream WS or WSS relay and a direct IPv4 or IPv6 route. Tests remove the old route and finish the existing stream over the new route. The routed Picoquic endpoint automatically continued an open stream over the upstream WS or WSS relay after a direct IPv4 or IPv6 path was cut. It revalidated restored UDP and then reused the standby relay after a second outage. The routed base endpoint also kept an open stream when healthy UDP went idle and then recovered the same stream over WS or WSS after UDP was cut. It also restored direct UDP after a failed re-probe, then recovered over the relay after another outage on that same stream. The base endpoint can promote UDP after an initial relay dial as well. The [Bend NAT traversal codec](src/quic_nat.bend) matches the frame and transport parameter encoding from Iroh 1.5.0. The [Bend receive state](src/quic_nat_state.bend) handles candidate updates and probe requests with Iroh’s role, address-limit, and round rules. The [Bend send state](src/quic_nat_send.bend) generates server advertisements and withdrawals, client reach-out frames, and the initial probe targets for a round. Run `make check-quic-nat` for wire vectors and state transitions. The Picoquic dialer and listener read the NAT traversal limit from Iroh’s authenticated transport parameters on live IPv4 and IPv6 connections. The listener retains each peer’s parameters independently across overlapping handshakes and after it stops accepting connections. An opt-in listener advertises Bend’s limit and delivers Iroh’s authenticated REACH_OUT frames to the Bend decoder. The opt-in listener sends a short, protected PATH_CHALLENGE and checks the response token and socket addresses. Live IPv4 and IPv6 proxy tests verify a response from Iroh’s direct UDP port while streams and datagrams continue. The [Bend probe driver](src/quic_multipath_nat.bend) makes up to nine attempts per candidate using the Iroh 1.5.0 backoff schedule and stops on a matching response. Both address families pass a forced first-probe loss test. The opt-in listener sends authenticated ADD_ADDRESS and REMOVE_ADDRESS frames with Iroh on IPv4 and IPv6 and waits for packet acknowledgements. The opt-in dialer advertises its limit and accepts authenticated candidate updates. It receives ADD_ADDRESS from Iroh and applies both ADD_ADDRESS and REMOVE_ADDRESS in the Bend listener fixture on IPv4 and IPv6. The opt-in dialer sends REACH_OUT and receives authenticated responses on the same bound UDP socket. IPv4 and IPv6 proxy tests verify responses from Iroh’s direct port, distinct from the initial proxy route. After a matching probe response, the opt-in dialer opens a new multipath QUIC path on the same UDP socket. The IPv4 and IPv6 tests send streams over both paths on the same connection. For a direct bootstrap address, `connect_nat_direct` enables the automatic dialer and `step_nat_direct` returns the new path ID after validation. The automatic driver passes the same IPv4 and IPv6 proxy tests against Iroh. The opt-in listener driver manages candidate announcements and withdrawals, applies Iroh’s authenticated reach-out requests, and schedules and verifies off-path probes. It passes IPv4 and IPv6 tests against Iroh using a separate proxy route while two connections remain usable. The opt-in relay bootstrap needs only the relay URL, peer identity, and a reachable local UDP address. With no direct peer address supplied, it accepts Iroh’s advertised candidates and opens a direct path on the same connection. Tests against upstream WS and WSS relays verify Iroh receives application streams over both the original relay path and the punched IPv4 or IPv6 path. The endpoint can query a configured Iroh QUIC address discovery service over the same UDP socket and use its authenticated observation in the NAT traversal round. The Bend relay can also serve the TLS-authenticated address discovery protocol on a separate UDP socket. Overlapping Iroh 1.5.0 clients verified the reported IPv4 and IPv6 addresses and ports. Iroh rejected a mismatched TLS name. The routed multipath API now negotiates and drives NAT traversal when it bootstraps over a relay. IPv4 and IPv6 WS and WSS tests give it only the relay URL and verify that Iroh receives unpinned streams over the relay before promotion and over the punched UDP path afterward. The routed API can use separate IPv4 and IPv6 probe sockets. Run `make check-endpoint-multipath-dual-stack` with `RELAY_URL` to verify that a later IPv4 advertisement can promote a path while an earlier IPv6 candidate goes unanswered, including when the peer accepts only one reach-out address per round. With a standard Iroh QAD service, the routed API also advertises the TLS-authenticated public mapping of its probe socket. Run `make check-endpoint-multipath-automatic-qad` with a local Iroh relay URL, the QAD backend port in `QAD_TEST_PORT`, and the loopback address in `QAD_TEST_IP`. IPv4 and IPv6 tests forward UDP 7842 to the Iroh 1.5.0 backend with a different source port and check that distinct mapping in Bend’s REACH_OUT frame. Run `make check-endpoint-multipath-qad-refresh` with the same settings to change the translated port on a live connection and verify that the replacement is advertised while a stream stays on the established direct path. |
