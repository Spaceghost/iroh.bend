# iroh.bend

A Rust-free implementation in progress targeting the Iroh 1.5.0 wire protocol.
Bend implements the post-authentication WebSocket relay frame codec. A native
OpenSSL host provides the transport and cryptography for the direct QUIC
request/response API. The source tree and normal build have no Rust dependency.
Upstream Iroh is built separately as the compatibility reference.

## Build and verify

Use Bend 2.0.39 and Clang. The direct tests also need OpenSSL 3.5 or later,
`pkg-config`, and an upstream Iroh 1.5.0 test peer.

1. Run `make check` for the native Bend codec suite. This runs the translated
   upstream byte snapshots and malformed-frame, frame-size, version and
   datagram metadata checks.
2. Run `make check-direct UPSTREAM=/path/to/upstream` for direct QUIC. The
   reference executable is the `upstream` binary produced by
   `tests-iroh-bend/drop-in.sh` in the [reference fork](../iroh.bend).
   The test covers both mixed-peer directions, Bend-to-Bend, and rejection
   of a peer with the wrong endpoint key.
3. Set `CUDA_HOME` for your compiler, select a GPU with `CUDA_VISIBLE_DEVICES`,
   and run `make check-gpu`. The runtime requires CUDA and decodes a batch
   of 16,384 relay ping frames on the selected card.

Set `BEND` and `BUILD` to override the compiler and build directory.

## Library interfaces

- [Relay codec](src/relay.bend) reads and writes v1/v2 post-authentication
  binary WebSocket payloads. It handles frame directions, QUIC varint tags,
  wire size limits, v1 UTF-8 health messages, and datagram ECN and segment
  sizes. The datagram API exposes the peer identity as 32 wire bytes.
- [Direct QUIC](src/direct.bend) accepts one IPv4 connection and one
  bidirectional stream. It pins both peers to explicitly supplied Ed25519
  keys, negotiates the caller's ALPN, and exchanges bounded binary messages.
  Listener and stream values are affine and each must be consumed by its next
  operation or released explicitly.

## Conformance scope

The target is the [Iroh 1.5.0 release](https://github.com/n0-computer/iroh/releases/tag/v1.5.0)
at `ea3bbb6ab41fa23816d7f9e3220ab77d444435b2`. The relay vectors come from
[Iroh's wire codec tests](https://github.com/n0-computer/iroh/blob/v1.5.0/iroh-relay/src/protos/relay.rs).

| Iroh behavior | Evidence or remaining work |
| --- | --- |
| Ed25519 endpoint identity, ALPN, direct QUIC | Mixed-peer tests for one pinned-identity IPv4 request/response stream |
| v1/v2 relay payloads | 13 upstream byte snapshots translated and matched in Bend, plus direction, version, malformed input and size checks |
| Relay authentication and transport | Implement HTTP/WebSocket upgrade, the authenticated handshake and live relay client and server |
| Public endpoint lifecycle and QUIC features | Implement concurrent streams, datagrams, 0-RTT, IPv6, multipath and stream affinity |
| Connectivity and discovery | Implement NAT traversal, relay fallback, address discovery, DNS/Pkarr and path migration |

This is a working protocol subset. Full Iroh interoperability requires the
remaining features and their upstream end-to-end tests.
