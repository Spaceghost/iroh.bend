# Resuming iroh.bend

When the owner says `resume` or `continue`, pick up the first open item below. Update this section when a checkpoint moves.

## Current checkpoint

1. Recheck the two-listener idle-timeout test on Fedora with ngtcp2 1.26.0 and Bend 2.0.39. On one run the IPv6 Iroh dialer negotiated 1,150 ms and reached its 12-second test deadline before reporting `TimedOut`. The wide listener negotiated 4,294,967,419 ms. The unchanged binaries passed all 19 checks on the next run. The two logs are `fedora126-config.log` and `fedora126-recheck.log` in the archive below. Capture which peer finished the handshake and which close each peer observed. The same test passed with ngtcp2 1.25.0 and Picoquic on both address families.
2. Once that case is explained, take up per-path idle expiry against Iroh 1.5.0. Exercise two paths on one connection and verify that the surviving path carries fresh application data. The Fedora-built connection-wide tests passed 64 Iroh exchanges across supplied and DNS-discovered IPv4, IPv6, WS and WSS routes in `d5a26d2`.
3. Keep live **listener** NAT mapping refresh parked until the owner asks to resume it. The outbound connection's mapping-refresh tests are a separate, passing case.

## Reproducing the first item

On the maintainer's build host, the following runs the two address families against the pinned Iroh peer. The independent reference lives outside the product tree.

```sh
ssh fedora 'bash -s' <<'FEDORA'
source ~/.local/bin/agent-storage-env iroh-idle-config
set -eu
cd "$TMPDIR/project"
export LD_LIBRARY_PATH="$TMPDIR/ngtcp2-1.26-prefix/lib:/home/linuxbrew/.linuxbrew/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
python3 -B tests/quic_idle_timeout.py "$TMPDIR/f126/iroh-bend-quic-datagram-idle-listeners" "$TMPDIR/iroh-idle-reference" --listeners
FEDORA
```

The working branch is `release/idle-config` in `/srv/ai/workspaces/iroh/idle-config` on Bak. Check `git status --short --branch` and the GitHub master tip before editing. Saved logs and the reference source are under `/srv/ai/artifacts/iroh/idle-config/` on Bak. The public [conformance scope](README.md#conformance-scope) tracks the broader implementation.

## Working agreements

- Compile on Fedora whenever it is reachable. Its Quadro P4000 and the Alienware RTX 3070 and RTX 4060 are available for GPU checks. Follow the owner's host storage rules for worktrees, builds and caches.
- Write protocol logic in Bend and native bindings in Nelua. Use upstream Iroh as the independent test peer. Keep generated C and the external Rust reference in the build workspace.
- Commit each verified change and push ordinary fast-forwards directly to GitHub `master`. Preserve existing worktrees and the parked change.
