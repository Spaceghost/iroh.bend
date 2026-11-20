# Resuming iroh.bend

When the owner says `resume` or `continue`, pick up the first open item below. Update this section when a checkpoint moves.

## Current checkpoint

1. Implement per-path idle expiry on the Picoquic multipath endpoint. Start with the upstream `open_path_validation_fails_server_side` test in `noq-proto/src/tests/multipath.rs`. Keep the original path active while the second path is silent. Check which path expires and exchange fresh application data on the survivor.
2. Check local and remote views against Iroh 1.5.0. Its pinned QUIC implementation floors path idle timers at three probe timeouts and keeps the last local path open. Single-path QUIC uses the connection-wide timer. The Fedora reference source is in `~/workspaces/2026-11-20-iroh-conformance/references/noq-proto-1.5.0/`.
3. Keep live **listener** NAT mapping refresh parked until the owner asks to resume it. The outbound connection's mapping-refresh tests are a separate, passing case.

## Checking the last checkpoint

The two-listener test now starts the short peer after Bend accepts the wide connection. Delaying the first handshake reproduced the old test failure on both address families. The corrected suite passed 21 checks each on ngtcp2 1.25.0, ngtcp2 1.26.0 and Picoquic. The following reruns its listener cases on Fedora. The independent reference lives outside the product tree.

```sh
ssh fedora 'bash -s' <<'FEDORA'
source ~/.local/bin/agent-storage-env iroh-idle-config
set -eu
cd "$HOME/Projects/iroh.bend-listener-idle"
export LD_LIBRARY_PATH="$TMPDIR/ngtcp2-1.26-prefix/lib:/home/linuxbrew/.linuxbrew/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
python3 -B tests/quic_idle_timeout.py "$TMPDIR/pair-126/iroh-bend-quic-datagram-idle-listeners" "$TMPDIR/iroh-idle-reference" --listeners
FEDORA
```

The canonical clone on Fedora is `~/Projects/iroh.bend`. The active worktree is `~/Projects/iroh.bend-listener-idle`, on branch `conformance/fedora-listener-idle`. Check `git status --short --branch` and the GitHub master tip before editing. The timing traces are under `~/workspaces/2026-11-20-iroh-conformance/artifacts/listener-idle-start/`. The sibling `idle-config/` archive contains the original reference and the route results. The public [conformance scope](README.md#conformance-scope) tracks the broader implementation.

## Working agreements

- Keep source edits, builds, test runs, evidence, commits and GitHub pushes on Fedora. Use its Quadro P4000 for GPU checks. Start sizable jobs with `source ~/.local/bin/agent-storage-env iroh-idle-config` and use the resulting scratch and cache locations.
- Write protocol logic in Bend and native bindings in Nelua. Use upstream Iroh as the independent test peer. Keep generated C and the external Rust reference in the build workspace.
- Commit each verified change and push ordinary fast-forwards directly to GitHub `master`. Preserve existing worktrees and the parked change.
