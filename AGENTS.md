# Resuming iroh.bend

When the owner says `resume` or `continue`, use the existing Fedora thread named `iroh.bend`.
Its Fedora user service is `iroh-bend-ocodex`.

```sh
ssh fedora '~/workspaces/2026-11-20-iroh-conformance/worker/resume.sh'
```

The launcher prints the current worker PID when it is already running. When the session has stopped, it resumes the same thread with Fedora’s `~/.bin/ocodex` at `max` in the active worktree. The user service keeps running after SSH disconnects. Read the latest output with the following command.

```sh
ssh fedora 'tmux -S "/run/user/$(id -u)/iroh-bend-ocodex.sock" capture-pane -p -t iroh-bend: | tail -12'
```

Continue the first open item below and update the checkpoint after each verified change.

## Current checkpoint

1. Match Iroh's relay path defaults and path-specific keepalives in the Picoquic endpoint. Iroh uses a 15-second idle limit on direct paths, a 30-second limit on relay paths and a five-second heartbeat on each path. Verify an idle but reachable standby and keep the existing relay-to-direct failback checks passing.
2. Carry the configured connection idle timeout through the specialized session resumption, early-data and NAT constructors. Check the advertised limit on full, resumed and rejected-early-data handshakes against Iroh 1.5.0.
3. Keep live **listener** NAT mapping refresh parked until the owner asks to resume it. The outbound connection's mapping-refresh tests are a separate, passing case.

## Checking the last checkpoint

Picoquic now expires a silent path independently of the connection. The 14 checks against Iroh's pinned Noq 1.5.0 and raw-key TLS code cover both address families, failed validation in both loss directions, validated paths in both Bend roles, the three-PTO floor, the last local path and base QUIC expiry. The original path exchanges a fresh stream after the alternate expires. The existing 21 Picoquic connection-idle checks and the CUDA suite also pass.

Run the path checks on Fedora with the build and reference scripts in the evidence directory.

```sh
source ~/.local/bin/agent-storage-env iroh-idle-config
set -eu
cd "$HOME/Projects/iroh.bend-listener-idle"
evidence="$HOME/workspaces/2026-11-20-iroh-conformance/artifacts/path-idle"
bash "$evidence/oracle/build.sh"
bash "$evidence/make.sh" check-quic-path-idle \
  UPSTREAM_QUIC_PATH_IDLE="$TMPDIR/path-idle/cargo-target/debug/iroh-path-idle-peer"
```

The canonical clone on Fedora is `~/Projects/iroh.bend`. The active worktree is `~/Projects/iroh.bend-listener-idle`, on branch `conformance/fedora-listener-idle`. Check `git status --short --branch` and the GitHub master tip before editing. The upstream sources and the two passing path-validation tests are recorded in `~/workspaces/2026-11-20-iroh-conformance/references/` and `artifacts/path-idle/`. Previous connection timer results are under `artifacts/listener-idle-start/` and `artifacts/idle-config/`. The public [conformance scope](README.md#conformance-scope) tracks the broader implementation.

## Working agreements

- Keep source edits, builds, test runs, evidence, commits and GitHub pushes on Fedora. Use its Quadro P4000 for GPU checks. Start sizable jobs with `source ~/.local/bin/agent-storage-env iroh-idle-config` and use the resulting scratch and cache locations.
- Write protocol logic in Bend and native bindings in Nelua. Use upstream Iroh as the independent test peer. Keep generated C and the external Rust reference in the build workspace.
- Commit each verified change and push ordinary fast-forwards directly to GitHub `master`. Preserve existing worktrees and the parked change.
