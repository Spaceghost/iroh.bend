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

1. Match Picoquic's handling of peer abandonment of the last path to Noq 1.5.0. The upstream `remote_path_abandon_last_path` tests passed on Fedora. Verify that Bend can open a replacement within the three-PTO grace period and closes if the grace period expires without a replacement.
2. Keep live **listener** NAT mapping refresh parked until the owner asks to resume it. The outbound connection's mapping-refresh tests are a separate, passing case.

## Checking the last checkpoint

Picoquic expires a silent path independently of the connection. The suite against Iroh's pinned Noq 1.5.0 and raw-key TLS code covers both address families, failed validation in both loss directions, validated paths in both Bend roles, the three-PTO floor, the last local path and base QUIC expiry. The original path exchanges a fresh stream after the alternate expires. The heartbeat cases also verify PINGs on a reachable standby during an idle period longer than its configured path timeout. The existing 21 Picoquic connection-idle checks and the CUDA suite passed the path-expiry checkpoint.

Relay paths use a 30-second timer. The relay socket and plain direct socket on a combined listener feed the same QUIC context. A separate three-case run measured about 30 seconds in each relay role and 15 seconds on plain loopback UDP. The mixed-peer listener, outbound direct failback after a second outage, and inbound NAT relay-loss checks passed on both WS and WSS.

The ngtcp2 resumption and identity listener APIs now carry the configured connection idle timeout on direct and relayed connections. The Iroh 1.5.0 checks for these APIs run with `make check-quic-resumption-idle` and `make check-quic-resumption-idle-relay`. On Fedora, `bash ~/workspaces/2026-11-20-iroh-conformance/artifacts/resumption-idle/make.sh` runs the direct checks. Add `relays` to run both WS and WSS with a fresh local test CA. Set `NGTCP2_VERSION=1.25` to check the older library. The Iroh reference and its build script are in `oracle/` beside the runner.

Picoquic’s pinned, identity and dual-stack listeners accept a configured idle timeout for full and resumed handshakes. Run `bash ~/workspaces/2026-11-20-iroh-conformance/artifacts/pico-resumption-idle/make.sh` on Fedora for the IPv4/IPv6 listener checks against Iroh 1.5.0. Add `relays` to run the relay-only and combined listener checks over WS and WSS. Both backends also run a listener restart on the same relay and identity. Iroh verifies ticket rejection, the replacement timeout and application datagram delivery on the relay.

Pass `check-quic-multipath-resumption-idle` to the same runner to check the Picoquic dialer. On both IP families, Iroh observed the caller’s limit on accepted early data, a full handshake after ticket rejection, and a resumed connection that expired while quiet.

Picoquic’s NAT dialers and listeners advertise the configured connection idle limit. The IPv4, IPv6, WS and WSS runs checked both peers’ NAT address limits alongside the connection limit, including zero, values above 32 bits, and a shorter peer limit. Run `bash ~/workspaces/2026-11-20-iroh-conformance/artifacts/pico-nat-idle/make.sh` for the direct checks. Add `relays` for WS and WSS.

Run the path checks on Fedora with the build and reference scripts in the evidence directory.

```sh
source ~/.local/bin/agent-storage-env iroh-idle-config
set -eu
cd "$HOME/Projects/iroh.bend-listener-idle"
evidence="$HOME/workspaces/2026-11-20-iroh-conformance/artifacts/path-idle"
bash "$evidence/oracle/build.sh"
bash "$evidence/make.sh" check-quic-path-idle check-quic-path-idle-relay-profiles \
  UPSTREAM_QUIC_PATH_IDLE="$TMPDIR/path-idle/cargo-target/debug/iroh-path-idle-peer"
```

The canonical clone on Fedora is `~/Projects/iroh.bend`. The active worktree is `~/Projects/iroh.bend-listener-idle`, on branch `conformance/fedora-listener-idle`. Check `git status --short --branch` and the GitHub master tip before editing. The upstream sources and the two passing path-validation tests are recorded in `~/workspaces/2026-11-20-iroh-conformance/references/` and `artifacts/path-idle/`. Previous connection timer results are under `artifacts/listener-idle-start/` and `artifacts/idle-config/`. The public [conformance scope](README.md#conformance-scope) tracks the broader implementation.

## Working agreements

- Keep source edits, builds, test runs, evidence, commits and GitHub pushes on Fedora. Use its Quadro P4000 for GPU checks. Start sizable jobs with `source ~/.local/bin/agent-storage-env iroh-idle-config` and use the resulting scratch and cache locations.
- Write protocol logic in Bend and native bindings in Nelua. Use upstream Iroh as the independent test peer. Keep generated C and the external Rust reference in the build workspace.
- Commit each verified change and push ordinary fast-forwards directly to GitHub `master`. Preserve existing worktrees and the parked change.
