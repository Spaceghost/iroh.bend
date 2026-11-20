#!/bin/sh
set -eu

# Two Iroh peers can discover a second loopback path. Give the loss proxy the
# only usable UDP route in a private network namespace for this control.
exec unshare --user --map-root-user --net -- sh -eu -c '
    ip link set lo up
    nft -f - <<RULES
table inet iroh_stream_finish {
    chain output {
        type filter hook output priority 0; policy accept;
        udp sport 24007 accept
        udp dport 24007 accept
        meta l4proto udp drop
    }
}
RULES
    exec python3 -B tests/quic_stream_finish.py "$1" "$1" control 24007
' sh "$1"
