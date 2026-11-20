#!/bin/sh
set -eu

client=$1
ipv4=$2
ipv6=$3
echo_peer=${4:-}
shared_peer=${5:-}
if [ ! -x "$ipv4" ] || [ ! -x "$ipv6" ]; then
    printf '%s\n' 'Set UPSTREAM_DATAGRAM_V4 and UPSTREAM_DATAGRAM_V6 to the Iroh 1.5.0 listen fixtures.' >&2
    exit 2
fi
if [ -n "$echo_peer" ] && [ ! -x "$echo_peer" ]; then
    printf '%s\n' 'UPSTREAM_DATAGRAM_ECHO must name an executable Iroh fixture.' >&2
    exit 2
fi
if [ -n "$shared_peer" ] && [ ! -x "$shared_peer" ]; then
    printf '%s\n' 'UPSTREAM_QUIC_SHARED must name an executable Iroh fixture.' >&2
    exit 2
fi
work=$(mktemp -d)
pid=
stop_peer() {
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null || :
        wait "$pid" 2>/dev/null || :
        pid=
    fi
}
cleanup() {
    stop_peer
    rm -f "$work/address" "$work/error"
    rmdir "$work"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

check_peer() {
    peer=$1
    host=$2
    mode=$3
    command=$4
    : >"$work/address"
    timeout 30s "$peer" "$command" >"$work/address" 2>"$work/error" &
    pid=$!
    tries=0
    while ! IFS= read -r address <"$work/address"; do
        if ! kill -0 "$pid" 2>/dev/null || [ "$tries" -ge 300 ]; then
            printf '%s\n' "Iroh fixture did not print an address for $host ($mode)." >&2
            cat "$work/error" >&2
            exit 1
        fi
        tries=$((tries + 1))
        sleep .05
    done
    if ! "$client" "$host" "${address##*:}" "$mode"; then
        cat "$work/error" >&2
        exit 1
    fi
    if [ "$mode" = echo ] || [ "$mode" = shared ]; then
        if ! wait "$pid"; then
            cat "$work/error" >&2
            exit 1
        fi
        pid=
    else
        stop_peer
    fi
}

for mode in valid wrong-key; do
    check_peer "$ipv4" 127.0.0.1 "$mode" listen
    check_peer "$ipv6" ::1 "$mode" listen
done
if [ -n "$echo_peer" ]; then
    check_peer "$echo_peer" 127.0.0.1 echo listen
    check_peer "$echo_peer" ::1 echo listen6
fi
if [ -n "$shared_peer" ]; then
    check_peer "$shared_peer" 127.0.0.1 shared listen
    check_peer "$shared_peer" ::1 shared listen6
fi
