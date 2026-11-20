#!/bin/sh
set -eu

client=$1
ipv4=$2
ipv6=$3
echo_peer=${4:-}
shared_peer=${5:-}
dial_peer=${6:-}
early_peer=${7:-}
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
if [ -n "$dial_peer" ] && [ ! -x "$dial_peer" ]; then
    printf '%s\n' 'UPSTREAM_QUIC_SHARED_DIAL must name an executable Iroh fixture.' >&2
    exit 2
fi
if [ -n "$early_peer" ] && [ ! -x "$early_peer" ]; then
    printf '%s\n' 'UPSTREAM_QUIC_EARLY must name an executable Iroh fixture.' >&2
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

start_listener() {
    : >"$work/address"
    timeout 30s "$1" "$2" >"$work/address" 2>"$work/error" &
    pid=$!
    tries=0
    while ! IFS= read -r address <"$work/address"; do
        if ! kill -0 "$pid" 2>/dev/null || [ "$tries" -ge 300 ]; then
            printf '%s\n' "$1 did not print an address for $2." >&2
            cat "$work/error" >&2
            exit 1
        fi
        tries=$((tries + 1))
        sleep .05
    done
}

finish_listener() {
    if wait "$pid"; then
        pid=
    else
        pid=
        cat "$work/error" >&2
        exit 1
    fi
}

check_peer() {
    host=$2
    mode=$3
    start_listener "$1" "$4"
    if ! "$client" "$host" "${address##*:}" "$mode"; then
        cat "$work/error" >&2
        exit 1
    fi
    if [ "$mode" = echo ] || [ "$mode" = shared ]; then
        finish_listener
    else
        stop_peer
    fi
}

check_listener() {
    start_listener "$client" "$1"
    if ! timeout 25s "$dial_peer" dial "$address"; then
        cat "$work/error" >&2
        exit 1
    fi
    finish_listener
    tail -n +2 "$work/address"
}

check_early() {
    start_listener "$early_peer" "$1"
    IFS=' ' read -r warm resumed < "$work/address"
    if ! timeout 12s "$client" "$2" "${warm##*:}" "${resumed##*:}" "$3"; then
        cat "$work/error" >&2
        exit 1
    fi
    finish_listener
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
if [ -n "$dial_peer" ]; then
    check_listener listen
    check_listener listen6
fi
if [ -n "$early_peer" ]; then
    check_early listen 127.0.0.1 early
    check_early listen6 ::1 early
    check_early listen-rotated 127.0.0.1 early-rejected
    check_early listen6-rotated ::1 early-rejected
    check_early listen-mismatch 127.0.0.1 ticket-mismatch
    check_early listen-mismatch 127.0.0.1 ticket-peer-mismatch
    check_early listen-mismatch 127.0.0.1 ticket-alpn-mismatch
fi
