#!/bin/sh
set -eu

client=$1
upstream=$2
work=$(mktemp -d "${TMPDIR:-/tmp}/iroh-bend-multipath-session.XXXXXXXX")
pid=
stop() {
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null || :
        wait "$pid" 2>/dev/null || :
        pid=
    fi
}
trap stop EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

check() {
    mode=$1
    host=$2
    resume=$3
    "$upstream" "$mode" > "$work/$mode.address" 2> "$work/$mode.log" &
    pid=$!
    for attempt in $(seq 1 100); do
        if [ -s "$work/$mode.address" ]; then break; fi
        if ! kill -0 "$pid" 2>/dev/null; then break; fi
        sleep .1
    done
    if [ ! -s "$work/$mode.address" ]; then
        cat "$work/$mode.log" >&2
        return 1
    fi
    IFS=' ' read -r warm target < "$work/$mode.address"
    timeout 12 "$client" "$host" "${warm##*:}" "${target##*:}" "$resume"
    wait "$pid"
    pid=
}

check listen 127.0.0.1 1
check listen6 ::1 1
check listen-binary 127.0.0.1 5
check listen-rotated 127.0.0.1 0
check listen6-rotated ::1 0
check listen-mismatch 127.0.0.1 2
check listen-mismatch 127.0.0.1 3
check listen-mismatch 127.0.0.1 4
printf 'QUIC session logs in %s\n' "$work"
