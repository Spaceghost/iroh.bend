#!/bin/sh
set -eu

client=$1
peer=$2
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
    rm -f "$work/listener" "$work/errors"
    rmdir "$work"
}

trap cleanup EXIT
trap 'exit 1' HUP INT TERM

start() {
    : > "$work/listener"
    timeout 15s "$peer" "$1" >"$work/listener" 2>"$work/errors" &
    pid=$!
    tries=0
    while ! IFS= read -r address <"$work/listener"; do
        if ! kill -0 "$pid" 2>/dev/null || [ "$tries" -ge 100 ]; then
            printf '%s\n' 'Iroh did not print its listening address.' >&2
            cat "$work/errors" >&2
            exit 1
        fi
        tries=$((tries + 1))
        sleep .05
    done
}

check_family() {
    mode=$1
    host=$2
    start "$mode"
    if ! timeout 10s "$client" "$host" "${address##*:}" wrong-key; then
        cat "$work/errors" >&2
        exit 1
    fi
    stop_peer
    start "$mode"
    if ! timeout 10s "$client" "$host" "${address##*:}"; then
        cat "$work/errors" >&2
        exit 1
    fi
    if ! wait "$pid"; then
        pid=
        cat "$work/errors" >&2
        exit 1
    fi
    pid=
    tail -n +2 "$work/listener"
}

check_family listen 127.0.0.1
check_family listen6 ::1
