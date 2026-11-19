#!/bin/sh
set -eu

native=$1
url=$2
upstream=${3:-}
scratch=$(mktemp -d "${TMPDIR:-/tmp}/iroh-bend-relay-quic.XXXXXXXX")
listener=
finish() {
    if [ -n "$listener" ]; then
        kill "$listener" 2>/dev/null || :
        wait "$listener" 2>/dev/null || :
    fi
    printf 'Relay QUIC logs in %s\n' "$scratch"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

check() {
    timeout 20 "$1" listen "$url" > "$scratch/$3.ready" 2> "$scratch/$3.listener" &
    listener=$!
    for _ in $(seq 1 100); do
        grep -Fxq 'relay QUIC listener ready' "$scratch/$3.ready" 2>/dev/null && break
        kill -0 "$listener" 2>/dev/null || break
        sleep 0.05
    done
    if ! grep -Fxq 'relay QUIC listener ready' "$scratch/$3.ready"; then
        cat "$scratch/$3.listener" >&2
        return 1
    fi
    timeout 12 "$2" dial "$url"
    if ! wait "$listener"; then
        cat "$scratch/$3.listener" >&2
        return 1
    fi
    listener=
    printf 'PASS %s QUIC stream over the relay\n' "$3"
}

check "$native" "$native" bend-to-bend
if [ -n "$upstream" ]; then
    check "$upstream" "$native" bend-to-iroh
    check "$native" "$upstream" iroh-to-bend
fi
