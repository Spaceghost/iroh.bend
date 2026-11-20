#!/bin/sh
set -eu

native=$1
url=$2
upstream=${3:-}
pkarr_url=${4:-}
dns_port=${5:-}
shared=${6:-}
shared_dial=${7:-}
scratch=$(mktemp -d "${TMPDIR:-/tmp}/iroh-bend-relay-quic.XXXXXXXX")
listener=
bridge=
stop_bridge() {
    if [ -n "$bridge" ]; then
        kill "$bridge" 2>/dev/null || :
        wait "$bridge" 2>/dev/null || :
        bridge=
    fi
}
finish() {
    stop_bridge
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
    timeout 12 "$2" "${4:-dial}" "${5:-$url}"
    if ! wait "$listener"; then
        cat "$scratch/$3.listener" >&2
        return 1
    fi
    listener=
    printf 'PASS %s QUIC stream over the relay\n' "$3"
}

wait_line() {
    for _ in $(seq 1 300); do
        if IFS= read -r line < "$1"; then return 0; fi
        kill -0 "$2" 2>/dev/null || break
        sleep 0.05
    done
    cat "$3" >&2
    return 1
}

open_fixture() {
    ready="$scratch/$1.address"
    log="$scratch/$1.listener"
    : > "$ready"
    timeout 25 "$2" "$3" > "$ready" 2> "$log" &
    listener=$!
    wait_line "$ready" "$listener" "$log"
    address=$line
}

finish_fixture() {
    if ! wait "$listener"; then
        cat "$log" >&2
        return 1
    fi
    listener=
}

endpoint_direct() {
    open_fixture "endpoint-$1" "$shared" "$1"
    timeout 14 "$native" dial-endpoint-direct "$2" "${address##*:}"
    finish_fixture
}

endpoint_relay() {
    open_fixture "$1" "$shared" listen
    bridge_ready="$scratch/$1.bridge-ready"
    bridge_log="$scratch/$1.bridge-log"
    : > "$bridge_ready"
    timeout 24 "$native" bridge-endpoint "$url" "${address##*:}" > "$bridge_ready" 2> "$bridge_log" &
    bridge=$!
    wait_line "$bridge_ready" "$bridge" "$bridge_log"
    test "$line" = 'endpoint relay bridge ready'
    timeout 14 "$native" "$1" "$2"
    finish_fixture
    stop_bridge
}

endpoint_listen() {
    open_fixture "$1" "$native" "$1"
    timeout 20 "$shared_dial" dial "$address"
    finish_fixture
    tail -n +2 "$ready"
}

"$native" endpoint-plan
check "$native" "$native" bend-to-bend
check "$native" "$native" fallback dial-fallback
check "$native" "$native" pkarr dial-pkarr
timeout 20 "$native" listen-direct > "$scratch/direct.port" 2> "$scratch/direct.listener" &
listener=$!
for _ in $(seq 1 100); do
    test ! -s "$scratch/direct.port" || break
    kill -0 "$listener" 2>/dev/null || break
    sleep 0.05
done
if ! read -r port < "$scratch/direct.port"; then
    cat "$scratch/direct.listener" >&2
    exit 1
fi
timeout 12 "$native" dial-direct "$port"
wait "$listener"
listener=
timeout 6 "$native" dial-unreachable "$url"
if [ -n "$upstream" ]; then
    check "$upstream" "$native" bend-to-iroh
    check "$native" "$upstream" iroh-to-bend
fi
if [ -n "$pkarr_url" ] && [ -n "$dns_port" ]; then
    timeout 10 "$native" publish-route "$pkarr_url" "$url"
    check "$native" "$native" dns dial-dns "$dns_port"
fi
if [ -n "$shared" ]; then
    endpoint_direct listen 127.0.0.1
    endpoint_direct listen6 ::1
    endpoint_relay dial-endpoint-fallback "$url"
    endpoint_relay dial-endpoint-pkarr "$url"
    if [ -n "$pkarr_url" ] && [ -n "$dns_port" ]; then
        endpoint_relay dial-endpoint-dns "$dns_port"
    fi
fi
if [ -n "$shared_dial" ]; then
    endpoint_listen listen-endpoint
    endpoint_listen listen6-endpoint
fi
