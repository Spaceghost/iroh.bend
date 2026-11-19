#!/bin/sh
set -eu

native=$1
upstream=$2
scratch=$(mktemp -d "${TMPDIR:-/tmp}/iroh-bend-streams.XXXXXXXX")
listener=
finish() {
    if [ -n "$listener" ]; then
        kill "$listener" 2>/dev/null || :
        wait "$listener" 2>/dev/null || :
    fi
    printf 'QUIC stream logs in %s\n' "$scratch"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

pair() {
    label=$1
    server=$2
    caller=$3
    listen_mode=$4
    dial_mode=$5
    address_kind=$6
    timeout 35 "$server" "$listen_mode" > "$scratch/address" 2> "$scratch/$label.server" &
    listener=$!
    for _ in $(seq 1 200); do
        test ! -s "$scratch/address" || break
        kill -0 "$listener" 2>/dev/null || break
        sleep 0.05
    done
    if ! read -r address < "$scratch/address"; then
        cat "$scratch/$label.server" >&2
        return 1
    fi
    case "$address_kind" in
        port) address=${address##*:} ;;
    esac
    if ! timeout 30 "$caller" "$dial_mode" "$address" 2> "$scratch/$label.client"; then
        cat "$scratch/$label.client" "$scratch/$label.server" >&2
        return 1
    fi
    if ! wait "$listener"; then
        cat "$scratch/$label.server" >&2
        return 1
    fi
    listener=
    printf 'PASS QUIC streams %s\n' "$label"
}

pair bend-ipv4 "$native" "$native" listen dial port
pair bend-ipv6 "$native" "$native" listen6 dial6 port

if [ -n "$upstream" ]; then
    pair bend-to-iroh-ipv4 "$upstream" "$native" listen dial port
    pair iroh-to-bend-ipv4 "$native" "$upstream" listen dial address
    pair bend-to-iroh-ipv6 "$upstream" "$native" listen6 dial6 port
    pair iroh-to-bend-ipv6 "$native" "$upstream" listen6 dial address
fi
