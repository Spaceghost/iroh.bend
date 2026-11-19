#!/bin/sh
set -eu

native=$1
upstream=$2
scratch=$(mktemp -d "${TMPDIR:-/tmp}/iroh-bend-streams.XXXXXXXX")
listener=
client=
finish() {
    if [ -n "$client" ]; then
        kill "$client" 2>/dev/null || :
        wait "$client" 2>/dev/null || :
    fi
    if [ -n "$listener" ]; then
        kill "$listener" 2>/dev/null || :
        wait "$listener" 2>/dev/null || :
    fi
    printf 'QUIC stream logs in %s\n' "$scratch"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start() {
    timeout 35 "$1" "$2" > "$scratch/address" 2> "$scratch/$3.server" &
    listener=$!
    for _ in $(seq 1 200); do
        test ! -s "$scratch/address" || break
        kill -0 "$listener" 2>/dev/null || break
        sleep 0.05
    done
    if ! read -r address < "$scratch/address"; then
        cat "$scratch/$3.server" >&2
        return 1
    fi
}

complete() {
    if ! wait "$listener"; then
        listener=
        cat "$scratch/$1.server" >&2
        return 1
    fi
    listener=
    printf 'PASS QUIC streams %s\n' "$1"
}

pair() {
    label=$1
    server=$2
    caller=$3
    listen_mode=$4
    dial_mode=$5
    address_kind=$6
    start "$server" "$listen_mode" "$label"
    case "$address_kind" in
        port) address=${address##*:} ;;
    esac
    if ! timeout 30 "$caller" "$dial_mode" "$address" 2> "$scratch/$label.client"; then
        cat "$scratch/$label.client" "$scratch/$label.server" >&2
        return 1
    fi
    complete "$label"
}

many() {
    label=$1
    start "$native" "$2" "$label"
    port=${address##*:}
    if [ "$2" = listen-many ]; then
        wrong=0
        timeout 6 "$native" dial-unpinned "$port" 2> "$scratch/$label.unpinned" || wrong=$?
        if [ "$wrong" -eq 0 ] || [ "$wrong" -eq 124 ]; then
            cat "$scratch/$label.unpinned" "$scratch/$label.server" >&2
            return 1
        fi
    fi
    timeout 30 "$native" "$3" "$port" 2> "$scratch/$label.first" &
    client=$!
    if [ -n "$upstream" ]; then
        caller=$upstream
        mode=dial
        destination=$address
    else
        caller=$native
        mode=$3
        destination=$port
    fi
    if ! timeout 30 "$caller" "$mode" "$destination" 2> "$scratch/$label.second"; then
        cat "$scratch/$label.first" "$scratch/$label.second" "$scratch/$label.server" >&2
        return 1
    fi
    if ! wait "$client"; then
        client=
        cat "$scratch/$label.first" "$scratch/$label.server" >&2
        return 1
    fi
    client=
    complete "$label"
}

pair bend-ipv4 "$native" "$native" listen dial port
pair bend-ipv6 "$native" "$native" listen6 dial6 port

if [ -n "$upstream" ]; then
    pair bend-to-iroh-ipv4 "$upstream" "$native" listen dial port
    pair iroh-to-bend-ipv4 "$native" "$upstream" listen dial address
    pair bend-to-iroh-ipv6 "$upstream" "$native" listen6 dial6 port
    pair iroh-to-bend-ipv6 "$native" "$upstream" listen6 dial address
fi

many reusable-listener-ipv4 listen-many dial
many reusable-listener-ipv6 listen-many6 dial6
