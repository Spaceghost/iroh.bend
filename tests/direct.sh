#!/bin/sh
set -eu
native=$1
upstream=$2
scratch=$(mktemp -d "${TMPDIR:-/tmp}/iroh-bend-direct.XXXXXXXX")
listener=
finish() {
    if [ -n "$listener" ]; then
        kill "$listener" 2>/dev/null || :
        wait "$listener" 2>/dev/null || :
    fi
    printf 'Direct interop logs in %s\n' "$scratch"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start() {
    timeout 35 "$1" "${3:-listen}" > "$scratch/address" 2> "$scratch/$2.listen.log" &
    listener=$!
    for i in $(seq 1 300); do
        test ! -s "$scratch/address" || break
        if ! kill -0 "$listener" 2>/dev/null; then
            cat "$scratch/$2.listen.log" >&2
            return 1
        fi
        sleep 0.05
    done
    if ! read -r address < "$scratch/address"; then
        printf 'Listener %s did not report an address\n' "$2" >&2
        cat "$scratch/$2.listen.log" >&2
        return 1
    fi
}
pass() {
    wait "$listener"
    listener=
    printf 'PASS %s\n' "$1"
}
start "$native" bend-self
timeout 20 "$native" dial "${address##*:}"
pass 'Bend dialer -> Bend listener'
start "$upstream" upstream
timeout 20 "$native" dial "${address##*:}"
pass 'Bend dialer -> upstream Iroh listener'
start "$native" bend
timeout 20 "$upstream" dial "$address"
pass 'upstream Iroh dialer -> Bend listener'

timeout 20 "$native" close
start "$native" aborting abort-listen
abort_status=0
timeout 20 "$native" dial "${address##*:}" 2> "$scratch/dial-aborted.log" || abort_status=$?
test "$abort_status" -ne 0
test "$abort_status" -ne 124
pass 'Bend closes unused listeners and aborts accepted streams'

start "$upstream" wrong-key
status=0
timeout 10 "$native" dial-wrong-key "${address##*:}" 2> "$scratch/dial-wrong-key.log" || status=$?
test "$status" -ne 0
test "$status" -ne 124
grep -q 'peer authentication failed' "$scratch/dial-wrong-key.log"
printf 'PASS Bend dialer rejects a mismatched endpoint key\n'
