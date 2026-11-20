#!/bin/sh
set -eu

server=$1
client=$2
upstream=$3
scratch=$(mktemp -d "${TMPDIR:-/tmp}/iroh-bend-relay-server.XXXXXXXX")
pid=
rate_pid=
disconnect_pids=
stop() {
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null || :
        wait "$pid" 2>/dev/null || :
        pid=
    fi
}
finish() {
    if [ -n "$rate_pid" ]; then
        kill "$rate_pid" 2>/dev/null || :
        wait "$rate_pid" 2>/dev/null || :
    fi
    for watcher in $disconnect_pids; do
        kill "$watcher" 2>/dev/null || :
        wait "$watcher" 2>/dev/null || :
    done
    stop
    printf 'Relay server logs in %s\n' "$scratch"
}
trap finish EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

start() {
    scheme=$1
    shift
    "$server" "$@" > "$scratch/port" 2> "$scratch/$scheme.log" &
    pid=$!
    for _ in $(seq 1 100); do
        test ! -s "$scratch/port" || break
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.05
    done
    if ! read -r port < "$scratch/port"; then
        cat "$scratch/$scheme.log" >&2
        return 1
    fi
    case "$port" in
        ''|*[!0-9]*) cat "$scratch/$scheme.log" >&2; return 1 ;;
    esac
}

exercise() {
    relay="$1://127.0.0.1:$port/relay"
    timeout 8 "$client" "$relay" v1
    timeout 8 "$client" "$relay"
    timeout 8 "$client" "$relay" mixed
    timeout 8 "$client" "$relay" duplicate
    timeout 8 "$client" "$relay" duplicate-v1
}

expect_denied() {
    expected=$1
    shift
    result=0
    timeout 8 "$client" "$@" > "$scratch/denial.log" 2>&1 || result=$?
    if [ "$result" -eq 0 ] || [ "$result" -ge 124 ] ||
        ! grep -Fq "$expected" "$scratch/denial.log"; then
        cat "$scratch/denial.log" >&2
        return 1
    fi
}

exercise_access() {
    relay="$1://127.0.0.1:$port/relay"
    expect_denied 'not authorized' "$relay"
    expect_denied 'fixture denied ☃ 🚫' "$relay?token=allow" bearer-denied
    expect_denied 'invalid relay bearer token' "$relay" bearer-invalid
    timeout 8 "$client" "$relay?token=al%6Cow&token=deny" mixed
    timeout 8 "$client" "$relay?token=deny" bearer
    for _ in $(seq 1 100); do
        test "$(awk '/^closed / { n++ } END { print n+0 }' "$scratch/port")" -lt 4 || break
        sleep 0.05
    done
    test "$(awk '/^denied / { n++ } END { print n+0 }' "$scratch/port")" -eq 2
    awk '/^admitted / { print $2 }' "$scratch/port" | sort > "$scratch/admitted"
    awk '/^closed / { print $2 }' "$scratch/port" | sort > "$scratch/closed"
    test "$(wc -l < "$scratch/admitted")" -eq 4
    cmp "$scratch/admitted" "$scratch/closed"
    printf 'PASS %s access policy, token precedence, denial reasons, and per-session close callbacks\n' "$1"
}

await_marker() {
    for _ in $(seq 1 100); do
        grep -Fxq "$1" "$2" && return 0
        kill -0 "$3" 2>/dev/null || break
        sleep 0.05
    done
    cat "$2" >&2
    return 1
}

write_rate_command() {
    printf '%s' "$1" > "$scratch/rate-command.next"
    mv "$scratch/rate-command.next" "$scratch/rate-command"
}

exercise_live_rate() {
    transport=$1
    update=$2
    shift 2
    write_rate_command hold
    start "$transport-live-rate" live-rate "$scratch/rate-command" "$@"
    timeout 10 "$client" "$transport://127.0.0.1:$port/relay" live-rate > "$scratch/live-rate-client.log" 2>&1 &
    rate_pid=$!
    await_marker 'rate paused' "$scratch/live-rate-client.log" "$rate_pid"
    write_rate_command invalid
    await_marker 'rate rejected invalid' "$scratch/port" "$pid"
    sleep 0.3
    if grep -Fxq 'rate resumed' "$scratch/live-rate-client.log"; then
        printf 'Invalid rate update released a throttled connection\n' >&2
        return 1
    fi
    write_rate_command "$update"
    await_marker "rate applied $update" "$scratch/port" "$pid"
    if ! wait "$rate_pid"; then
        cat "$scratch/live-rate-client.log" >&2
        return 1
    fi
    rate_pid=
    grep -Fx 'PASS live receive limit changed on existing connections' "$scratch/live-rate-client.log"
    stop
}

write_disconnect_command() {
    printf '%s' "$1" > "$scratch/disconnect-command.next"
    mv "$scratch/disconnect-command.next" "$scratch/disconnect-command"
}

watch_connection() {
    label=$1
    timeout 14 "$client" "$relay" "$2" > "$scratch/$label.log" 2>&1 &
    watcher=$!
    disconnect_pids="$disconnect_pids $watcher"
    await_marker 'relay watcher ready' "$scratch/$label.log" "$watcher"
}

wait_disconnect() {
    await_marker 'relay watcher disconnected' "$scratch/$1.log" "$2"
    wait "$2"
}

exercise_disconnect() {
    transport=$1
    shift
    write_disconnect_command hold
    start "$transport-disconnect" disconnect "$scratch/disconnect-command" "$@"
    relay="$transport://127.0.0.1:$port/relay?token=allow"
    watch_connection standby watch-a
    first_pid=$watcher
    first_id=$(awk '/^admitted / { print $2; exit }' "$scratch/port")
    watch_connection survivor watch-a
    second_pid=$watcher
    watch_connection active watch-a
    third_pid=$watcher
    watch_connection other watch-b
    other_pid=$watcher

    write_disconnect_command "wrong $first_id"
    await_marker "disconnect missing wrong $first_id" "$scratch/port" "$pid"
    kill -0 "$first_pid"
    write_disconnect_command "one $first_id"
    await_marker "disconnect applied one $first_id" "$scratch/port" "$pid"
    wait_disconnect standby "$first_pid"
    await_marker "closed $first_id" "$scratch/port" "$pid"
    kill -0 "$second_pid" "$third_pid" "$other_pid"

    write_disconnect_command all
    await_marker 'disconnect applied all' "$scratch/port" "$pid"
    wait_disconnect survivor "$second_pid"
    wait_disconnect active "$third_pid"
    kill -0 "$other_pid"

    write_disconnect_command other
    await_marker 'disconnect applied other' "$scratch/port" "$pid"
    wait_disconnect other "$other_pid"
    disconnect_pids=
    for _ in $(seq 1 100); do
        test "$(awk '/^closed / { n++ } END { print n+0 }' "$scratch/port")" -lt 4 || break
        sleep 0.05
    done
    awk '/^admitted / { print $2 }' "$scratch/port" | sort > "$scratch/disconnect-admitted"
    awk '/^closed / { print $2 }' "$scratch/port" | sort > "$scratch/disconnect-closed"
    test "$(wc -l < "$scratch/disconnect-admitted")" -eq 4
    cmp "$scratch/disconnect-admitted" "$scratch/disconnect-closed"
    printf 'PASS %s connection-specific and whole-endpoint disconnect callbacks\n' "$transport"
    stop
}

start ws
python3 -B tests/relay_server_http.py "http://127.0.0.1:$port"
python3 tests/relay_server_auth.py "$port"
python3 tests/relay_client_poll.py "$client"
exercise ws
timeout 8 "$client" "ws://127.0.0.1:$port/relay" poll
timeout 30 "$client" "ws://127.0.0.1:$port/relay" heartbeat
if [ -n "$upstream" ]; then
    timeout 12 "$upstream" "http://127.0.0.1:$port"
fi
stop

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=Relay-Test-CA \
    -addext 'basicConstraints=critical,CA:TRUE' -addext 'keyUsage=critical,keyCertSign' \
    -out "$scratch/ca.pem" -keyout "$scratch/ca.key" 2> "$scratch/openssl.log"
openssl req -new -newkey rsa:2048 -nodes -subj /CN=localhost \
    -out "$scratch/leaf.csr" -keyout "$scratch/key.pem" 2>> "$scratch/openssl.log"
printf '%s\n' 'basicConstraints=critical,CA:FALSE' 'extendedKeyUsage=serverAuth' \
    'authorityKeyIdentifier=keyid:always' 'subjectAltName=DNS:localhost,IP:127.0.0.1' > "$scratch/leaf.ext"
openssl x509 -req -in "$scratch/leaf.csr" -CA "$scratch/ca.pem" -CAkey "$scratch/ca.key" \
    -CAcreateserial -days 1 -extfile "$scratch/leaf.ext" -out "$scratch/cert.pem" 2>> "$scratch/openssl.log"
start wss "$scratch/cert.pem" "$scratch/key.pem"
python3 -B tests/relay_server_http.py "https://127.0.0.1:$port" "$scratch/ca.pem"
untrusted=0
timeout 8 "$client" "wss://127.0.0.1:$port/relay" 2> "$scratch/untrusted.log" || untrusted=$?
if [ "$untrusted" -eq 0 ] || [ "$untrusted" -eq 124 ] ||
    ! grep -q 'WebSocket upgrade failed' "$scratch/untrusted.log"; then
    cat "$scratch/untrusted.log" >&2
    exit 1
fi
CURL_CA_BUNDLE="$scratch/ca.pem"
export CURL_CA_BUNDLE
exercise wss
timeout 8 "$client" "wss://127.0.0.1:$port/relay" poll
if [ -n "$upstream" ]; then
    openssl x509 -in "$scratch/ca.pem" -outform DER -out "$scratch/ca.der"
    timeout 12 "$upstream" "https://127.0.0.1:$port" "$scratch/ca.der"
fi
stop

"$server" policy-test
start shared-token shared-token
relay="ws://127.0.0.1:$port/relay"
expect_denied 'not authorized' "$relay?token=allow" bearer-denied
timeout 8 "$client" "$relay?token=deny" bearer
stop

start ws-access access
python3 tests/relay_server_auth.py "$port"
exercise_access ws
stop

start wss-access access "$scratch/cert.pem" "$scratch/key.pem"
exercise_access wss
stop

exercise_disconnect ws
exercise_disconnect wss "$scratch/cert.pem" "$scratch/key.pem"

start headers-ws headers
python3 tests/relay_server_headers.py "$port" "$client"
stop

start headers-wss headers "$scratch/cert.pem" "$scratch/key.pem"
python3 tests/relay_server_headers.py "$port" "$client" "$scratch/ca.pem"
stop

start rate-ws rate
timeout 8 "$client" "ws://127.0.0.1:$port/relay" rate
timeout 8 "$client" "ws://127.0.0.1:$port/relay" rate-v1
python3 -B tests/relay_server_fragments.py "$port" "$client"
stop

start rate-wss rate "$scratch/cert.pem" "$scratch/key.pem"
timeout 8 "$client" "wss://127.0.0.1:$port/relay" rate
timeout 8 "$client" "wss://127.0.0.1:$port/relay" rate-paced
python3 -B tests/relay_server_fragments.py "$port" "$client" "$scratch/ca.pem"
stop

exercise_live_rate ws unlimited
exercise_live_rate wss replace "$scratch/cert.pem" "$scratch/key.pem"
