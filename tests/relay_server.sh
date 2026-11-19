#!/bin/sh
set -eu

server=$1
client=$2
upstream=$3
scratch=$(mktemp -d "${TMPDIR:-/tmp}/iroh-bend-relay-server.XXXXXXXX")
pid=
stop() {
    if [ -n "$pid" ]; then
        kill "$pid" 2>/dev/null || :
        wait "$pid" 2>/dev/null || :
        pid=
    fi
}
finish() {
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
}

start ws
python3 tests/relay_server_auth.py "$port"
exercise ws
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
    'subjectAltName=DNS:localhost,IP:127.0.0.1' > "$scratch/leaf.ext"
openssl x509 -req -in "$scratch/leaf.csr" -CA "$scratch/ca.pem" -CAkey "$scratch/ca.key" \
    -CAcreateserial -days 1 -extfile "$scratch/leaf.ext" -out "$scratch/cert.pem" 2>> "$scratch/openssl.log"
start wss "$scratch/cert.pem" "$scratch/key.pem"
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
if [ -n "$upstream" ]; then
    openssl x509 -in "$scratch/ca.pem" -outform DER -out "$scratch/ca.der"
    timeout 12 "$upstream" "https://127.0.0.1:$port" "$scratch/ca.der"
fi
