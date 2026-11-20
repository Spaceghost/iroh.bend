#!/bin/sh
set -eu

server=$1
upstream=$2
scratch=$(mktemp -d "${TMPDIR:-/tmp}/iroh-bend-relay-raw-server.XXXXXXXX")
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

start() {
    scheme=$1
    shift
    "$server" "$@" > "$scratch/$scheme.port" 2> "$scratch/$scheme.log" &
    pid=$!
    for attempt in $(seq 1 100); do
        if [ -s "$scratch/$scheme.port" ]; then break; fi
        if ! kill -0 "$pid" 2>/dev/null; then break; fi
        sleep .1
    done
    port=$(head -n1 "$scratch/$scheme.port")
    if [ -z "$port" ]; then
        cat "$scratch/$scheme.log" >&2
        return 1
    fi
}

start ws
python3 -B tests/relay_server_auth.py "$port"
if [ -n "$upstream" ]; then
    timeout 15 "$upstream" "http://127.0.0.1:$port"
fi
stop

if [ -n "$upstream" ]; then
    start headers headers
    python3 -B tests/relay_raw_headers.py "$port" "$upstream"
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
    openssl x509 -in "$scratch/ca.pem" -outform DER -out "$scratch/ca.der"
    start wss "$scratch/cert.pem" "$scratch/key.pem"
    timeout 15 "$upstream" "https://127.0.0.1:$port" "$scratch/ca.der"
    stop
fi
printf 'Raw relay logs in %s\n' "$scratch"
