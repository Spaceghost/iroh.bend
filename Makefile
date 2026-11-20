BEND ?= bend
BUILD ?= build

.PHONY: check check-gpu check-dns-tcp check-relay-websocket check-relay-http check-quic-nat

check: $(BUILD)/iroh-bend-check $(BUILD)/iroh-bend-handshake $(BUILD)/iroh-bend-discovery $(BUILD)/iroh-bend-rate check-relay-websocket check-relay-http check-quic-nat
	$(BUILD)/iroh-bend-check
	$(BUILD)/iroh-bend-handshake
	$(BUILD)/iroh-bend-discovery
	$(BUILD)/iroh-bend-rate

$(BUILD)/iroh-bend-check: tests/check.bend src/relay.bend src/base32.bend
	mkdir -p $(BUILD)
	BEND_NO_TELEMETRY=1 $(BEND) tests/check.bend -o $@

$(BUILD)/iroh-bend-handshake: tests/handshake.bend src/handshake.bend src/relay_challenge.bend src/relay.bend
	mkdir -p $(BUILD)
	BEND_NO_TELEMETRY=1 $(BEND) tests/handshake.bend -o $@

$(BUILD)/iroh-bend-discovery: tests/discovery.bend src/discovery.bend src/relay.bend
	mkdir -p $(BUILD)
	BEND_NO_TELEMETRY=1 $(BEND) tests/discovery.bend -o $@

$(BUILD)/iroh-bend-rate: tests/relay_rate.bend src/relay_rate.bend src/relay_heartbeat.bend
	mkdir -p $(BUILD)
	BEND_NO_TELEMETRY=1 $(BEND) tests/relay_rate.bend -o $@

check-quic-nat: $(BUILD)/iroh-bend-quic-nat
	$(BUILD)/iroh-bend-quic-nat

$(BUILD)/iroh-bend-quic-nat: tests/quic_nat.bend src/quic_nat.bend src/quic_nat_state.bend src/quic_nat_send.bend src/quic_nat_retry.bend
	mkdir -p $(BUILD)
	BEND_NO_TELEMETRY=1 $(BEND) tests/quic_nat.bend -o $@

check-relay-websocket: $(BUILD)/iroh-bend-websocket
	$(BUILD)/iroh-bend-websocket

$(BUILD)/iroh-bend-websocket: tests/relay_websocket.bend src/relay_websocket.bend src/relay.bend
	mkdir -p $(BUILD)
	BEND_NO_TELEMETRY=1 $(BEND) tests/relay_websocket.bend -o $@

check-relay-http: $(BUILD)/iroh-bend-relay-http
	$(BUILD)/iroh-bend-relay-http

$(BUILD)/iroh-bend-relay-http: tests/relay_http.bend src/relay_http.bend src/relay_websocket.bend src/relay.bend
	mkdir -p $(BUILD)
	BEND_NO_TELEMETRY=1 $(BEND) tests/relay_http.bend -o $@

check-dns-tcp: $(BUILD)/iroh-bend-discovery
	python3 tests/discovery_tcp.py $(BUILD)/iroh-bend-discovery

check-gpu: $(BUILD)/iroh-bend-gpu
	BENDRTS= $(BUILD)/iroh-bend-gpu +RTS --gpu 1GB

$(BUILD)/iroh-bend-gpu: tests/gpu.bend tests/punycode.bend src/punycode.bend src/url_text.bend src/relay.bend
	mkdir -p $(BUILD)
	BEND_NO_TELEMETRY=1 $(BEND) tests/gpu.bend -o $@

NELUA ?= nelua
CLANG ?= clang
PKG_CONFIG ?= pkg-config
UPSTREAM ?= iroh-upstream-peer

.PHONY: check-relay-http-accept

check-relay-http-accept: $(BUILD)/iroh-bend-relay-http-accept
	$(BUILD)/iroh-bend-relay-http-accept

$(BUILD)/relay-http-accept.c: tests/relay_http_accept.bend src/relay_http.bend src/relay_http_accept.bend src/relay_http_accept.nelua tools/nelua-effect.sh
	mkdir -p "$(BUILD)/relay-http-accept-stage/src" "$(BUILD)/relay-http-accept-stage/tests"
	cp src/relay_http.bend src/relay_http_accept.bend "$(BUILD)/relay-http-accept-stage/src/"
	cp tests/relay_http_accept.bend "$(BUILD)/relay-http-accept-stage/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/relay_http_accept.nelua \
		"$(abspath $(BUILD)/relay-http-accept-stage/src/relay_http_accept.c)"
	cd "$(BUILD)/relay-http-accept-stage" && BEND_NO_TELEMETRY=1 $(BEND) tests/relay_http_accept.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-relay-http-accept: $(BUILD)/relay-http-accept.c
	$(CLANG) -std=c11 -O2 $$($(PKG_CONFIG) --cflags openssl) $< \
		-o $@ -pthread -lm $$($(PKG_CONFIG) --libs openssl)

.PHONY: check-direct

check-direct: $(BUILD)/iroh-bend-direct
	tests/direct.sh $(BUILD)/iroh-bend-direct "$(UPSTREAM)"

$(BUILD)/direct.c: tests/direct.bend src/direct.bend src/direct.nelua tools/nelua-effect.sh
	mkdir -p "$(BUILD)/stage/src" "$(BUILD)/stage/tests"
	cp src/direct.bend "$(BUILD)/stage/src/"
	cp tests/direct.bend "$(BUILD)/stage/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/direct.nelua \
		"$(abspath $(BUILD)/stage/src/direct.c)"
	cd "$(BUILD)/stage" && BEND_NO_TELEMETRY=1 $(BEND) tests/direct.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-direct: $(BUILD)/direct.c
	$(CLANG) -std=c11 -O2 $$($(PKG_CONFIG) --cflags openssl) $< \
		-o $@ -pthread -lm $$($(PKG_CONFIG) --libs openssl)

.PHONY: check-relay-auth

check-relay-auth: $(BUILD)/iroh-bend-relay-auth
	$(BUILD)/iroh-bend-relay-auth

AUTH_SOURCES = src/ed25519.bend src/handshake.bend src/relay.bend src/relay_auth.bend src/relay_challenge.bend

$(BUILD)/relay-auth.c: tests/relay_auth.bend $(AUTH_SOURCES) src/relay_exporter.bend src/ed25519.nelua tools/nelua-effect.sh
	mkdir -p "$(BUILD)/stage/src" "$(BUILD)/stage/tests"
	cp $(AUTH_SOURCES) src/relay_exporter.bend "$(BUILD)/stage/src/"
	cp tests/relay_auth.bend "$(BUILD)/stage/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/ed25519.nelua \
		"$(abspath $(BUILD)/stage/src/ed25519.c)"
	cd "$(BUILD)/stage" && BEND_NO_TELEMETRY=1 $(BEND) tests/relay_auth.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-relay-auth: $(BUILD)/relay-auth.c
	$(CLANG) -std=c11 -O2 $$($(PKG_CONFIG) --cflags openssl) $< \
		-o $@ -pthread -lm $$($(PKG_CONFIG) --libs openssl)

.PHONY: check-endpoint-id
check-endpoint-id: $(BUILD)/iroh-bend-endpoint-id
	$<

$(BUILD)/endpoint-id.c: tests/endpoint_id.bend src/endpoint_id.bend src/ed25519.bend src/ed25519.nelua tools/nelua-effect.sh
	mkdir -p "$(@:.c=-stage)/src" "$(@:.c=-stage)/tests"
	cp src/endpoint_id.bend src/ed25519.bend "$(@:.c=-stage)/src/"
	cp tests/endpoint_id.bend "$(@:.c=-stage)/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/ed25519.nelua \
		"$(abspath $(@:.c=-stage))/src/ed25519.c"
	cd "$(@:.c=-stage)" && BEND_NO_TELEMETRY=1 $(BEND) tests/endpoint_id.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-endpoint-id: $(BUILD)/endpoint-id.c
	$(CLANG) -std=c11 -O2 $$($(PKG_CONFIG) --cflags openssl) "$<" \
		-o "$@" -pthread -lm $$($(PKG_CONFIG) --libs openssl)

.PHONY: check-endpoint-ticket
UPSTREAM_ENDPOINT_TICKET_CODEC ?=
URL_TESTDATA ?=
IDNA_TESTDATA ?=
check-endpoint-ticket: $(BUILD)/iroh-bend-endpoint-ticket
	$<
	python3 -B tests/endpoint_ticket_urls.py "$<" $(if $(UPSTREAM_ENDPOINT_TICKET_CODEC),--upstream "$(UPSTREAM_ENDPOINT_TICKET_CODEC)") $(if $(URL_TESTDATA),--url-testdata "$(URL_TESTDATA)") $(if $(IDNA_TESTDATA),--idna-testdata "$(IDNA_TESTDATA)")

RELAY_URL_SOURCES = src/relay_url.bend src/url_text.bend src/url_path.bend src/url_ip.bend src/ip.bend src/idna.bend src/idna_normalize.bend src/idna_table.bend src/idna_data.bend src/punycode.bend

$(BUILD)/endpoint-ticket.c: tests/endpoint_ticket.bend tests/punycode.bend $(RELAY_URL_SOURCES) src/endpoint_ticket.bend src/endpoint_id.bend src/relay.bend src/ed25519.bend src/ed25519.nelua tools/nelua-effect.sh
	mkdir -p "$(@:.c=-stage)/src" "$(@:.c=-stage)/tests"
	cp $(RELAY_URL_SOURCES) src/endpoint_ticket.bend src/endpoint_id.bend src/relay.bend src/ed25519.bend "$(@:.c=-stage)/src/"
	cp tests/endpoint_ticket.bend tests/punycode.bend "$(@:.c=-stage)/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/ed25519.nelua \
		"$(abspath $(@:.c=-stage))/src/ed25519.c"
	cd "$(@:.c=-stage)" && BEND_NO_TELEMETRY=1 $(BEND) tests/endpoint_ticket.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-endpoint-ticket: $(BUILD)/endpoint-ticket.c
	$(CLANG) -std=c11 -O2 $$($(PKG_CONFIG) --cflags openssl) "$<" \
		-o "$@" -pthread -lm $$($(PKG_CONFIG) --libs openssl)

.PHONY: check-relay-live
RELAY_URL ?= ws://127.0.0.1:3340/relay
RELAY_SOURCES = $(AUTH_SOURCES) src/relay_client.bend src/relay_exporter.bend src/relay_socket.bend

check-relay-live: $(BUILD)/iroh-bend-relay-live
	$(BUILD)/iroh-bend-relay-live "$(RELAY_URL)"
	$(BUILD)/iroh-bend-relay-live "$(RELAY_URL)" v1
	$(BUILD)/iroh-bend-relay-live "$(RELAY_URL)" poll

$(BUILD)/relay-live.c: tests/relay_live.bend $(RELAY_SOURCES) src/ed25519.nelua src/relay_socket.nelua tools/nelua-effect.sh
	mkdir -p "$(BUILD)/relay-stage/src" "$(BUILD)/relay-stage/tests"
	cp $(RELAY_SOURCES) "$(BUILD)/relay-stage/src/"
	cp tests/relay_live.bend "$(BUILD)/relay-stage/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/ed25519.nelua \
		"$(abspath $(BUILD)/relay-stage/src/ed25519.c)"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/relay_socket.nelua \
		"$(abspath $(BUILD)/relay-stage/src/relay_socket.c)"
	cd "$(BUILD)/relay-stage" && BEND_NO_TELEMETRY=1 $(BEND) tests/relay_live.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-relay-live: $(BUILD)/relay-live.c
	$(CLANG) -std=c11 -O2 $$($(PKG_CONFIG) --cflags openssl libcurl) $< \
		-o $@ -pthread -lm $$($(PKG_CONFIG) --libs openssl libcurl)

.PHONY: check-relay-quic check-quic-route-migration check-quic-restore-direct
UPSTREAM_RELAY_QUIC ?=
UPSTREAM_QUIC_ROUTE_MIGRATION ?=
UPSTREAM_IROH_RELAY_URL ?=
DISCOVERY_DNS_PORT ?=
RELAY_QUIC_SOURCES = $(RELAY_SOURCES) src/direct.bend src/quic_datagram.bend src/quic_stream.bend src/quic_nat.bend src/relay_quic.bend src/relay_quic_inbound.bend src/quic_handshake_routes.bend src/endpoint_dial.bend src/endpoint.bend src/lookup_socket.bend src/endpoint_ticket.bend src/endpoint_id.bend $(RELAY_URL_SOURCES) src/discovery.bend src/pkarr.bend src/pkarr_http.bend src/pkarr_publisher.bend src/bencode.bend
RELAY_QUIC_EFFECTS = ed25519 relay_socket direct quic_datagram relay_quic pkarr_http pkarr_publisher lookup_socket

check-relay-quic: $(BUILD)/iroh-bend-relay-quic
	sh tests/relay_quic.sh "$(BUILD)/iroh-bend-relay-quic" "$(RELAY_URL)" "$(UPSTREAM_RELAY_QUIC)" \
		"$(PKARR_URL)" "$(DISCOVERY_DNS_PORT)" "$(UPSTREAM_QUIC_SHARED)" "$(UPSTREAM_QUIC_SHARED_DIAL)" "$(UPSTREAM_IROH_RELAY_URL)"

.PHONY: check-endpoint-connect-options check-multipath-connect-options
UPSTREAM_CONNECT_OPTIONS ?=
check-endpoint-connect-options: $(BUILD)/iroh-bend-relay-quic
	python3 -B tests/endpoint_connect_options.py "$<" endpoint "$(UPSTREAM_CONNECT_OPTIONS)"

check-multipath-connect-options: $(BUILD)/iroh-bend-endpoint-multipath-options
	python3 -B tests/endpoint_connect_options.py "$<" multipath "$(UPSTREAM_CONNECT_OPTIONS)"

.PHONY: check-multipath-negotiation
check-multipath-negotiation: $(BUILD)/iroh-bend-endpoint-multipath-ticket $(BUILD)/iroh-bend-relay-quic
	python3 -B tests/endpoint_multipath.py "$<" "$(word 2,$^)" "" "" --single-path

.PHONY: check-endpoint-ticket-dial
UPSTREAM_ENDPOINT_TICKET ?=
check-endpoint-ticket-dial: $(BUILD)/iroh-bend-relay-quic
	@test -x "$(UPSTREAM_ENDPOINT_TICKET)" || { echo 'Set UPSTREAM_ENDPOINT_TICKET to the Iroh endpoint ticket listener.' >&2; exit 2; }
	python3 -B tests/endpoint_ticket_dial.py "$<" "$(UPSTREAM_ENDPOINT_TICKET)" "$(UPSTREAM_IROH_RELAY_URL)"

.PHONY: check-endpoint-ticket-lookup
UPSTREAM_ENDPOINT_TICKET_LOOKUP ?=
check-endpoint-ticket-lookup: $(BUILD)/iroh-bend-relay-quic
	@test -x "$(UPSTREAM_ENDPOINT_TICKET_LOOKUP)" && test -n "$(PKARR_URL)" && test -n "$(DISCOVERY_DNS_PORT)" || { echo 'Set UPSTREAM_ENDPOINT_TICKET_LOOKUP, PKARR_URL and DISCOVERY_DNS_PORT for the local Iroh lookup service.' >&2; exit 2; }
	python3 -B tests/endpoint_ticket_lookup.py "$<" "$(UPSTREAM_ENDPOINT_TICKET_LOOKUP)" "$(PKARR_URL)" "$(DISCOVERY_DNS_PORT)"

.PHONY: check-relay-quic-inbound check-relay-quic-reconnect check-relay-quic-direct-relay check-relay-quic-startup
UPSTREAM_RELAY_INBOUND ?=
check-relay-quic-inbound: $(BUILD)/iroh-bend-relay-quic
	@test -x "$(UPSTREAM_RELAY_INBOUND)" || { echo 'Set UPSTREAM_RELAY_INBOUND to the Iroh two-peer relay dialer.' >&2; exit 2; }
	python3 -B tests/relay_quic_inbound.py "$<" "$(UPSTREAM_RELAY_INBOUND)" "$(RELAY_URL)" "$(UPSTREAM_IROH_RELAY_URL)"

check-relay-quic-reconnect: $(BUILD)/iroh-bend-relay-quic
	@test -x "$(UPSTREAM_RELAY_INBOUND)" || { echo 'Set UPSTREAM_RELAY_INBOUND to the Iroh relay dialer with reconnect mode.' >&2; exit 2; }
	python3 -B tests/relay_quic_reconnect.py "$<" "$(UPSTREAM_RELAY_INBOUND)" "$(RELAY_URL)" "$(UPSTREAM_IROH_RELAY_URL)"

check-relay-quic-direct-relay: $(BUILD)/iroh-bend-relay-quic
	@test -x "$(UPSTREAM_RELAY_INBOUND)" || { echo 'Set UPSTREAM_RELAY_INBOUND to the Iroh dialer with direct-relay mode.' >&2; exit 2; }
	python3 -B tests/relay_quic_inbound.py --direct-relay "$<" "$(UPSTREAM_RELAY_INBOUND)" "$(RELAY_URL)" "$(UPSTREAM_IROH_RELAY_URL)"

check-relay-quic-startup: $(BUILD)/iroh-bend-relay-quic
	@test -x "$(UPSTREAM_RELAY_INBOUND)" || { echo 'Set UPSTREAM_RELAY_INBOUND to the Iroh dialer with relay-startup mode.' >&2; exit 2; }
	python3 -B tests/relay_quic_inbound.py --relay-startup "$<" "$(UPSTREAM_RELAY_INBOUND)" "$(RELAY_URL)" "$(UPSTREAM_IROH_RELAY_URL)"

$(BUILD)/relay-quic.c: tests/relay_quic.bend tests/endpoint_validation.bend tests/endpoint_lookup_stream.bend tests/direct.bend tests/quic_streams.bend tests/quic_datagram.bend tests/quic_migration.bend $(RELAY_QUIC_SOURCES) $(addprefix src/,$(addsuffix .nelua,$(RELAY_QUIC_EFFECTS))) tools/nelua-effect.sh
	mkdir -p "$(BUILD)/relay-quic-stage/src" "$(BUILD)/relay-quic-stage/tests"
	cp $(RELAY_QUIC_SOURCES) "$(BUILD)/relay-quic-stage/src/"
	cp tests/relay_quic.bend tests/endpoint_validation.bend tests/endpoint_lookup_stream.bend tests/direct.bend tests/quic_streams.bend tests/quic_datagram.bend tests/quic_migration.bend "$(BUILD)/relay-quic-stage/tests/"
	for native in $(RELAY_QUIC_EFFECTS); do \
		tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" "src/$$native.nelua" \
			"$(abspath $(BUILD)/relay-quic-stage/src)/$$native.c" || exit; \
	done
	cd "$(BUILD)/relay-quic-stage" && BEND_NO_TELEMETRY=1 $(BEND) tests/relay_quic.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-relay-quic: $(BUILD)/relay-quic.c
	$(CLANG) -std=c11 -O2 $$($(PKG_CONFIG) --cflags $(DATAGRAM_LIBS) libcurl) $< \
		-o $@ -pthread -lm $$($(PKG_CONFIG) --libs $(DATAGRAM_LIBS) libcurl)

check-quic-route-migration: $(BUILD)/iroh-bend-quic-route-migration
	@test -x "$(UPSTREAM_QUIC_ROUTE_MIGRATION)" || { echo 'Set UPSTREAM_QUIC_ROUTE_MIGRATION to the Iroh route migration fixture.' >&2; exit 2; }
	python3 -B tests/quic_route_migration.py "$(BUILD)/iroh-bend-quic-route-migration" \
		"$(UPSTREAM_QUIC_ROUTE_MIGRATION)" "$(RELAY_URL)" "$(UPSTREAM_IROH_RELAY_URL)"

check-quic-restore-direct: $(BUILD)/iroh-bend-quic-route-migration
	@test -x "$(UPSTREAM_QUIC_ROUTE_MIGRATION)" || { echo 'Set UPSTREAM_QUIC_ROUTE_MIGRATION to the Iroh direct restoration fixture.' >&2; exit 2; }
	python3 -B tests/quic_route_migration.py "$<" "$(UPSTREAM_QUIC_ROUTE_MIGRATION)" "$(RELAY_URL)" "$(UPSTREAM_IROH_RELAY_URL)" --restore-direct

$(BUILD)/quic-route-migration.c: tests/quic_route_migration.bend tests/quic_migration.bend tests/quic_datagram.bend $(RELAY_QUIC_SOURCES) $(addprefix src/,$(addsuffix .nelua,$(RELAY_QUIC_EFFECTS))) tools/nelua-effect.sh
	mkdir -p "$(BUILD)/quic-route-migration-stage/src" "$(BUILD)/quic-route-migration-stage/tests"
	cp $(RELAY_QUIC_SOURCES) "$(BUILD)/quic-route-migration-stage/src/"
	cp tests/quic_route_migration.bend tests/quic_migration.bend tests/quic_datagram.bend "$(BUILD)/quic-route-migration-stage/tests/"
	for native in $(RELAY_QUIC_EFFECTS); do \
		tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" "src/$$native.nelua" \
			"$(abspath $(BUILD)/quic-route-migration-stage/src)/$$native.c" || exit; \
	done
	cd "$(BUILD)/quic-route-migration-stage" && BEND_NO_TELEMETRY=1 $(BEND) tests/quic_route_migration.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-quic-route-migration: $(BUILD)/quic-route-migration.c
	$(CLANG) -std=c11 -O2 $$($(PKG_CONFIG) --cflags $(DATAGRAM_LIBS) libcurl) $< \
		-o $@ -pthread -lm $$($(PKG_CONFIG) --libs $(DATAGRAM_LIBS) libcurl)

.PHONY: check-pkarr

check-pkarr: $(BUILD)/iroh-bend-pkarr
	$(BUILD)/iroh-bend-pkarr

PKARR_SOURCES = src/pkarr.bend src/discovery.bend src/ed25519.bend src/relay.bend
$(BUILD)/pkarr.c: tests/pkarr.bend $(PKARR_SOURCES) src/ed25519.nelua tools/nelua-effect.sh
	mkdir -p "$(BUILD)/pkarr-stage/src" "$(BUILD)/pkarr-stage/tests"
	cp $(PKARR_SOURCES) "$(BUILD)/pkarr-stage/src/"
	cp tests/pkarr.bend "$(BUILD)/pkarr-stage/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/ed25519.nelua \
		"$(abspath $(BUILD)/pkarr-stage/src/ed25519.c)"
	cd "$(BUILD)/pkarr-stage" && BEND_NO_TELEMETRY=1 $(BEND) tests/pkarr.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-pkarr: $(BUILD)/pkarr.c
	$(CLANG) -std=c11 -O2 $$($(PKG_CONFIG) --cflags openssl) $< \
		-o $@ -pthread -lm $$($(PKG_CONFIG) --libs openssl)

.PHONY: check-pkarr-http check-pkarr-http-live check-pkarr-publisher-live
PKARR_URL ?=
PKARR_HTTP_SOURCES = $(PKARR_SOURCES) src/bencode.bend src/pkarr_http.bend src/pkarr_publisher.bend

check-pkarr-http: $(BUILD)/iroh-bend-pkarr-http
	python3 tests/pkarr_http.py "$(BUILD)/iroh-bend-pkarr-http"

check-pkarr-http-live: $(BUILD)/iroh-bend-pkarr-http
	test -n "$(PKARR_URL)"
	"$(BUILD)/iroh-bend-pkarr-http" publish "$(PKARR_URL)"
	"$(BUILD)/iroh-bend-pkarr-http" resolve "$(PKARR_URL)"

check-pkarr-publisher-live: $(BUILD)/iroh-bend-pkarr-http
	test -n "$(PKARR_URL)"
	"$(BUILD)/iroh-bend-pkarr-http" republish "$(PKARR_URL)"

$(BUILD)/pkarr-http.c: tests/pkarr_http.bend tests/pkarr.bend $(PKARR_HTTP_SOURCES) src/pkarr_http.nelua src/pkarr_publisher.nelua src/ed25519.nelua tools/nelua-effect.sh
	mkdir -p "$(BUILD)/pkarr-http-stage/src" "$(BUILD)/pkarr-http-stage/tests"
	cp $(PKARR_HTTP_SOURCES) "$(BUILD)/pkarr-http-stage/src/"
	cp tests/pkarr_http.bend tests/pkarr.bend "$(BUILD)/pkarr-http-stage/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/ed25519.nelua \
		"$(abspath $(BUILD)/pkarr-http-stage/src/ed25519.c)"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/pkarr_http.nelua \
		"$(abspath $(BUILD)/pkarr-http-stage/src/pkarr_http.c)"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/pkarr_publisher.nelua \
		"$(abspath $(BUILD)/pkarr-http-stage/src/pkarr_publisher.c)"
	cd "$(BUILD)/pkarr-http-stage" && BEND_NO_TELEMETRY=1 $(BEND) tests/pkarr_http.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-pkarr-http: $(BUILD)/pkarr-http.c
	$(CLANG) -std=c11 -O2 $$($(PKG_CONFIG) --cflags openssl libcurl) $< \
		-o $@ -pthread -lm $$($(PKG_CONFIG) --libs openssl libcurl)

.PHONY: check-pkarr-dht
PKARR_DHT_SOURCES = $(PKARR_SOURCES) src/bencode.bend src/krpc.bend src/ip.bend src/pkarr_dht.bend src/pkarr_dht_search.bend src/pkarr_dht_socket.bend

check-pkarr-dht: $(BUILD)/iroh-bend-pkarr-dht
	"$(BUILD)/iroh-bend-pkarr-dht"
	python3 tests/pkarr_dht_routing.py "$(BUILD)/iroh-bend-pkarr-dht"

$(BUILD)/pkarr-dht.c: tests/pkarr_dht.bend tests/pkarr.bend $(PKARR_DHT_SOURCES) src/ed25519.nelua src/pkarr_dht_socket.nelua tools/nelua-effect.sh
	mkdir -p "$(BUILD)/pkarr-dht-stage/src" "$(BUILD)/pkarr-dht-stage/tests"
	cp $(PKARR_DHT_SOURCES) "$(BUILD)/pkarr-dht-stage/src/"
	cp tests/pkarr_dht.bend tests/pkarr.bend "$(BUILD)/pkarr-dht-stage/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/ed25519.nelua \
		"$(abspath $(BUILD)/pkarr-dht-stage/src/ed25519.c)"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/pkarr_dht_socket.nelua \
		"$(abspath $(BUILD)/pkarr-dht-stage/src/pkarr_dht_socket.c)"
	cd "$(BUILD)/pkarr-dht-stage" && BEND_NO_TELEMETRY=1 $(BEND) tests/pkarr_dht.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-pkarr-dht: $(BUILD)/pkarr-dht.c
	$(CLANG) -std=c11 -O2 $$($(PKG_CONFIG) --cflags openssl) $< \
		-o $@ -pthread -lm $$($(PKG_CONFIG) --libs openssl)

.PHONY: check-quic-streams
UPSTREAM_STREAMS ?=

check-quic-streams: $(BUILD)/iroh-bend-quic-streams
	tests/quic_streams.sh "$(BUILD)/iroh-bend-quic-streams" "$(UPSTREAM_STREAMS)"

$(BUILD)/quic-streams.c: tests/quic_streams.bend tests/direct.bend src/direct.bend src/direct.nelua tools/nelua-effect.sh
	mkdir -p "$(BUILD)/quic-streams-stage/src" "$(BUILD)/quic-streams-stage/tests"
	cp src/direct.bend "$(BUILD)/quic-streams-stage/src/"
	cp tests/direct.bend tests/quic_streams.bend "$(BUILD)/quic-streams-stage/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/direct.nelua \
		"$(abspath $(BUILD)/quic-streams-stage/src/direct.c)"
	cd "$(BUILD)/quic-streams-stage" && BEND_NO_TELEMETRY=1 $(BEND) tests/quic_streams.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-quic-streams: $(BUILD)/quic-streams.c
	$(CLANG) -std=c11 -O2 $$($(PKG_CONFIG) --cflags openssl) $< \
		-o $@ -pthread -lm $$($(PKG_CONFIG) --libs openssl)

.PHONY: check-relay-server
UPSTREAM_RELAY_CLIENT ?=
RELAY_SERVER_SOURCES = $(AUTH_SOURCES) $(RELAY_RAW_SOURCES) src/relay_exporter.bend src/relay_heartbeat.bend \
	src/relay_rate.bend src/relay_access.bend src/relay_server.bend src/relay_transport.bend src/relay_http_routes.bend

check-relay-server: $(BUILD)/iroh-bend-relay-server $(BUILD)/iroh-bend-relay-live
	tests/relay_server.sh "$(BUILD)/iroh-bend-relay-server" "$(BUILD)/iroh-bend-relay-live" "$(UPSTREAM_RELAY_CLIENT)"

$(BUILD)/relay-server.c: tests/relay_server.bend
$(BUILD)/relay-raw-server.c: tests/relay_raw_server.bend

$(BUILD)/relay-server.c $(BUILD)/relay-raw-server.c: $(RELAY_SERVER_SOURCES) src/ed25519.nelua src/relay_server_socket.nelua src/relay_http_accept.nelua tools/nelua-effect.sh
	mkdir -p "$(@:.c=-stage)/src" "$(@:.c=-stage)/tests"
	cp $(sort $(RELAY_SERVER_SOURCES)) "$(@:.c=-stage)/src/"
	cp $(filter tests/%.bend,$^) "$(@:.c=-stage)/tests/"
	for native in ed25519 $(RELAY_RAW_EFFECTS); do \
		tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" "src/$$native.nelua" \
			"$(abspath $(@:.c=-stage))/src/$$native.c" || exit; \
	done
	cd "$(@:.c=-stage)" && BEND_NO_TELEMETRY=1 $(BEND) "tests/$(notdir $(filter tests/%.bend,$^))" -o "$(abspath $@)"

$(BUILD)/iroh-bend-relay-server: $(BUILD)/relay-server.c
$(BUILD)/iroh-bend-relay-raw-server: $(BUILD)/relay-raw-server.c

$(BUILD)/iroh-bend-relay-server $(BUILD)/iroh-bend-relay-raw-server:
	$(CLANG) -std=c11 -O2 $$($(PKG_CONFIG) --cflags openssl libwebsockets) $< \
		-o $@ -pthread -lm $$($(PKG_CONFIG) --libs openssl libwebsockets)

.PHONY: check-relay-raw-server
check-relay-raw-server: $(BUILD)/iroh-bend-relay-raw-server
	sh tests/relay_raw_server.sh "$<" "$(UPSTREAM_RELAY_CLIENT)"

.PHONY: check-relay-raw-transport
RELAY_RAW_SOURCES = src/relay_server_socket.bend src/relay_http.bend src/relay_http_accept.bend \
	src/relay_raw_http.bend src/relay_websocket.bend src/relay.bend
RELAY_RAW_EFFECTS = relay_server_socket relay_http_accept

check-relay-raw-transport: $(BUILD)/iroh-bend-relay-raw-transport
	python3 -B tests/relay_raw_transport.py "$<"

$(BUILD)/relay-raw-transport.c: tests/relay_raw_transport.bend $(RELAY_RAW_SOURCES) $(addprefix src/,$(addsuffix .nelua,$(RELAY_RAW_EFFECTS))) tools/nelua-effect.sh
	mkdir -p "$(BUILD)/relay-raw-stage/src" "$(BUILD)/relay-raw-stage/tests"
	cp $(RELAY_RAW_SOURCES) "$(BUILD)/relay-raw-stage/src/"
	cp tests/relay_raw_transport.bend "$(BUILD)/relay-raw-stage/tests/"
	for native in $(RELAY_RAW_EFFECTS); do \
		tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" "src/$$native.nelua" \
			"$(abspath $(BUILD)/relay-raw-stage/src)/$$native.c" || exit; \
	done
	cd "$(BUILD)/relay-raw-stage" && BEND_NO_TELEMETRY=1 $(BEND) tests/relay_raw_transport.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-relay-raw-transport: $(BUILD)/relay-raw-transport.c
	$(CLANG) -std=c11 -O2 $$($(PKG_CONFIG) --cflags openssl libwebsockets) $< \
		-o $@ -pthread -lm $$($(PKG_CONFIG) --libs openssl libwebsockets)

.PHONY: check-quic-datagram check-quic-rebind check-quic-migration
.PHONY: check-picoquic-multipath check-quic-multipath check-quic-multipath-listener check-quic-multipath-session check-quic-multipath-early check-quic-multipath-early-streams check-endpoint-multipath
.PHONY: check-quic-multipath-early-uni
.PHONY: check-endpoint-multipath-recovery check-endpoint-multipath-restore-direct check-endpoint-multipath-nat check-endpoint-multipath-qad
UPSTREAM_DATAGRAM_V4 ?=
UPSTREAM_DATAGRAM_V6 ?=
UPSTREAM_DATAGRAM_ECHO ?=
UPSTREAM_QUIC_SHARED ?=
UPSTREAM_QUIC_SHARED_DIAL ?=
UPSTREAM_QUIC_EARLY ?=
UPSTREAM_QUIC_EARLY_DIAL ?=
UPSTREAM_QUIC_REBIND ?=
UPSTREAM_QUIC_MIGRATION ?=
DATAGRAM_LIBS = libngtcp2_crypto_ossl libngtcp2 openssl
QUIC_EARLY_LISTENER = $(if $(strip $(UPSTREAM_QUIC_EARLY_DIAL)),$(BUILD)/iroh-bend-quic-early-listener)

check-quic-datagram: $(BUILD)/iroh-bend-quic-datagram $(QUIC_EARLY_LISTENER)
	sh tests/quic_datagram.sh "$(BUILD)/iroh-bend-quic-datagram" "$(UPSTREAM_DATAGRAM_V4)" \
		"$(UPSTREAM_DATAGRAM_V6)" "$(UPSTREAM_DATAGRAM_ECHO)" "$(UPSTREAM_QUIC_SHARED)" \
		"$(UPSTREAM_QUIC_SHARED_DIAL)" "$(UPSTREAM_QUIC_EARLY)" "$(UPSTREAM_QUIC_EARLY_DIAL)" "$(QUIC_EARLY_LISTENER)"

.PHONY: check-quic-listener-identity
UPSTREAM_QUIC_IDENTITY_DIAL ?=
check-quic-listener-identity: $(BUILD)/iroh-bend-quic-early-listener $(BUILD)/iroh-bend-quic-multipath-early-listener
	@test -x "$(UPSTREAM_QUIC_IDENTITY_DIAL)" || { echo 'Set UPSTREAM_QUIC_IDENTITY_DIAL to the seed-selectable Iroh early-data dialer.' >&2; exit 2; }
	python3 -B tests/quic_listener_identity.py "$(BUILD)/iroh-bend-quic-early-listener" "$(UPSTREAM_QUIC_IDENTITY_DIAL)"
	python3 -B tests/quic_listener_identity.py "$(BUILD)/iroh-bend-quic-multipath-early-listener" "$(UPSTREAM_QUIC_IDENTITY_DIAL)"

check-quic-rebind: $(BUILD)/iroh-bend-quic-datagram
	@test -x "$(UPSTREAM_QUIC_REBIND)" || { echo 'Set UPSTREAM_QUIC_REBIND to the executable Iroh dial-rebind fixture.' >&2; exit 2; }
	python3 tests/quic_rebind.py "$(BUILD)/iroh-bend-quic-datagram" "$(UPSTREAM_QUIC_REBIND)"

check-quic-migration: $(BUILD)/iroh-bend-quic-migration
	@test -x "$(UPSTREAM_QUIC_MIGRATION)" || { echo 'Set UPSTREAM_QUIC_MIGRATION to the executable Iroh migration listener.' >&2; exit 2; }
	python3 -B tests/quic_migration.py "$(BUILD)/iroh-bend-quic-migration" "$(UPSTREAM_QUIC_MIGRATION)"

PICOQUIC_SOURCE ?=
PICOTLS_SOURCE ?=
PICOQUIC_BUILD ?=
PICOTLS_BUILD ?= $(PICOQUIC_BUILD)/_deps/picotls-build
UPSTREAM_QUIC_MULTIPATH ?=
UPSTREAM_QUIC_MULTIPATH_DIAL ?=
UPSTREAM_QUIC_MULTIPATH_SESSION ?=
UPSTREAM_ENDPOINT_MULTIPATH ?=
QAD_TEST_IP ?= 127.0.0.1
QAD_TEST_PORT ?=
QAD_TEST_TLS_NAME ?=
QAD_TEST_CA_BUNDLE ?=
PICOQUIC_FLAGS = -I"$(PICOQUIC_SOURCE)/picoquic" -I"$(PICOTLS_SOURCE)/include"
PICOQUIC_LIBS = -Wl,--wrap=ptls_handle_message -Wl,--wrap=ptls_get_cipher -Wl,--wrap=ptls_get_read_epoch \
	-Wl,--wrap=ptls_handshake_is_complete -Wl,--wrap=ptls_is_psk_handshake -Wl,--wrap=ptls_free \
	-Wl,--wrap=picoquic_decode_frames -Wl,--start-group "$(PICOQUIC_BUILD)/libpicoquic-core.a" \
	"$(PICOTLS_BUILD)/libpicotls-core.a" "$(PICOTLS_BUILD)/libpicotls-minicrypto.a" \
	"$(PICOTLS_BUILD)/libpicotls-openssl.a" -Wl,--end-group
MULTIPATH_CURL_CFLAGS ?= $$($(PKG_CONFIG) --cflags libcurl)
MULTIPATH_CURL_LIBS ?= $$($(PKG_CONFIG) --libs libcurl)

check-picoquic-multipath: check-quic-multipath

check-quic-multipath: $(BUILD)/iroh-bend-quic-multipath
	@test -x "$(UPSTREAM_QUIC_MULTIPATH)" || { echo 'Set UPSTREAM_QUIC_MULTIPATH to the Iroh multipath fixture.' >&2; exit 2; }
	sh tests/quic_multipath.sh "$(BUILD)/iroh-bend-quic-multipath" "$(UPSTREAM_QUIC_MULTIPATH)"

check-quic-multipath-listener: $(BUILD)/iroh-bend-quic-multipath-listener $(BUILD)/iroh-bend-quic-multipath
	@test -x "$(UPSTREAM_QUIC_MULTIPATH_DIAL)" || { echo 'Set UPSTREAM_QUIC_MULTIPATH_DIAL to the Iroh multipath dialer.' >&2; exit 2; }
	python3 -B tests/quic_multipath_listener.py "$(BUILD)/iroh-bend-quic-multipath-listener" \
		"$(UPSTREAM_QUIC_MULTIPATH_DIAL)" "$(BUILD)/iroh-bend-quic-multipath"

check-quic-multipath-session: $(BUILD)/iroh-bend-quic-multipath-session
	@test -x "$(UPSTREAM_QUIC_MULTIPATH_SESSION)" || { echo 'Set UPSTREAM_QUIC_MULTIPATH_SESSION to the Iroh session listener fixture.' >&2; exit 2; }
	sh tests/quic_multipath_session.sh "$<" "$(UPSTREAM_QUIC_MULTIPATH_SESSION)"

check-quic-multipath-early: $(BUILD)/iroh-bend-quic-multipath-session
	@test -x "$(UPSTREAM_QUIC_MULTIPATH_SESSION)" || { echo 'Set UPSTREAM_QUIC_MULTIPATH_SESSION to the Iroh listener fixture with early-data modes.' >&2; exit 2; }
	sh tests/quic_multipath_session.sh "$<" "$(UPSTREAM_QUIC_MULTIPATH_SESSION)" --early

check-quic-multipath-early-streams: $(BUILD)/iroh-bend-quic-multipath-session
	@test -x "$(UPSTREAM_QUIC_EARLY)" || { echo 'Set UPSTREAM_QUIC_EARLY to the Iroh early-stream and datagram fixture.' >&2; exit 2; }
	sh tests/quic_multipath_session.sh "$<" "$(UPSTREAM_QUIC_EARLY)" --early-streams

check-quic-multipath-early-uni: $(BUILD)/iroh-bend-quic-multipath-session
	@test -x "$(UPSTREAM_QUIC_EARLY)" || { echo 'Set UPSTREAM_QUIC_EARLY to the Iroh resumption fixture with unidirectional modes.' >&2; exit 2; }
	sh tests/quic_multipath_session.sh "$<" "$(UPSTREAM_QUIC_EARLY)" --early-uni

check-endpoint-multipath: $(BUILD)/iroh-bend-endpoint-multipath $(BUILD)/iroh-bend-endpoint-multipath-ticket
	@test -x "$(UPSTREAM_ENDPOINT_MULTIPATH)" || { echo 'Set UPSTREAM_ENDPOINT_MULTIPATH to the Iroh endpoint multipath fixture.' >&2; exit 2; }
	python3 -B tests/endpoint_multipath.py "$(BUILD)/iroh-bend-endpoint-multipath" \
		"$(UPSTREAM_ENDPOINT_MULTIPATH)" "$(if $(UPSTREAM_IROH_RELAY_URL),$(RELAY_URL))" "$(UPSTREAM_IROH_RELAY_URL)"
	python3 -B tests/endpoint_multipath.py "$(BUILD)/iroh-bend-endpoint-multipath-ticket" \
		"$(UPSTREAM_ENDPOINT_MULTIPATH)" "$(if $(UPSTREAM_IROH_RELAY_URL),$(RELAY_URL))" "$(UPSTREAM_IROH_RELAY_URL)" --tickets

check-endpoint-multipath-recovery: $(BUILD)/iroh-bend-endpoint-multipath-recovery
	@test -x "$(UPSTREAM_ENDPOINT_MULTIPATH)" || { echo 'Set UPSTREAM_ENDPOINT_MULTIPATH to the Iroh relay recovery fixture.' >&2; exit 2; }
	python3 -B tests/endpoint_multipath.py "$<" "$(UPSTREAM_ENDPOINT_MULTIPATH)" "$(RELAY_URL)" "$(UPSTREAM_IROH_RELAY_URL)" --recovery

check-endpoint-multipath-restore-direct: $(BUILD)/iroh-bend-endpoint-multipath-recovery
	@test -x "$(UPSTREAM_ENDPOINT_MULTIPATH)" || { echo 'Set UPSTREAM_ENDPOINT_MULTIPATH to the Iroh direct restoration fixture.' >&2; exit 2; }
	python3 -B tests/endpoint_multipath.py "$<" "$(UPSTREAM_ENDPOINT_MULTIPATH)" "$(RELAY_URL)" "$(UPSTREAM_IROH_RELAY_URL)" --restore-direct

check-endpoint-multipath-nat: $(BUILD)/iroh-bend-endpoint-multipath-nat
	@test -x "$(UPSTREAM_ENDPOINT_MULTIPATH)" || { echo 'Set UPSTREAM_ENDPOINT_MULTIPATH to the Iroh endpoint multipath fixture.' >&2; exit 2; }
	python3 -B tests/endpoint_multipath.py "$<" "$(UPSTREAM_ENDPOINT_MULTIPATH)" "$(RELAY_URL)" "$(UPSTREAM_IROH_RELAY_URL)" --relay-nat

check-endpoint-multipath-qad: $(BUILD)/iroh-bend-endpoint-multipath-nat
	@test -x "$(UPSTREAM_ENDPOINT_MULTIPATH)" || { echo 'Set UPSTREAM_ENDPOINT_MULTIPATH to the Iroh endpoint multipath fixture.' >&2; exit 2; }
	python3 -B tests/endpoint_multipath.py "$<" "$(UPSTREAM_ENDPOINT_MULTIPATH)" "$(RELAY_URL)" \
		"$(UPSTREAM_IROH_RELAY_URL)" --relay-qad "$(QAD_TEST_IP)" "$(QAD_TEST_PORT)" "$(QAD_TEST_TLS_NAME)" "$(QAD_TEST_CA_BUNDLE)"

.PHONY: check-endpoint-multipath-dual-stack
check-endpoint-multipath-dual-stack: $(BUILD)/iroh-bend-endpoint-multipath-dual-stack $(BUILD)/iroh-bend-endpoint-multipath
	python3 -B tests/endpoint_multipath_dual_stack.py "$<" "$(BUILD)/iroh-bend-endpoint-multipath" "$(RELAY_URL)"

.PHONY: check-endpoint-multipath-automatic-qad
check-endpoint-multipath-automatic-qad: $(BUILD)/iroh-bend-endpoint-multipath-dual-stack $(BUILD)/iroh-bend-endpoint-multipath
	python3 -B tests/endpoint_multipath_automatic_qad.py "$<" "$(BUILD)/iroh-bend-endpoint-multipath" "$(RELAY_URL)" "$(QAD_TEST_PORT)" "$(QAD_TEST_IP)"

.PHONY: check-endpoint-multipath-qad-refresh
check-endpoint-multipath-qad-refresh: $(BUILD)/iroh-bend-endpoint-multipath-dual-stack $(BUILD)/iroh-bend-endpoint-multipath
	python3 -B tests/endpoint_multipath_automatic_qad.py "$<" "$(BUILD)/iroh-bend-endpoint-multipath" "$(RELAY_URL)" "$(QAD_TEST_PORT)" "$(QAD_TEST_IP)" --refresh

.PHONY: check-endpoint-multipath-listener
check-endpoint-multipath-listener: $(BUILD)/iroh-bend-endpoint-multipath-listener
	@test -x "$(UPSTREAM_RELAY_INBOUND)" || { echo 'Set UPSTREAM_RELAY_INBOUND to the Iroh dialer with direct-relay mode.' >&2; exit 2; }
	python3 -B tests/relay_quic_inbound.py --direct-relay "$<" "$(UPSTREAM_RELAY_INBOUND)" "$(RELAY_URL)" "$(UPSTREAM_IROH_RELAY_URL)"

.PHONY: check-endpoint-multipath-inbound-nat
UPSTREAM_INBOUND_NAT ?=
check-endpoint-multipath-inbound-nat: $(BUILD)/iroh-bend-endpoint-multipath-inbound-nat
	@test -x "$(UPSTREAM_INBOUND_NAT)" || { echo 'Set UPSTREAM_INBOUND_NAT to the Iroh inbound NAT fixture.' >&2; exit 2; }
	python3 -B tests/endpoint_multipath_inbound_nat.py "$<" "$(UPSTREAM_INBOUND_NAT)" "$(RELAY_URL)" "$(UPSTREAM_IROH_RELAY_URL)"

.PHONY: check-endpoint-multipath-inbound-qad
check-endpoint-multipath-inbound-qad: $(BUILD)/iroh-bend-endpoint-multipath-inbound-nat
	test -n "$(RELAY_URL)" -a -n "$(UPSTREAM_IROH_RELAY_URL)" -a -x "$(UPSTREAM_INBOUND_NAT)"
	python3 -B tests/endpoint_multipath_inbound_nat.py "$<" "$(UPSTREAM_INBOUND_NAT)" "$(RELAY_URL)" "$(UPSTREAM_IROH_RELAY_URL)" observed

.PHONY: check-endpoint-multipath-inbound-failback
UPSTREAM_INBOUND_FAILBACK_RELAY ?=
INBOUND_FAILBACK_FAULT ?= drop
INBOUND_FAILBACK_SCHEME ?= ws
INBOUND_FAILBACK_RELAY_CONFIG ?=
check-endpoint-multipath-inbound-failback: $(BUILD)/iroh-bend-endpoint-multipath-inbound-nat
	@test -x "$(UPSTREAM_INBOUND_NAT)" && test -x "$(UPSTREAM_INBOUND_FAILBACK_RELAY)" || { echo 'Set UPSTREAM_INBOUND_NAT and UPSTREAM_INBOUND_FAILBACK_RELAY to the Iroh fixtures.' >&2; exit 2; }
	python3 -B tests/endpoint_multipath_inbound_failback.py "$<" "$(UPSTREAM_INBOUND_NAT)" "$(UPSTREAM_INBOUND_FAILBACK_RELAY)" "$(INBOUND_FAILBACK_SCHEME)" "$(INBOUND_FAILBACK_RELAY_CONFIG)" "$(INBOUND_FAILBACK_FAULT)"

$(BUILD)/endpoint-multipath-inbound-nat.c: tests/endpoint_multipath_inbound_nat.bend tests/quic_multipath_listener.bend
$(BUILD)/endpoint-multipath-listener.c: tests/endpoint_multipath_listener.bend tests/quic_multipath_listener.bend
$(BUILD)/endpoint-multipath-dual-stack.c: tests/endpoint_multipath_dual_stack.bend tests/quic_multipath_listener.bend
$(BUILD)/endpoint-multipath-nat.c: tests/endpoint_multipath_nat.bend
$(BUILD)/endpoint-multipath-options.c: tests/endpoint_multipath_options.bend tests/endpoint_validation.bend
$(BUILD)/endpoint-multipath-ticket.c: tests/endpoint_multipath_ticket.bend
$(BUILD)/endpoint-multipath.c: tests/endpoint_multipath.bend
$(BUILD)/endpoint-multipath-recovery.c: tests/endpoint_multipath_recovery.bend
$(BUILD)/endpoint-multipath.c $(BUILD)/endpoint-multipath-ticket.c $(BUILD)/endpoint-multipath-options.c $(BUILD)/endpoint-multipath-recovery.c $(BUILD)/endpoint-multipath-nat.c $(BUILD)/endpoint-multipath-dual-stack.c $(BUILD)/endpoint-multipath-listener.c $(BUILD)/endpoint-multipath-inbound-nat.c: $(BUILD)/%.c: tests/quic_multipath_bend.bend src/endpoint_multipath.bend src/quic_multipath.bend src/quic_stream.bend src/quic_nat.bend src/quic_nat_state.bend src/quic_nat_send.bend src/quic_nat_retry.bend src/quic_multipath_nat.bend $(RELAY_QUIC_SOURCES) $(addprefix src/,$(addsuffix .nelua,$(RELAY_QUIC_EFFECTS) quic_multipath)) tools/nelua-effect.sh
	mkdir -p "$(@:.c=-stage)/src" "$(@:.c=-stage)/tests"
	cp $(RELAY_QUIC_SOURCES) src/endpoint_multipath.bend src/quic_multipath.bend src/quic_nat_state.bend src/quic_nat_send.bend src/quic_nat_retry.bend src/quic_multipath_nat.bend "$(@:.c=-stage)/src/"
	cp "tests/$(subst -,_,$*).bend" tests/quic_multipath_bend.bend tests/quic_multipath_listener.bend $(filter tests/endpoint_validation.bend,$^) "$(@:.c=-stage)/tests/"
	for native in $(RELAY_QUIC_EFFECTS) quic_multipath; do \
		tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" "src/$$native.nelua" \
			"$(abspath $(@:.c=-stage))/src/$$native.c" || exit; \
	done
	cd "$(@:.c=-stage)" && BEND_NO_TELEMETRY=1 $(BEND) "tests/$(subst -,_,$*).bend" -o "$(abspath $@)"

# Build the endpoint integration fixture without compiler optimizations.
$(BUILD)/iroh-bend-endpoint-multipath $(BUILD)/iroh-bend-endpoint-multipath-ticket $(BUILD)/iroh-bend-endpoint-multipath-options $(BUILD)/iroh-bend-endpoint-multipath-recovery $(BUILD)/iroh-bend-endpoint-multipath-nat $(BUILD)/iroh-bend-endpoint-multipath-dual-stack $(BUILD)/iroh-bend-endpoint-multipath-listener $(BUILD)/iroh-bend-endpoint-multipath-inbound-nat: $(BUILD)/iroh-bend-%: $(BUILD)/%.c
	$(CLANG) -std=gnu11 $(PICOQUIC_FLAGS) $(MULTIPATH_CURL_CFLAGS) \
		$$($(PKG_CONFIG) --cflags openssl) "$<" -o "$@" $(PICOQUIC_LIBS) \
		-pthread $(MULTIPATH_CURL_LIBS) $$($(PKG_CONFIG) --libs openssl)

$(BUILD)/quic-multipath.c: tests/quic_multipath_bend.bend src/quic_multipath.bend src/quic_stream.bend src/quic_nat.bend src/quic_nat_state.bend src/quic_nat_send.bend src/quic_nat_retry.bend src/quic_multipath_nat.bend src/quic_multipath.nelua tools/nelua-effect.sh
	mkdir -p "$(BUILD)/quic-multipath-stage/src" "$(BUILD)/quic-multipath-stage/tests"
	cp src/quic_multipath.bend src/quic_stream.bend src/quic_nat.bend src/quic_nat_state.bend src/quic_nat_send.bend src/quic_nat_retry.bend src/quic_multipath_nat.bend "$(BUILD)/quic-multipath-stage/src/"
	cp tests/quic_multipath_bend.bend "$(BUILD)/quic-multipath-stage/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/quic_multipath.nelua \
		"$(abspath $(BUILD)/quic-multipath-stage/src/quic_multipath.c)"
	cd "$(BUILD)/quic-multipath-stage" && BEND_NO_TELEMETRY=1 $(BEND) tests/quic_multipath_bend.bend -o "$(abspath $@)"

$(BUILD)/quic-multipath-listener.c: tests/quic_multipath_listener.bend tests/quic_multipath_bend.bend src/quic_multipath.bend src/quic_stream.bend src/quic_nat.bend src/quic_nat_state.bend src/quic_nat_send.bend src/quic_nat_retry.bend src/quic_multipath_nat.bend src/quic_multipath.nelua tools/nelua-effect.sh
	mkdir -p "$(BUILD)/quic-multipath-listener-stage/src" "$(BUILD)/quic-multipath-listener-stage/tests"
	cp src/quic_multipath.bend src/quic_stream.bend src/quic_nat.bend src/quic_nat_state.bend src/quic_nat_send.bend src/quic_nat_retry.bend src/quic_multipath_nat.bend "$(BUILD)/quic-multipath-listener-stage/src/"
	cp tests/quic_multipath_listener.bend tests/quic_multipath_bend.bend "$(BUILD)/quic-multipath-listener-stage/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/quic_multipath.nelua \
		"$(abspath $(BUILD)/quic-multipath-listener-stage/src/quic_multipath.c)"
	cd "$(BUILD)/quic-multipath-listener-stage" && BEND_NO_TELEMETRY=1 $(BEND) tests/quic_multipath_listener.bend -o "$(abspath $@)"

.PHONY: check-quic-multipath-early-listener
check-quic-multipath-early-listener: $(BUILD)/iroh-bend-quic-multipath-early-listener
	@test -x "$(UPSTREAM_QUIC_EARLY_DIAL)" || { echo 'Set UPSTREAM_QUIC_EARLY_DIAL to the Iroh early-data dialer.' >&2; exit 2; }
	python3 -B tests/quic_multipath_early_listener.py "$<" "$(UPSTREAM_QUIC_EARLY_DIAL)"

$(BUILD)/quic-multipath-early-listener.c: tests/quic_multipath_early_listener.bend tests/quic_multipath_listener.bend tests/quic_multipath_bend.bend src/quic_multipath.bend src/quic_stream.bend src/quic_nat.bend src/quic_nat_state.bend src/quic_nat_send.bend src/quic_nat_retry.bend src/quic_multipath_nat.bend src/quic_multipath.nelua tools/nelua-effect.sh
	mkdir -p "$(@:.c=-stage)/src" "$(@:.c=-stage)/tests"
	cp src/quic_multipath.bend src/quic_stream.bend src/quic_nat.bend src/quic_nat_state.bend src/quic_nat_send.bend src/quic_nat_retry.bend src/quic_multipath_nat.bend "$(@:.c=-stage)/src/"
	cp tests/quic_multipath_early_listener.bend tests/quic_multipath_listener.bend tests/quic_multipath_bend.bend "$(@:.c=-stage)/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/quic_multipath.nelua \
		"$(abspath $(@:.c=-stage))/src/quic_multipath.c"
	cd "$(@:.c=-stage)" && BEND_NO_TELEMETRY=1 $(BEND) tests/quic_multipath_early_listener.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-quic-multipath-early-listener: $(BUILD)/quic-multipath-early-listener.c

.PHONY: check-relay-qad
UPSTREAM_QAD_CLIENT ?=
QAD_SERVER_CERT ?=
QAD_SERVER_KEY ?=
QAD_TEST_CA_DER ?=

check-relay-qad: $(BUILD)/iroh-bend-relay-qad
	@test -x "$(UPSTREAM_QAD_CLIENT)" || { echo 'Set UPSTREAM_QAD_CLIENT to the Iroh relay address discovery client.' >&2; exit 2; }
	python3 -B tests/relay_qad.py "$<" "$(UPSTREAM_QAD_CLIENT)" "$(QAD_SERVER_CERT)" "$(QAD_SERVER_KEY)" \
		"$(QAD_TEST_TLS_NAME)" "$(QAD_TEST_CA_DER)"

$(BUILD)/relay-qad.c: tests/relay_qad.bend src/quic_multipath.bend src/quic_stream.bend src/quic_nat.bend src/quic_multipath.nelua tools/nelua-effect.sh
	mkdir -p "$(@:.c=-stage)/src" "$(@:.c=-stage)/tests"
	cp src/quic_multipath.bend src/quic_stream.bend src/quic_nat.bend "$(@:.c=-stage)/src/"
	cp tests/relay_qad.bend "$(@:.c=-stage)/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/quic_multipath.nelua \
		"$(abspath $(@:.c=-stage))/src/quic_multipath.c"
	cd "$(@:.c=-stage)" && BEND_NO_TELEMETRY=1 $(BEND) tests/relay_qad.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-relay-qad: $(BUILD)/relay-qad.c
$(BUILD)/iroh-bend-quic-multipath: $(BUILD)/quic-multipath.c
$(BUILD)/iroh-bend-quic-multipath-listener: $(BUILD)/quic-multipath-listener.c
$(BUILD)/iroh-bend-quic-multipath-session: $(BUILD)/quic-multipath-session.c

$(BUILD)/quic-multipath-session.c: tests/quic_multipath_session.bend src/quic_multipath.bend src/quic_stream.bend src/quic_nat.bend src/quic_multipath.nelua tools/nelua-effect.sh
	mkdir -p "$(@:.c=-stage)/src" "$(@:.c=-stage)/tests"
	cp src/quic_multipath.bend src/quic_stream.bend src/quic_nat.bend "$(@:.c=-stage)/src/"
	cp tests/quic_multipath_session.bend "$(@:.c=-stage)/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/quic_multipath.nelua \
		"$(abspath $(@:.c=-stage))/src/quic_multipath.c"
	cd "$(@:.c=-stage)" && BEND_NO_TELEMETRY=1 $(BEND) tests/quic_multipath_session.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-quic-multipath-cancel $(BUILD)/iroh-bend-quic-multipath $(BUILD)/iroh-bend-quic-multipath-listener $(BUILD)/iroh-bend-quic-multipath-session $(BUILD)/iroh-bend-quic-multipath-early-listener $(BUILD)/iroh-bend-relay-qad:
	@test -f "$(PICOQUIC_SOURCE)/picoquic/picoquic.h" && test -f "$(PICOTLS_SOURCE)/include/picotls.h" \
		&& test -f "$(PICOQUIC_BUILD)/libpicoquic-core.a" && test -f "$(PICOTLS_BUILD)/libpicotls-core.a" \
		|| { echo 'Set PICOQUIC_SOURCE, PICOTLS_SOURCE, PICOQUIC_BUILD, and PICOTLS_BUILD.' >&2; exit 2; }
	$(CLANG) -std=gnu11 -O2 $(PICOQUIC_FLAGS) \
		$$($(PKG_CONFIG) --cflags openssl) "$<" -o "$@" $(PICOQUIC_LIBS) \
		-pthread $$($(PKG_CONFIG) --libs openssl)

.PHONY: check-quic-stream-cancel check-quic-datagram-cancel check-quic-multipath-cancel
UPSTREAM_QUIC_STREAM_CANCEL ?=
check-quic-stream-cancel: check-quic-datagram-cancel check-quic-multipath-cancel

check-quic-datagram-cancel check-quic-multipath-cancel: check-%: $(BUILD)/iroh-bend-%
	@test -x "$(UPSTREAM_QUIC_STREAM_CANCEL)" || { echo 'Set UPSTREAM_QUIC_STREAM_CANCEL to the Iroh stream cancellation fixture.' >&2; exit 2; }
	python3 -B tests/quic_stream_cancel.py "$<" "$(UPSTREAM_QUIC_STREAM_CANCEL)"

.PHONY: check-quic-stream-finish check-quic-datagram-finish check-quic-multipath-finish
UPSTREAM_QUIC_STREAM_FINISH ?=
check-quic-stream-finish: check-quic-datagram-finish check-quic-multipath-finish

.PHONY: check-quic-stream-finish-control
check-quic-stream-finish-control:
	@test -x "$(UPSTREAM_QUIC_STREAM_FINISH)" || { echo 'Set UPSTREAM_QUIC_STREAM_FINISH to the Iroh FIN acknowledgement fixture.' >&2; exit 2; }
	sh tests/quic_stream_finish_control.sh "$(UPSTREAM_QUIC_STREAM_FINISH)"

check-quic-datagram-finish check-quic-multipath-finish: check-%-finish: $(BUILD)/iroh-bend-%-cancel
	@test -x "$(UPSTREAM_QUIC_STREAM_FINISH)" || { echo 'Set UPSTREAM_QUIC_STREAM_FINISH to the Iroh FIN acknowledgement fixture.' >&2; exit 2; }
	python3 -B tests/quic_stream_finish.py "$<" "$(UPSTREAM_QUIC_STREAM_FINISH)"

.PHONY: check-quic-stream-reset-ack check-quic-datagram-reset-ack check-quic-multipath-reset-ack check-quic-stream-reset-ack-control
UPSTREAM_QUIC_STREAM_RESET_ACK ?=
check-quic-stream-reset-ack: check-quic-datagram-reset-ack check-quic-multipath-reset-ack

check-quic-datagram-reset-ack check-quic-multipath-reset-ack: check-%-reset-ack: $(BUILD)/iroh-bend-%-cancel
	@test -x "$(UPSTREAM_QUIC_STREAM_RESET_ACK)" || { echo 'Set UPSTREAM_QUIC_STREAM_RESET_ACK to the Iroh reset acknowledgement fixture.' >&2; exit 2; }
	python3 -B tests/quic_stream_finish.py "$<" "$(UPSTREAM_QUIC_STREAM_RESET_ACK)" reset-ack

check-quic-stream-reset-ack-control:
	@test -x "$(UPSTREAM_QUIC_STREAM_RESET_ACK)" || { echo 'Set UPSTREAM_QUIC_STREAM_RESET_ACK to the Iroh reset acknowledgement fixture.' >&2; exit 2; }
	sh tests/quic_stream_finish_control.sh "$(UPSTREAM_QUIC_STREAM_RESET_ACK)" reset-ack

.PHONY: check-quic-stream-reset-ack-return check-quic-datagram-reset-ack-return check-quic-multipath-reset-ack-return check-quic-stream-reset-ack-return-control
check-quic-stream-reset-ack-return: check-quic-datagram-reset-ack-return check-quic-multipath-reset-ack-return

check-quic-datagram-reset-ack-return check-quic-multipath-reset-ack-return: check-%-reset-ack-return: $(BUILD)/iroh-bend-%-cancel
	@test -x "$(UPSTREAM_QUIC_STREAM_RESET_ACK)" || { echo 'Set UPSTREAM_QUIC_STREAM_RESET_ACK to the Iroh reset acknowledgement fixture.' >&2; exit 2; }
	python3 -B tests/quic_stream_finish.py "$<" "$(UPSTREAM_QUIC_STREAM_RESET_ACK)" reset-ack-return

check-quic-stream-reset-ack-return-control:
	@test -x "$(UPSTREAM_QUIC_STREAM_RESET_ACK)" || { echo 'Set UPSTREAM_QUIC_STREAM_RESET_ACK to the Iroh reset acknowledgement fixture.' >&2; exit 2; }
	sh tests/quic_stream_finish_control.sh "$(UPSTREAM_QUIC_STREAM_RESET_ACK)" reset-ack-return

$(BUILD)/quic-datagram-cancel.c: tests/quic_datagram_cancel.bend tests/quic_datagram.bend src/quic_datagram.bend src/quic_datagram.nelua
$(BUILD)/quic-multipath-cancel.c: tests/quic_multipath_cancel.bend tests/quic_multipath_bend.bend tests/quic_multipath_listener.bend src/quic_multipath.bend src/quic_multipath.nelua src/quic_nat_state.bend src/quic_nat_send.bend src/quic_nat_retry.bend src/quic_multipath_nat.bend
$(BUILD)/quic-datagram-cancel.c $(BUILD)/quic-multipath-cancel.c: $(BUILD)/%-cancel.c: tests/quic_stream_cancel.bend src/quic_stream.bend src/quic_nat.bend tools/nelua-effect.sh
	mkdir -p "$(@:.c=-stage)/src" "$(@:.c=-stage)/tests"
	cp $(filter src/%.bend,$^) "$(@:.c=-stage)/src/"
	cp $(filter tests/%.bend,$^) "$(@:.c=-stage)/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" $(filter %.nelua,$^) "$(abspath $(@:.c=-stage))/src/$(subst -,_,$*).c"
	cd "$(@:.c=-stage)" && BEND_NO_TELEMETRY=1 $(BEND) tests/$(subst -,_,$*)_cancel.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-quic-datagram-cancel: $(BUILD)/quic-datagram-cancel.c
$(BUILD)/iroh-bend-quic-multipath-cancel: $(BUILD)/quic-multipath-cancel.c

$(BUILD)/quic-datagram.c: tests/quic_datagram.bend src/quic_datagram.bend src/quic_stream.bend src/quic_nat.bend src/quic_datagram.nelua tools/nelua-effect.sh
	mkdir -p "$(BUILD)/quic-datagram-stage/src" "$(BUILD)/quic-datagram-stage/tests"
	cp src/quic_datagram.bend src/quic_stream.bend src/quic_nat.bend "$(BUILD)/quic-datagram-stage/src/"
	cp tests/quic_datagram.bend "$(BUILD)/quic-datagram-stage/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/quic_datagram.nelua \
		"$(abspath $(BUILD)/quic-datagram-stage/src/quic_datagram.c)"
	cd "$(BUILD)/quic-datagram-stage" && BEND_NO_TELEMETRY=1 $(BEND) tests/quic_datagram.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-quic-datagram: $(BUILD)/quic-datagram.c
$(BUILD)/iroh-bend-quic-datagram $(BUILD)/iroh-bend-quic-datagram-cancel:
	$(CLANG) -std=c11 -O2 $$($(PKG_CONFIG) --cflags $(DATAGRAM_LIBS)) $< \
		-o $@ -pthread -lm $$($(PKG_CONFIG) --libs $(DATAGRAM_LIBS))

$(BUILD)/quic-early-listener.c: tests/quic_early_listener.bend tests/quic_datagram.bend src/quic_datagram.bend src/quic_stream.bend src/quic_nat.bend src/quic_datagram.nelua tools/nelua-effect.sh
	mkdir -p "$(BUILD)/quic-early-listener-stage/src" "$(BUILD)/quic-early-listener-stage/tests"
	cp src/quic_datagram.bend src/quic_stream.bend src/quic_nat.bend "$(BUILD)/quic-early-listener-stage/src/"
	cp tests/quic_early_listener.bend tests/quic_datagram.bend "$(BUILD)/quic-early-listener-stage/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/quic_datagram.nelua \
		"$(abspath $(BUILD)/quic-early-listener-stage/src/quic_datagram.c)"
	cd "$(BUILD)/quic-early-listener-stage" && BEND_NO_TELEMETRY=1 $(BEND) tests/quic_early_listener.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-quic-early-listener: $(BUILD)/quic-early-listener.c
	$(CLANG) -std=c11 -O2 $$($(PKG_CONFIG) --cflags $(DATAGRAM_LIBS)) $< \
		-o $@ -pthread -lm $$($(PKG_CONFIG) --libs $(DATAGRAM_LIBS))

$(BUILD)/quic-migration.c: tests/quic_migration.bend tests/quic_datagram.bend src/quic_datagram.bend src/quic_stream.bend src/quic_nat.bend src/quic_datagram.nelua tools/nelua-effect.sh
	mkdir -p "$(BUILD)/quic-migration-stage/src" "$(BUILD)/quic-migration-stage/tests"
	cp src/quic_datagram.bend src/quic_stream.bend src/quic_nat.bend "$(BUILD)/quic-migration-stage/src/"
	cp tests/quic_migration.bend tests/quic_datagram.bend "$(BUILD)/quic-migration-stage/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/quic_datagram.nelua \
		"$(abspath $(BUILD)/quic-migration-stage/src/quic_datagram.c)"
	cd "$(BUILD)/quic-migration-stage" && BEND_NO_TELEMETRY=1 $(BEND) tests/quic_migration.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-quic-migration: $(BUILD)/quic-migration.c
	$(CLANG) -std=c11 -O2 $$($(PKG_CONFIG) --cflags $(DATAGRAM_LIBS)) $< \
		-o $@ -pthread -lm $$($(PKG_CONFIG) --libs $(DATAGRAM_LIBS))
