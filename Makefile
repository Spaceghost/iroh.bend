BEND ?= bend
BUILD ?= build

.PHONY: check check-gpu check-dns-tcp

check: $(BUILD)/iroh-bend-check $(BUILD)/iroh-bend-handshake $(BUILD)/iroh-bend-discovery
	$(BUILD)/iroh-bend-check
	$(BUILD)/iroh-bend-handshake
	$(BUILD)/iroh-bend-discovery

$(BUILD)/iroh-bend-check: tests/check.bend src/relay.bend src/base32.bend
	mkdir -p $(BUILD)
	BEND_NO_TELEMETRY=1 $(BEND) tests/check.bend -o $@

$(BUILD)/iroh-bend-handshake: tests/handshake.bend src/handshake.bend src/relay_challenge.bend src/relay.bend
	mkdir -p $(BUILD)
	BEND_NO_TELEMETRY=1 $(BEND) tests/handshake.bend -o $@

$(BUILD)/iroh-bend-discovery: tests/discovery.bend src/discovery.bend src/relay.bend
	mkdir -p $(BUILD)
	BEND_NO_TELEMETRY=1 $(BEND) tests/discovery.bend -o $@

check-dns-tcp: $(BUILD)/iroh-bend-discovery
	python3 tests/discovery_tcp.py $(BUILD)/iroh-bend-discovery

check-gpu: $(BUILD)/iroh-bend-gpu
	BENDRTS= $(BUILD)/iroh-bend-gpu +RTS --gpu 1GB

$(BUILD)/iroh-bend-gpu: tests/gpu.bend src/relay.bend
	mkdir -p $(BUILD)
	BEND_NO_TELEMETRY=1 $(BEND) tests/gpu.bend -o $@

NELUA ?= nelua
CLANG ?= clang
PKG_CONFIG ?= pkg-config
UPSTREAM ?= iroh-upstream-peer

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

$(BUILD)/relay-auth.c: tests/relay_auth.bend $(AUTH_SOURCES) src/ed25519.nelua tools/nelua-effect.sh
	mkdir -p "$(BUILD)/stage/src" "$(BUILD)/stage/tests"
	cp $(AUTH_SOURCES) "$(BUILD)/stage/src/"
	cp tests/relay_auth.bend "$(BUILD)/stage/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/ed25519.nelua \
		"$(abspath $(BUILD)/stage/src/ed25519.c)"
	cd "$(BUILD)/stage" && BEND_NO_TELEMETRY=1 $(BEND) tests/relay_auth.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-relay-auth: $(BUILD)/relay-auth.c
	$(CLANG) -std=c11 -O2 $$($(PKG_CONFIG) --cflags openssl) $< \
		-o $@ -pthread -lm $$($(PKG_CONFIG) --libs openssl)

.PHONY: check-relay-live
RELAY_URL ?= ws://127.0.0.1:3340/relay
RELAY_SOURCES = $(AUTH_SOURCES) src/relay_client.bend src/relay_socket.bend

check-relay-live: $(BUILD)/iroh-bend-relay-live
	$(BUILD)/iroh-bend-relay-live "$(RELAY_URL)"
	$(BUILD)/iroh-bend-relay-live "$(RELAY_URL)" v1

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

.PHONY: check-pkarr-http check-pkarr-http-live
PKARR_URL ?=
PKARR_HTTP_SOURCES = $(PKARR_SOURCES) src/pkarr_http.bend

check-pkarr-http: $(BUILD)/iroh-bend-pkarr-http
	python3 tests/pkarr_http.py "$(BUILD)/iroh-bend-pkarr-http"

check-pkarr-http-live: $(BUILD)/iroh-bend-pkarr-http
	test -n "$(PKARR_URL)"
	"$(BUILD)/iroh-bend-pkarr-http" publish "$(PKARR_URL)"
	"$(BUILD)/iroh-bend-pkarr-http" resolve "$(PKARR_URL)"

$(BUILD)/pkarr-http.c: tests/pkarr_http.bend tests/pkarr.bend $(PKARR_HTTP_SOURCES) src/pkarr_http.nelua src/ed25519.nelua tools/nelua-effect.sh
	mkdir -p "$(BUILD)/pkarr-http-stage/src" "$(BUILD)/pkarr-http-stage/tests"
	cp $(PKARR_HTTP_SOURCES) "$(BUILD)/pkarr-http-stage/src/"
	cp tests/pkarr_http.bend tests/pkarr.bend "$(BUILD)/pkarr-http-stage/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/ed25519.nelua \
		"$(abspath $(BUILD)/pkarr-http-stage/src/ed25519.c)"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/pkarr_http.nelua \
		"$(abspath $(BUILD)/pkarr-http-stage/src/pkarr_http.c)"
	cd "$(BUILD)/pkarr-http-stage" && BEND_NO_TELEMETRY=1 $(BEND) tests/pkarr_http.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-pkarr-http: $(BUILD)/pkarr-http.c
	$(CLANG) -std=c11 -O2 $$($(PKG_CONFIG) --cflags openssl libcurl) $< \
		-o $@ -pthread -lm $$($(PKG_CONFIG) --libs openssl libcurl)

.PHONY: check-pkarr-dht
PKARR_DHT_SOURCES = $(PKARR_SOURCES) src/bencode.bend src/krpc.bend src/pkarr_dht.bend src/pkarr_dht_search.bend

check-pkarr-dht: $(BUILD)/iroh-bend-pkarr-dht
	"$(BUILD)/iroh-bend-pkarr-dht"
	python3 tests/pkarr_dht_routing.py "$(BUILD)/iroh-bend-pkarr-dht"

$(BUILD)/pkarr-dht.c: tests/pkarr_dht.bend tests/pkarr.bend $(PKARR_DHT_SOURCES) src/ed25519.nelua tools/nelua-effect.sh
	mkdir -p "$(BUILD)/pkarr-dht-stage/src" "$(BUILD)/pkarr-dht-stage/tests"
	cp $(PKARR_DHT_SOURCES) "$(BUILD)/pkarr-dht-stage/src/"
	cp tests/pkarr_dht.bend tests/pkarr.bend "$(BUILD)/pkarr-dht-stage/tests/"
	tools/nelua-effect.sh "$(NELUA)" "$(abspath $(BUILD)/nelua)" src/ed25519.nelua \
		"$(abspath $(BUILD)/pkarr-dht-stage/src/ed25519.c)"
	cd "$(BUILD)/pkarr-dht-stage" && BEND_NO_TELEMETRY=1 $(BEND) tests/pkarr_dht.bend -o "$(abspath $@)"

$(BUILD)/iroh-bend-pkarr-dht: $(BUILD)/pkarr-dht.c
	$(CLANG) -std=c11 -O2 $$($(PKG_CONFIG) --cflags openssl) $< \
		-o $@ -pthread -lm $$($(PKG_CONFIG) --libs openssl)
