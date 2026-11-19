BEND ?= bend
BUILD ?= build

.PHONY: check check-gpu

check: $(BUILD)/iroh-bend-check
	$(BUILD)/iroh-bend-check

$(BUILD)/iroh-bend-check: tests/check.bend src/relay.bend src/base32.bend
	mkdir -p $(BUILD)
	BEND_NO_TELEMETRY=1 $(BEND) tests/check.bend -o $@

check-gpu: $(BUILD)/iroh-bend-gpu
	BENDRTS= $(BUILD)/iroh-bend-gpu +RTS --gpu 1GB

$(BUILD)/iroh-bend-gpu: tests/gpu.bend src/relay.bend
	mkdir -p $(BUILD)
	BEND_NO_TELEMETRY=1 $(BEND) tests/gpu.bend -o $@

CLANG ?= clang
PKG_CONFIG ?= pkg-config
UPSTREAM ?= iroh-upstream-peer

.PHONY: check-direct

check-direct: $(BUILD)/iroh-bend-direct
	tests/direct.sh $(BUILD)/iroh-bend-direct "$(UPSTREAM)"

$(BUILD)/direct.c: tests/direct.bend src/direct.bend src/direct.c
	mkdir -p $(BUILD)
	BEND_NO_TELEMETRY=1 $(BEND) tests/direct.bend -o $@

$(BUILD)/iroh-bend-direct: $(BUILD)/direct.c
	$(CLANG) -std=c11 -O2 $$($(PKG_CONFIG) --cflags openssl) $< 		-o $@ -pthread -lm $$($(PKG_CONFIG) --libs openssl)
