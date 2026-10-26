# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: MIT

# Sightread testbed: a fixture registry that plays WordPress.org,
# Packagist, GitHub, npm and OSV on loopback, a canary every bad payload
# targets, a webhook receiver, probes and a sealed Docker WordPress for
# --soundcheck. See README.md for the ports and the scenarios.
#
# Needs Go; Docker with Compose v2 only for up-wp (e15 and the Soundcheck
# column). Run from this folder or as make -C testbed <target>.

GO       ?= $(shell command -v go 2>/dev/null || echo /usr/local/go/bin/go)
COMPOSE  := docker compose -f docker-compose.yml
BIN      := state/bin
PIDS     := state/pids
WORK     := bench/work
# The benchmark's flags, as make bench BENCH="-only b01,env -tools all".
BENCH    ?=
# Which compared tools the benchmark judges (see bench/tools.go):
# auto (npm audit, composer audit, GuardDog when installed), all (adds
# Soundcheck, which needs up-wp and takes several minutes), none.
TOOLS    ?= auto

export GOWORK := off

.PHONY: up up-wp down test-bench bench reproduce corpus toggle status good bad wp logs

up: ## start the registry, canary and webhook on 127.0.0.1 in the background
	@mkdir -p $(BIN) $(PIDS)
	cd .. && $(GO) build -o testbed/$(BIN)/registry ./testbed/registry/cmd/registry
	cd .. && $(GO) build -o testbed/$(BIN)/canary ./testbed/canary/cmd/canary
	cd .. && $(GO) build -o testbed/$(BIN)/webhook ./testbed/webhook/cmd/webhook
	@rm -f state/ca.pem
	@for svc in registry canary webhook; do \
		if [ -f $(PIDS)/$$svc ] && kill -0 "$$(cat $(PIDS)/$$svc)" 2>/dev/null; then echo "$$svc already up"; continue; fi; \
		case $$svc in \
		registry) $(BIN)/registry -packages packages -state state > state/$$svc.out 2>&1 & ;; \
		*) $(BIN)/$$svc -state state > state/$$svc.out 2>&1 & ;; \
		esac; \
		echo $$! > $(PIDS)/$$svc; \
	done
	@for i in $$(seq 1 50); do [ -f state/ca.pem ] && break; sleep 0.2; done
	@echo "registry: https://127.0.0.1:18900-18904 and 18908 (CA in state/ca.pem)"
	@echo "canary:   127.0.0.1:18905    webhook: http://127.0.0.1:18906"
	@echo "point Sightread at it: see README.md, Run Sightread by hand"

up-wp: ## start the sealed Docker WordPress on 127.0.0.1:18907 and seed it (e15)
	@mkdir -p state/wp-share
	$(COMPOSE) up -d --build --wait
	$(COMPOSE) exec -T -u www-data wp sh /seed/seed.sh
	@echo "WordPress: http://127.0.0.1:18907/  (admin/admin); WP-CLI: bin/wp"

down: ## stop everything up and up-wp started (the WordPress volume is removed)
	@for f in $(PIDS)/*; do [ -f "$$f" ] || continue; kill "$$(cat "$$f")" 2>/dev/null || true; rm -f "$$f"; done
	-$(COMPOSE) down -v --remove-orphans 2>/dev/null

test-bench: ## run the tagged bench tests (canary, egress, sealed Docker check, p01-large); up-wp first for the Docker parts
	cd .. && $(GO) test -tags testbed -count=1 -timeout 60m ./testbed/bench/

bench: ## run every scenario; writes ../docs/benchmark.md and bench/work/results.json (stop make up first)
	cd .. && $(GO) run -tags testbed ./testbed/bench -tools "$(TOOLS)" $(BENCH)

reproduce: ## run the benchmark twice and fail if any outcome differs
	cd .. && $(GO) run -tags testbed ./testbed/bench -tools "$(TOOLS)" -work testbed/$(WORK)/first -results testbed/$(WORK)/first.json -out testbed/$(WORK)/first.md $(BENCH) || true
	cd .. && $(GO) run -tags testbed ./testbed/bench -tools "$(TOOLS)" -work testbed/$(WORK)/second -results testbed/$(WORK)/second.json -out testbed/$(WORK)/second.md $(BENCH) || true
	cd .. && $(GO) run -tags testbed ./testbed/bench -diff testbed/$(WORK)/first.json testbed/$(WORK)/second.json

corpus: ## owner only, needs network: fetch the pinned real releases and write the real-release section (PIN=1 the first time)
	cd .. && $(GO) run -tags corpus ./testbed/corpus fetch $(if $(PIN),-pin)
	cd .. && $(GO) run -tags corpus ./testbed/corpus run

toggle: ## set one scenario's state: make toggle ID=b01 STATE=good
	./toggle.sh $(ID) $(STATE)

good: ## withhold every candidate, or one: make good ID=b01
	./toggle.sh $(or $(ID),all) good

bad: ## publish every candidate, or one: make bad ID=b01
	./toggle.sh $(or $(ID),all) bad

status: ## list the scenarios whose candidate is withheld
	@./toggle.sh status

wp: ## run WP-CLI in the Docker WordPress: make wp ARGS="plugin list"
	bin/wp $(ARGS)

logs: ## follow the Docker WordPress logs
	$(COMPOSE) logs -f wp gate
