GOLANGCI := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0

# The workspace go.work one folder up doesn't list this module, and
# Sightread builds against released kit versions only.
export GOWORK := off

# How long each fuzz target runs under `make fuzz`.
FUZZTIME ?= 30s
# `make fuzz` runs the targets whose place in the list, counted from 0,
# leaves SHARD when divided by SHARDS, so CI can split them over jobs.
SHARD ?= 0
SHARDS ?= 1

.PHONY: build test test-short test-integrated lint fmt check hooks fuzz signals-doc testbed testbed-down perf bench reproduce actionlint

build: ## build bin/rhythm-sightread
	go build -o bin/rhythm-sightread ./cmd/rhythm-sightread

test: ## run every Go test with the race detector
	go test -race ./...

test-short: ## the quick tests only
	go test -short ./...

test-integrated: ## every test, failing instead of skipping when a stage isn't linked
	SIGHTREAD_REQUIRE_LINKED=1 go test -race ./...

lint:
	$(GOLANGCI) run ./...

fmt:
	gofmt -w .

check: lint test ## everything CI runs

hooks: ## enable the Conventional Commits hook
	git config core.hooksPath .githooks

fuzz: ## run every Fuzz* target (or one SHARD of SHARDS) for FUZZTIME (default 30s) each
	@set -e; i=0; failed=""; for pkg in $$(go list ./...); do \
		for f in $$(go test -list '^Fuzz' "$$pkg" | grep '^Fuzz' || true); do \
			if [ $$((i % $(SHARDS))) -eq $(SHARD) ]; then \
				echo "fuzz $$pkg $$f for $(FUZZTIME)"; \
				go test -run '^$$' -fuzz "^$$f$$" -fuzztime $(FUZZTIME) "$$pkg" || failed="$$failed $$pkg.$$f"; \
			fi; \
			i=$$((i + 1)); \
		done; \
	done; \
	if [ -n "$$failed" ]; then echo "fuzz found crashers in:$$failed"; exit 1; fi

signals-doc: ## write docs/signals.md from the signal catalogue and explain text
	go run ./detect/cmd/signalsdoc

testbed: ## start the fixture registries on 127.0.0.1
	$(MAKE) -C testbed up

testbed-down:
	$(MAKE) -C testbed down

perf: ## hold the speed targets: 2 s per plugin side and 50 MB/s of lexing
	SIGHTREAD_PERF=1 go test -count=1 -run 'TestAnalyzePluginTime|TestLexThroughput' ./analyze ./lex/...
	go test -run '^$$' -bench BenchmarkAnalyzeWordPressPlugin -benchtime 3x ./analyze

bench: build perf ## the speed targets, then the benchmark against the testbed; writes docs/benchmark.md
	$(MAKE) -C testbed bench

reproduce: build ## replay the testbed scenarios and compare with the expected reports
	$(MAKE) -C testbed reproduce

actionlint: ## lint the GitHub workflows, from the image CI pins
	docker run --rm -v "$(CURDIR):/repo" -w /repo rhysd/actionlint@sha256:887a259a5a534f3c4f36cb02dca341673c6089431057242cdc931e9f133147e9 -color
