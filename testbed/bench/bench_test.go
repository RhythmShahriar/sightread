// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build testbed

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/testbed/benchdoc"
	"github.com/RhythmShahriar/sightread/testbed/scenario"
	"github.com/RhythmShahriar/sightread/testbed/staging"
)

// These tests drive the real binary against the loopback testbed, like
// the benchmark. They need the stages linked; before integration they
// fail, which is the point of running them in the nightly.
//
//	go test -tags testbed ./testbed/bench

var (
	shared     *harness
	sharedErr  error
	sharedOnce sync.Once
	sharedTmp  string
)

// testHarness starts one harness for the whole package (the ports are
// fixed, so only one can run at a time).
func testHarness(t *testing.T) *harness {
	t.Helper()
	sharedOnce.Do(func() {
		root, err := moduleRoot()
		if err != nil {
			sharedErr = err
			return
		}
		work, err := os.MkdirTemp("", "sightread-bench-test-")
		if err != nil {
			sharedErr = err
			return
		}
		sharedTmp = work
		shared, sharedErr = newHarness(context.Background(), root, options{
			bin: filepath.Join(work, "bin", "rhythm-sightread"), build: true, work: filepath.Join(work, "work"),
			tools: "none", timeout: 2 * time.Minute,
		})
	})
	if sharedErr != nil {
		t.Fatal(sharedErr)
	}
	if shared.res.BinErr != "" {
		t.Fatal(shared.res.BinErr)
	}
	return shared
}

func TestMain(m *testing.M) {
	code := m.Run()
	if shared != nil {
		shared.Close()
	}
	if sharedTmp != "" {
		_ = os.RemoveAll(sharedTmp)
	}
	os.Exit(code)
}

// TestManifest checks the manifest against what the bench can run:
// every scenario's folders are built by the registry, every command
// expands to existing paths and every environment scenario that needs
// its own setup has it.
func TestManifest(t *testing.T) {
	h := testHarness(t)
	ids := h.reg.IDs()
	for _, s := range h.manifest.Scenarios {
		for _, p := range s.Packages() {
			if !slices.Contains(ids, p) {
				t.Errorf("%s: the registry built no folder %s", s.ID, p)
			}
		}
		args := h.expand(s.Command)
		for i, a := range args {
			if strings.Contains(a, "{") {
				t.Errorf("%s: %q is not expanded", s.ID, a)
			}
			if i > 0 && slices.Contains([]string{"--path", "--before", "--after", "--from-file", "--to-file", "--wp"}, args[i-1]) {
				p := a
				if !filepath.IsAbs(p) {
					p = filepath.Join(h.tb, p)
				}
				if _, err := os.Stat(p); err != nil {
					t.Errorf("%s: %s %s does not exist", s.ID, args[i-1], a)
				}
			}
		}
		if s.Kind == scenario.KindEnv && s.Env == nil && len(s.Expect.Signals) == 0 {
			t.Errorf("%s: an environment scenario with nothing to assert", s.ID)
		}
	}
}

// TestGoodStateIsClean runs every good scenario: nothing at or above
// its gate beyond what it is allowed.
func TestGoodStateIsClean(t *testing.T) {
	h := testHarness(t)
	for _, s := range h.manifest.Scenarios {
		if s.Kind != scenario.KindGood || s.Pending != "" {
			continue
		}
		t.Run(s.ID, func(t *testing.T) {
			r := h.scored(context.Background(), s)
			if r.Status != string(scenario.StatusClean) {
				t.Errorf("%s: %s, false alarms %v %s", s.ID, r.Status, r.FalseAlarms, r.Problem)
			}
			if m := r.Mismatch(); len(m) > 0 {
				t.Errorf("%s: %s", s.ID, strings.Join(m, "; "))
			}
		})
	}
}

// TestCanaryNeverFires runs every bad scenario and then checks the
// canary: no connection, no file. A payload only reaches it if
// something ran the fetched code.
func TestCanaryNeverFires(t *testing.T) {
	h := testHarness(t)
	for _, s := range h.manifest.Scenarios {
		if s.Kind == scenario.KindBad {
			_ = h.scored(context.Background(), s)
		}
	}
	files, _ := h.can.Files()
	if h.can.Count() != 0 || len(files) != 0 {
		t.Fatalf("the canary fired: %d connections, files %v", h.can.Count(), files)
	}
}

// TestNoEgress proves both seals: from inside the sealed Docker network
// a public address has no route, and outside Docker a run that forgets
// a base URL is stopped by the proxy guard instead of going out.
func TestNoEgress(t *testing.T) {
	h := testHarness(t)
	t.Run("docker", func(t *testing.T) {
		if !wpUp(context.Background()) {
			t.Skip("the Docker WordPress is not up (make -C testbed up-wp)")
		}
		// 192.0.2.1 is a documentation address (RFC 5737): unroutable,
		// so the test touches no one even if the seal were broken.
		// ENETUNREACH (101) proves there is no route at all; a broken
		// seal would time out (110) instead.
		php := `$s = @fsockopen("192.0.2.1", 80, $errno, $errstr, 5); echo $s ? "connected" : $errno;`
		out, err := exec.Command("docker", "compose", "-f", filepath.Join(h.tb, "docker-compose.yml"),
			"exec", "-T", "wp", "php", "-r", php).CombinedOutput()
		if err != nil {
			t.Fatalf("docker compose exec: %v\n%s", err, out)
		}
		if got := strings.TrimSpace(string(out)); got != "101" {
			t.Fatalf("a connection to a public address from the sealed network gave %q, want 101 (network unreachable)", got)
		}
	})
	t.Run("proxy guard", func(t *testing.T) {
		before := h.guard.Count()
		// The npm base is left unset, so Sightread aims at the real
		// registry; the proxy variables send that to the guard.
		r := h.run(context.Background(), []string{"npm", "leftpadplus", "--path", "projects/wp", "--fail-on", "high", "--no-color", "--retries", "0"},
			runOpts{id: "noegress", env: map[string]string{"SIGHTREAD_NPM_REGISTRY": ""}, noWatch: true})
		if r.exit == 0 {
			t.Errorf("a run against the real npm registry exited 0 behind the closed proxy:\n%s", r.output())
		}
		attempts := h.guard.Attempts()[before:]
		if len(attempts) == 0 {
			t.Fatalf("nothing reached the proxy guard: did the run bypass HTTPS_PROXY?\n%s", r.output())
		}
		if !slices.ContainsFunc(attempts, func(a string) bool { return strings.Contains(a, "registry.npmjs.org") }) {
			t.Errorf("the guard saw %v, want a CONNECT to registry.npmjs.org", attempts)
		}
	})
}

// TestLargeFixture holds p01-large to the PRD 17 testbed targets.
func TestLargeFixture(t *testing.T) {
	if testing.Short() {
		t.Skip("writes 80 MB of fixtures")
	}
	h := testHarness(t)
	l := h.large(context.Background())
	if !l.Met() {
		t.Fatalf("p01-large: warm %.1f s (limit %s), RSS cold %.0f MB warm %.0f MB (limit %d), exit %d %s",
			l.Warm.Seconds, benchdoc.LargeWarmLimit, l.Cold.RSSMB, l.Warm.RSSMB, benchdoc.LargeRSSLimitMB, l.Exit, l.Note)
	}
}

// TestSoundcheckE15 runs every e15 case against the Docker WordPress.
func TestSoundcheckE15(t *testing.T) {
	h := testHarness(t)
	if !wpUp(context.Background()) {
		t.Skip("the Docker WordPress is not up (make -C testbed up-wp)")
	}
	results := h.staging(context.Background())
	if len(results) != len(staging.Cases()) {
		t.Fatalf("%d results for %d cases", len(results), len(staging.Cases()))
	}
	for _, r := range results {
		if r.Result == benchdoc.ResultFail {
			t.Errorf("%s: %s", r.ID, strings.Join(r.Notes, "; "))
		}
	}
}

// TestRSSIsMeasured makes sure the speed table is not all zeros on the
// platforms that report rusage.
func TestRSSIsMeasured(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no rusage on Windows")
	}
	h := testHarness(t)
	r := h.run(context.Background(), []string{"--version"}, runOpts{id: "rss", noWatch: true})
	if r.exit != 0 {
		t.Fatalf("--version: exit %d %s", r.exit, r.output())
	}
	if r.rssMB <= 0 {
		t.Errorf("peak RSS of a run is %v MB", r.rssMB)
	}
}
