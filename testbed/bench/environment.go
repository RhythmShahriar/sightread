// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build testbed

package main

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/RhythmShahriar/sightread/testbed/benchdoc"
	"github.com/RhythmShahriar/sightread/testbed/ports"
	"github.com/RhythmShahriar/sightread/testbed/scenario"
)

// envCheck collects what an environment scenario got wrong.
type envCheck struct {
	notes  []string
	failed bool
	notRun string
}

func (c *envCheck) fail(format string, a ...any) {
	c.failed = true
	c.notes = append(c.notes, fmt.Sprintf(format, a...))
}

func (c *envCheck) note(format string, a ...any) {
	c.notes = append(c.notes, fmt.Sprintf(format, a...))
}

// environment runs one environment scenario: the manifest's command
// with the setup the scenario needs, then its env assertions and the
// scenario-specific checks below.
func (h *harness) environment(ctx context.Context, s scenario.Scenario) benchdoc.EnvResult {
	start := time.Now()
	c := &envCheck{}
	if err := h.setStates(s.Packages()); err != nil {
		c.fail("set states: %v", err)
	} else {
		h.envScenario(ctx, s, c)
	}
	r := benchdoc.EnvResult{ID: s.ID, Title: s.Title, Result: benchdoc.ResultPass, Notes: c.notes, Seconds: time.Since(start).Seconds()}
	switch {
	case c.notRun != "":
		r.Result, r.Notes = benchdoc.ResultNotRun, append([]string{c.notRun}, c.notes...)
	case c.failed:
		r.Result = benchdoc.ResultFail
	}
	return r
}

// envArgs is a scenario's command with the JSON report and a gate, so
// "could not fetch" is exit 3 (PRD 10) and findings are readable.
func (h *harness) envArgs(s scenario.Scenario, tag string, drop ...string) ([]string, string) {
	out := filepath.Join(h.work, "out", s.ID+"-"+tag+".json")
	_ = os.Remove(out)
	var args []string
	for _, a := range h.expand(s.Command) {
		if !slices.Contains(drop, a) {
			args = append(args, a)
		}
	}
	return append(args, "--fail-on", "high", "-o", out, "--no-color"), out
}

// assertEnv applies the manifest's env block and expected signals.
func (h *harness) assertEnv(s scenario.Scenario, r execResult, report string, c *envCheck) {
	if r.err != nil {
		c.fail("could not start: %v", r.err)
		return
	}
	if r.timedOut {
		c.fail("timed out after %s", h.timeout)
	}
	if strings.Contains(r.output(), "goroutine ") && strings.Contains(r.output(), "panic") {
		c.fail("the binary panicked")
	}
	out := strings.ToLower(r.output())
	if e := s.Env; e != nil {
		if e.Exit != nil && r.exit != *e.Exit {
			c.fail("exit %d, want %d", r.exit, *e.Exit)
		}
		for _, want := range e.Says {
			if !strings.Contains(out, strings.ToLower(want)) {
				c.fail("does not say %q", want)
			}
		}
		for _, never := range e.Never {
			if strings.Contains(out, strings.ToLower(never)) {
				c.fail("says %q, which it must not", never)
			}
		}
	}
	// A scenario that expects the run to work (no exit pinned, or 0 or
	// 1) must also leave a report: a run that stopped on a usage error
	// passes no assertion by saying nothing. e10 may stop with a clear
	// error instead.
	needReport := s.ID != "e10" && (s.Env == nil || s.Env.Exit == nil || *s.Env.Exit <= 1)
	if !needReport && len(s.Expect.Signals) == 0 {
		return
	}
	f, err := os.Open(report) //nolint:gosec // the report this run wrote
	if err != nil {
		c.fail("no JSON report (exit %d): %s", r.exit, firstLine(r.stderr, err))
		return
	}
	rep, err := scenario.ReadReport(f)
	_ = f.Close()
	if err != nil {
		c.fail("report: %v", err)
		return
	}
	o := scenario.Evaluate(scenario.Scenario{ID: s.ID, Kind: scenario.KindBad, Expect: s.Expect}, rep)
	if len(o.Missing) > 0 {
		c.fail("missing signals: %s", strings.Join(o.Missing, ", "))
	}
}

// envScenario dispatches the per-scenario setup and checks.
func (h *harness) envScenario(ctx context.Context, s scenario.Scenario, c *envCheck) {
	o := runOpts{id: s.ID}
	_ = os.RemoveAll(filepath.Join(h.work, "cache", s.ID))
	front := func(port int) map[string]string {
		return map[string]string{"SIGHTREAD_NPM_REGISTRY": fmt.Sprintf("%s://127.0.0.1:%d", h.scheme(), port)}
	}

	switch s.ID {
	case "e01": // registry down: the npm base names a port where nothing listens
		o.env = map[string]string{"SIGHTREAD_NPM_REGISTRY": fmt.Sprintf("%s://127.0.0.1:%d", h.scheme(), ports.ProbeUnconfigured)}
		args, out := h.envArgs(s, "run")
		h.assertEnv(s, h.run(ctx, args, o), out, c)

	case "e02": // 429 then 200 with Retry-After
		h.retry.Reset()
		o.env = front(ports.FrontRetry)
		args, out := h.envArgs(s, "run")
		r := h.run(ctx, args, o)
		h.assertEnv(s, r, out, c)
		if h.retry.Limited() == 0 {
			c.fail("the front never answered 429: the run did not reach it")
		} else {
			c.note("%d answers of 429, %d requests", h.retry.Limited(), h.retry.Requests())
		}

	case "e03": // stalled body: stops at --timeout
		h.stall.Reset()
		o.env = front(ports.FrontStall)
		args, out := h.envArgs(s, "run")
		args = append(args, "--timeout", "2s", "--retries", "0")
		r := h.run(ctx, args, o)
		h.assertEnv(s, r, out, c)
		if r.elapsed > 20*time.Second {
			c.fail("took %s with --timeout 2s", r.elapsed.Round(time.Second))
		}
		if h.stall.Stalled() == 0 {
			c.fail("the tarball download never reached the stalling front")
		}

	case "e04": // zip bomb: unanalysed within the memory cap
		args, out := h.envArgs(s, "run")
		r := h.run(ctx, args, o)
		h.assertEnv(s, r, out, c)
		if r.rssMB > 512 {
			c.fail("peak RSS %.0f MB, over the 512 MB cap", r.rssMB)
		}

	case "e05": // hostile entries: reported, nothing written outside
		args, out := h.envArgs(s, "run")
		mark := len(h.outside)
		r := h.run(ctx, args, o)
		h.assertEnv(s, r, out, c)
		if len(h.outside) > mark {
			c.fail("wrote outside the work folders: %s", strings.Join(h.outside[mark:], "; "))
		}
		if strays := strayFiles(filepath.Join(h.work, "tmp", s.ID)); len(strays) > 0 {
			c.fail("left files in its temp folder: %s", strings.Join(strays, ", "))
		}

	case "e06": // cached blob tampered on disk: detected and refetched
		args, out := h.envArgs(s, "run")
		first := h.run(ctx, args, o)
		h.assertEnv(s, first, out, c)
		cache := filepath.Join(h.work, "cache", s.ID)
		n := tamperBlobs(cache)
		if n == 0 {
			c.fail("no cached blob to tamper with in the run's cache")
			return
		}
		mark := h.requestCount()
		second := h.run(ctx, args, o)
		h.assertEnv(s, second, out, c)
		if second.exit != first.exit {
			c.fail("exit %d after tampering, %d before", second.exit, first.exit)
		}
		if !h.requestedSince(mark, ".tgz") {
			c.fail("the tampered blob was reused: no tarball fetched again")
		}
		c.note("tampered %d cached blobs", n)

	case "e07": // two runs share one cache
		args, out := h.envArgs(s, "a")
		argsB, outB := h.envArgs(s, "b")
		o.noWatch = true
		var wg sync.WaitGroup
		var ra, rb execResult
		wg.Add(2)
		go func() { defer wg.Done(); ra = h.run(ctx, args, o) }()
		go func() { defer wg.Done(); rb = h.run(ctx, argsB, o) }()
		wg.Wait()
		h.assertEnv(s, ra, out, c)
		h.assertEnv(s, rb, outB, c)
		if ra.exit != rb.exit {
			c.fail("the two runs exited %d and %d", ra.exit, rb.exit)
		}
		third := h.run(ctx, args, runOpts{id: s.ID})
		if third.exit != ra.exit {
			c.fail("a run after them exited %d, they exited %d: the shared cache is corrupt", third.exit, ra.exit)
		}

	case "e08": // Ctrl-C during a stalled fetch
		if runtime.GOOS == "windows" {
			c.notRun = "needs SIGINT, which Windows cannot send a child"
			return
		}
		h.stall.Reset()
		o.env = front(ports.FrontStall)
		args, out := h.envArgs(s, "run")
		o.interruptAfter = 3 * time.Second
		r := h.run(ctx, args, o)
		h.assertEnv(s, r, out, c)
		if h.stall.Stalled() == 0 {
			c.fail("interrupted before the download started")
		}
		if partial := partialEntries(filepath.Join(h.work, "cache", s.ID)); len(partial) > 0 {
			c.fail("partial cache entries left: %s", strings.Join(partial, ", "))
		}
		if strays := strayFiles(filepath.Join(h.work, "tmp", s.ID)); len(strays) > 0 {
			c.fail("temp files left: %s", strings.Join(strays, ", "))
		}

	case "e09": // offline with a warm cache
		warmArgs, _ := h.envArgs(s, "warm", "--offline")
		if w := h.run(ctx, warmArgs, o); w.exit != 0 {
			c.fail("the online warm-up exited %d: %s", w.exit, firstLine(w.stderr, w.err))
		}
		args, out := h.envArgs(s, "run")
		o.env = map[string]string{"RHYTHM_OFFLINE": "1"}
		mark := h.requestCount()
		h.assertEnv(s, h.run(ctx, args, o), out, c)
		if n := h.requestCount() - mark; n > 0 {
			c.fail("made %d registry requests while offline", n)
		}

	case "e10": // read-only HOME, no RHYTHM_CACHE_DIR
		if runtime.GOOS == "windows" || os.Geteuid() == 0 {
			c.notRun = "needs a non-root user on a Unix file system to make HOME read-only"
			return
		}
		home := filepath.Join(h.work, "rohome")
		if err := os.MkdirAll(home, 0o750); err != nil {
			c.fail("%v", err)
			return
		}
		if err := os.Chmod(home, 0o500); err != nil { //nolint:gosec // read-only on purpose
			c.fail("%v", err)
			return
		}
		defer func() { _ = os.Chmod(home, 0o750) }() //nolint:gosec // restore for cleanup
		o.home, o.cache, o.noWatch = home, "-", true
		o.env = map[string]string{"XDG_CACHE_HOME": "", "XDG_CONFIG_HOME": ""}
		args, out := h.envArgs(s, "run")
		r := h.run(ctx, args, o)
		h.assertEnv(s, r, out, c)
		lower := strings.ToLower(r.output())
		switch {
		case r.exit == 0 || r.exit == 1:
			c.note("ran with a fallback cache (exit %d)", r.exit)
		case (r.exit == 2 || r.exit == 3) && (strings.Contains(lower, "cache") || strings.Contains(lower, "home") || strings.Contains(lower, "read-only")):
			c.note("stopped with a clear error (exit %d)", r.exit)
		default:
			c.fail("exit %d without a clear cache or HOME message: %s", r.exit, firstLine(r.stderr, nil))
		}

	case "e11": // private host and namesake: never named in a request
		args, out := h.envArgs(s, "run")
		mark := h.requestCount()
		r := h.run(ctx, args, o)
		h.assertEnv(s, r, out, c)
		for _, line := range h.requestsSince(mark) {
			low := strings.ToLower(line)
			for _, secret := range []string{"private-host.example", "e11-private", "@acme", "%40acme"} {
				if strings.Contains(low, secret) {
					c.fail("a request names %s: %s", secret, line)
				}
			}
		}

	case "e13": // Windows run catches b10
		if runtime.GOOS != "windows" {
			c.notRun = "Windows only; the nightly bench-windows job runs it on windows-latest with -only e13 -plain-http"
			return
		}
		b10, ok := h.scenarioByID("b10")
		if !ok {
			c.fail("no b10 in the manifest")
			return
		}
		if err := h.setStates(b10.Packages()); err != nil {
			c.fail("%v", err)
			return
		}
		rv := h.review(ctx, b10, o, "e13")
		if rv.outcome.Status != scenario.StatusCaught {
			c.fail("b10 on Windows: %s %s", rv.outcome.Status, rv.problem)
		}

	case "e14": // escapes printed escaped
		args, out := h.envArgs(s, "run")
		r := h.run(ctx, args, o)
		h.assertEnv(s, r, out, c)
		if bad := rawControls(r.output()); len(bad) > 0 {
			c.fail("printed raw control characters: %s", strings.Join(bad, ", "))
		}

	default: // e12 and any new scenario: the manifest's assertions only
		args, out := h.envArgs(s, "run")
		h.assertEnv(s, h.run(ctx, args, o), out, c)
	}
}

// scenarioByID finds a manifest entry.
func (h *harness) scenarioByID(id string) (scenario.Scenario, bool) {
	for _, s := range h.manifest.Scenarios {
		if s.ID == id {
			return s, true
		}
	}
	return scenario.Scenario{}, false
}

// rawControls names the escape and bidi characters that appear raw in
// out. With NO_COLOR set Sightread prints no escape of its own, so any
// ESC came from package content.
func rawControls(out string) []string {
	seen := map[string]bool{}
	for _, r := range out {
		switch {
		case r == 0x1b:
			seen["ESC"] = true
		case r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069:
			seen[fmt.Sprintf("U+%04X", r)] = true
		case r < 0x20 && r != '\n' && r != '\t' && r != '\r':
			seen[fmt.Sprintf("U+%04X", r)] = true
		case unicode.Is(unicode.Cf, r) && r != 0xfeff:
			seen[fmt.Sprintf("U+%04X", r)] = true
		}
	}
	out2 := make([]string, 0, len(seen))
	for k := range seen {
		out2 = append(out2, k)
	}
	slices.Sort(out2)
	return out2
}

// tamperBlobs flips the last byte of every cached blob under cache (in
// any blobs folder: the tool's cache is RHYTHM_CACHE_DIR/sightread, PRD
// 8.5) and returns how many it changed.
func tamperBlobs(cache string) int {
	n := 0
	_ = filepath.WalkDir(cache, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() || !slices.Contains(strings.Split(filepath.ToSlash(p), "/"), "blobs") {
			return nil
		}
		b, err := os.ReadFile(p) //nolint:gosec // our own cache folder
		if err != nil || len(b) == 0 {
			return nil
		}
		b[len(b)-1] ^= 0xff
		_ = os.Chmod(p, 0o600)                //nolint:gosec // blobs are read-only; this test tampers on purpose
		if os.WriteFile(p, b, 0o600) == nil { //nolint:gosec // p comes from walking our own cache folder
			n++
		}
		return nil
	})
	return n
}

// partialEntries lists cache files that look unfinished.
func partialEntries(cache string) []string {
	var out []string
	_ = filepath.WalkDir(cache, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		name := strings.ToLower(d.Name())
		if strings.Contains(name, ".tmp") || strings.Contains(name, "partial") || strings.HasPrefix(name, ".") && strings.Contains(name, "tmp") {
			rel, _ := filepath.Rel(cache, p)
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	return out
}

// strayFiles lists whatever is left in a run's temp folder.
func strayFiles(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

// requestLines reads the registry's request log.
func (h *harness) requestLines() []string {
	b, err := os.ReadFile(filepath.Join(h.state, "requests.log")) //nolint:gosec // the registry's own log
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimRight(string(b), "\n"), "\n")
}

// requestCount is the number of logged requests so far.
func (h *harness) requestCount() int { return len(h.requestLines()) }

// requestsSince returns the requests logged after mark.
func (h *harness) requestsSince(mark int) []string {
	lines := h.requestLines()
	if mark >= len(lines) {
		return nil
	}
	return lines[mark:]
}

// requestedSince reports whether a request whose line contains part was
// logged after mark.
func (h *harness) requestedSince(mark int, part string) bool {
	return slices.ContainsFunc(h.requestsSince(mark), func(l string) bool { return strings.Contains(l, part) })
}
