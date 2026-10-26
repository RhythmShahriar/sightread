// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build testbed

package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/RhythmShahriar/sightread/testbed/benchdoc"
	"github.com/RhythmShahriar/sightread/testbed/fsnap"
	"github.com/RhythmShahriar/sightread/testbed/large"
	"github.com/RhythmShahriar/sightread/testbed/scenario"
)

// reviewed is one run of a scored scenario with its report read back.
type reviewed struct {
	exec    execResult
	report  *scenario.Report
	outcome scenario.Outcome
	problem string
}

// review runs a scenario's command with its gate and a JSON report and
// evaluates the report. extra goes after the manifest's arguments.
func (h *harness) review(ctx context.Context, s scenario.Scenario, o runOpts, tag string, extra ...string) reviewed {
	out := filepath.Join(h.work, "out", s.ID+"-"+tag+".json")
	_ = os.Remove(out)
	args := append(h.expand(s.Command), "--fail-on", s.EffectiveFailOn(), "-o", out, "--no-color")
	args = append(args, extra...)
	rv := reviewed{exec: h.run(ctx, args, o)}

	raw, err := os.ReadFile(out) //nolint:gosec // the report this run wrote
	if err == nil {
		h.checkMasked(s.ID, "report "+filepath.Base(out), raw)
		rv.report, err = scenario.ReadReport(bytes.NewReader(raw))
	}
	if rv.report != nil {
		rv.outcome = scenario.Evaluate(s, rv.report)
		return rv
	}
	rv.problem = fmt.Sprintf("no rhythm-sightread/v1 report (exit %d): %s", rv.exec.exit, firstLine(rv.exec.stderr, err))
	if rv.exec.err != nil {
		rv.problem = "could not start: " + rv.exec.err.Error()
	}
	if rv.exec.timedOut {
		rv.problem = "timed out after " + h.timeout.String()
	}
	// Without a report nothing can be counted as caught or clean. A
	// crash is neither a miss nor a false alarm either.
	rv.outcome = scenario.Outcome{Scenario: s, Status: scenario.StatusNoReport}
	if s.Pending != "" {
		rv.outcome.Status = scenario.StatusPending
	}
	return rv
}

// scored runs a bad or good scenario cold, then warm on the same cache.
func (h *harness) scored(ctx context.Context, s scenario.Scenario) benchdoc.ScenarioResult {
	if err := h.setStates(s.Packages()); err != nil {
		return benchdoc.ScenarioResult{ID: s.ID, Kind: s.Kind, Title: s.Title, Status: string(scenario.StatusNoReport), Problem: err.Error(),
			NotCheckedOK: len(s.Expect.NotCheckedReasons) == 0}
	}
	o := runOpts{id: s.ID}
	_ = os.RemoveAll(filepath.Join(h.work, "cache", s.ID))
	cold := h.review(ctx, s, o, "cold")
	warm := h.review(ctx, s, o, "warm")

	res := benchdoc.ScenarioResult{
		ID: s.ID, Kind: s.Kind, Title: s.Title, Pending: s.Pending,
		Status:      string(cold.outcome.Status),
		Present:     cold.outcome.Present,
		Missing:     cold.outcome.Missing,
		FalseAlarms: cold.outcome.FalseAlarms,
		Forbidden:   cold.outcome.Forbidden,
		WantVerdict: s.Expect.Verdict,
		Exit:        cold.exec.exit,
		WantExit:    s.Expect.Exit,
		Problem:     cold.problem,
		Cold:        benchdoc.Timing{Seconds: cold.exec.elapsed.Seconds(), RSSMB: cold.exec.rssMB},
		Warm:        benchdoc.Timing{Seconds: warm.exec.elapsed.Seconds(), RSSMB: warm.exec.rssMB},
		WarmStatus:  string(warm.outcome.Status),
		WarmExit:    warm.exec.exit,
	}
	// Without a report only an expectation of no reasons is met; the
	// missing report itself is the problem shown.
	res.NotCheckedOK = len(s.Expect.NotCheckedReasons) == 0
	if cold.report != nil {
		res.Verdict = cold.report.OverallVerdict()
		res.NotCheckedOK = cold.report.NotCheckedOK(s.Expect.NotCheckedReasons)
	}
	return res
}

// control reruns every good scenario rounds times on a warm cache: a
// finding that comes and goes is a false alarm too.
func (h *harness) control(ctx context.Context, scored []scenario.Scenario, rounds int) benchdoc.Control {
	c := benchdoc.Control{Rounds: rounds}
	first := map[string]scenario.Status{}
	for round := 1; round <= rounds; round++ {
		for _, s := range scored {
			if s.Kind != scenario.KindGood || s.Pending != "" || ctx.Err() != nil {
				continue
			}
			if err := h.setStates(s.Packages()); err != nil {
				continue
			}
			rv := h.review(ctx, s, runOpts{id: s.ID}, "control")
			c.Runs++
			if rv.outcome.Status != scenario.StatusClean {
				c.FalseAlarms++
			}
			if prev, ok := first[s.ID]; !ok {
				first[s.ID] = rv.outcome.Status
			} else if prev != rv.outcome.Status && !slices.Contains(c.Unstable, s.ID) {
				c.Unstable = append(c.Unstable, s.ID)
			}
		}
	}
	return c
}

// large reviews the generated p01-large pair cold and warm.
func (h *harness) large(ctx context.Context) benchdoc.Large {
	dir := filepath.Join(h.state, large.Slug)
	if err := large.Generate(dir, large.Default); err != nil {
		return benchdoc.Large{Note: "generate: " + err.Error()}
	}
	l := benchdoc.Large{Ran: true}
	if snap, err := fsnap.Take(filepath.Join(dir, "new")); err == nil {
		var size int64
		for _, e := range snap {
			if e.Kind == "file" {
				l.Files++
				size += e.Size
			}
		}
		l.MB = float64(size) / (1 << 20)
	}
	args := []string{"plugin", large.Slug, "--from-file", filepath.Join(dir, "old"), "--to-file", filepath.Join(dir, "new"),
		"--allow-unverified", "--fail-on", "none", "-o", filepath.Join(h.work, "out", "p01-large.json"), "--no-color"}
	o := runOpts{id: "p01-large"}
	cold := h.run(ctx, args, o)
	warm := h.run(ctx, args, o)
	l.Exit = warm.exit
	if cold.exit != 0 {
		l.Exit = cold.exit
	}
	l.Cold = benchdoc.Timing{Seconds: cold.elapsed.Seconds(), RSSMB: cold.rssMB}
	l.Warm = benchdoc.Timing{Seconds: warm.elapsed.Seconds(), RSSMB: warm.rssMB}
	if cold.exit != 0 {
		l.Note = fmt.Sprintf("exit %d: %s", cold.exit, firstLine(cold.stderr, cold.err))
	}
	return l
}

// safety gathers the counters that must stay at zero.
func (h *harness) safety() benchdoc.Safety {
	var s benchdoc.Safety
	if h.can != nil {
		s.CanaryConnections = h.can.Count()
		s.CanaryFiles, _ = h.can.Files()
	}
	s.Egress = append(append(s.Egress, h.egress...), h.foreignRequests()...)
	s.OutsideWrites = h.outside
	s.Unmasked = h.unmasked
	return s
}

// foreignRequests lists registry requests whose Host names something
// other than loopback: a client that sent a real host name to a fixture.
func (h *harness) foreignRequests() []string {
	f, err := os.Open(filepath.Join(h.state, "requests.log")) //nolint:gosec // the registry's own log
	if err != nil {
		return nil
	}
	defer func() { _ = f.Close() }()
	var out []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		var line struct{ Host, Path string }
		if json.Unmarshal(sc.Bytes(), &line) != nil {
			continue
		}
		if !loopbackHost(line.Host) {
			out = append(out, "registry request for "+line.Host+line.Path)
		}
	}
	return out
}

// loopbackHost reports whether a Host header names loopback.
func loopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkMasked records where a fixture's fake key appears in full in b:
// Sightread masks secrets in every output, so one found is a leak.
func (h *harness) checkMasked(id, where string, b []byte) {
	for _, k := range h.fakeKeys {
		if bytes.Contains(b, []byte(k)) {
			h.unmasked = append(h.unmasked, id+": "+where)
			return
		}
	}
}
