// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package benchdoc

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

// Schema names the results.json format.
const Schema = "sightread-bench/v1"

// The PRD 17 testbed targets.
const (
	// LargeWarmLimit is the most a warm review of p01-large may take.
	LargeWarmLimit = 10 * time.Second
	// LargeRSSLimitMB is the most memory a review of p01-large may use.
	LargeRSSLimitMB = 512
	// BenchLimit is the most the full benchmark may take.
	BenchLimit = 10 * time.Minute
)

// Results is one benchmark run, written to results.json.
type Results struct {
	Schema string `json:"schema"`
	// Started is when the run began; Seconds how long it took.
	Started time.Time `json:"started"`
	Seconds float64   `json:"seconds"`
	// Version is what rhythm-sightread --version printed.
	Version string `json:"version"`
	// Machine names the OS, architecture and CPU count.
	Machine string `json:"machine"`
	// Partial is set when only some scenarios ran (-only); the targets
	// are then reported but a partial run never claims them met.
	Partial bool `json:"partial,omitempty"`
	// BinErr says why the binary could not be built or run at all.
	BinErr string `json:"bin_error,omitempty"`

	Scenarios []ScenarioResult `json:"scenarios"`
	Control   Control          `json:"control"`
	Env       []EnvResult      `json:"environment"`
	Staging   []EnvResult      `json:"staging"`
	Safety    Safety           `json:"safety"`
	Large     Large            `json:"large"`
	Tools     []Tool           `json:"tools"`
}

// Timing is one run's wall time and peak memory.
type Timing struct {
	Seconds float64 `json:"seconds"`
	RSSMB   float64 `json:"rss_mb"`
}

// ScenarioResult is one bad or good scenario.
type ScenarioResult struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Title   string `json:"title"`
	Pending string `json:"pending,omitempty"`
	// Status is the scenario package's status (caught, missed, clean...).
	Status      string   `json:"status"`
	Present     []string `json:"present,omitempty"`
	Missing     []string `json:"missing,omitempty"`
	FalseAlarms []string `json:"false_alarms,omitempty"`
	Forbidden   []string `json:"forbidden,omitempty"`
	// Verdict and Exit are what the cold run gave; Want* what the
	// manifest expects (an empty WantVerdict accepts any).
	Verdict     string `json:"verdict"`
	WantVerdict string `json:"want_verdict,omitempty"`
	Exit        int    `json:"exit"`
	WantExit    int    `json:"want_exit"`
	// NotCheckedOK is false when an expected Not checked reason is absent.
	NotCheckedOK bool `json:"not_checked_ok"`
	// Problem explains a run that gave no usable report.
	Problem string `json:"problem,omitempty"`
	// Cold is the first run on an empty cache, Warm the second.
	Cold Timing `json:"cold"`
	Warm Timing `json:"warm"`
	// WarmStatus and WarmExit are the warm run's outcome, for the
	// in-run reproducibility check.
	WarmStatus string `json:"warm_status"`
	WarmExit   int    `json:"warm_exit"`
	// Tools maps a compared tool's name to its result label.
	Tools map[string]string `json:"tools,omitempty"`
}

// Mismatch lists what a scored scenario got wrong beyond its status:
// the exit code, the verdict and the Not checked reasons.
func (s ScenarioResult) Mismatch() []string {
	if s.Pending != "" {
		return nil
	}
	var out []string
	if s.Exit != s.WantExit {
		out = append(out, fmt.Sprintf("exit %d, want %d", s.Exit, s.WantExit))
	}
	if s.WantVerdict != "" && s.Verdict != s.WantVerdict {
		out = append(out, fmt.Sprintf("verdict %s, want %s", orDash(s.Verdict), s.WantVerdict))
	}
	if !s.NotCheckedOK {
		out = append(out, "an expected Not checked reason is missing")
	}
	return out
}

// Reproducible reports whether the warm run gave the same outcome.
func (s ScenarioResult) Reproducible() bool {
	return s.Status == s.WarmStatus && s.Exit == s.WarmExit
}

// Control is the control pass: every good scenario again, Rounds times.
type Control struct {
	Rounds      int      `json:"rounds"`
	Runs        int      `json:"runs"`
	FalseAlarms int      `json:"false_alarms"`
	Unstable    []string `json:"unstable,omitempty"` // scenarios whose outcome changed between rounds
}

// The results of an environment scenario or an e15 case.
const (
	ResultPass   = "pass"
	ResultFail   = "fail"
	ResultNotRun = "not run"
)

// EnvResult is one environment scenario or one --soundcheck case.
type EnvResult struct {
	ID      string   `json:"id"`
	Title   string   `json:"title"`
	Result  string   `json:"result"`
	Notes   []string `json:"notes,omitempty"`
	Seconds float64  `json:"seconds"`
}

// Safety holds the counters that must all be zero.
type Safety struct {
	CanaryConnections int      `json:"canary_connections"`
	CanaryFiles       []string `json:"canary_files,omitempty"`
	// Egress lists attempts to reach anything outside the fixture set:
	// proxy guard request lines and registry requests naming a foreign
	// host.
	Egress []string `json:"egress,omitempty"`
	// OutsideWrites lists files written outside the work folders, as
	// "<scenario>: added: <path>".
	OutsideWrites []string `json:"outside_writes,omitempty"`
}

// Zero reports whether nothing fired, escaped or was written outside.
func (s Safety) Zero() bool {
	return s.CanaryConnections == 0 && len(s.CanaryFiles) == 0 && len(s.Egress) == 0 && len(s.OutsideWrites) == 0
}

// Large is the p01-large performance check.
type Large struct {
	Ran   bool    `json:"ran"`
	Note  string  `json:"note,omitempty"`
	Files int     `json:"files"`
	MB    float64 `json:"mb"`
	Exit  int     `json:"exit"`
	Cold  Timing  `json:"cold"`
	Warm  Timing  `json:"warm"`
}

// Met reports whether the warm review was fast and small enough.
func (l Large) Met() bool {
	return l.Ran && l.Exit != 3 && l.Exit != 2 && l.Warm.Seconds < LargeWarmLimit.Seconds() &&
		l.Warm.RSSMB < LargeRSSLimitMB && l.Cold.RSSMB < LargeRSSLimitMB
}

// Tool is a compared tool: its version, or why it was not run.
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	NotRun  string `json:"not_run,omitempty"`
	// Scope names what it can see ("npm and Composer lockfiles").
	Scope string `json:"scope"`
}

// Labels a compared tool gets per scenario.
const (
	ToolCaught     = "caught"
	ToolMissed     = "missed"
	ToolClean      = "clean"
	ToolFalseAlarm = "false alarm"
	ToolCantSee    = "can't see"
	ToolNotRun     = "not run"
	ToolError      = "error"
)

// Write saves r as indented JSON at path.
func (r *Results) Write(path string) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644) //nolint:gosec // benchmark output, not a secret
}

// Read loads a results.json.
func Read(path string) (*Results, error) {
	b, err := os.ReadFile(path) //nolint:gosec // a results file the caller named
	if err != nil {
		return nil, err
	}
	var r Results
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if r.Schema != Schema {
		return nil, fmt.Errorf("%s: schema %q, want %q", path, r.Schema, Schema)
	}
	return &r, nil
}

// outcomes flattens what make reproduce compares: every scenario's
// status, exit and verdict and every environment and e15 result. Times
// and memory are left out; they always differ.
func (r *Results) outcomes() map[string]string {
	out := map[string]string{}
	for _, s := range r.Scenarios {
		out["scenario "+s.ID] = fmt.Sprintf("%s exit %d verdict %s", s.Status, s.Exit, orDash(s.Verdict))
		for name, label := range s.Tools {
			out["tool "+name+" "+s.ID] = label
		}
	}
	for _, e := range r.Env {
		out["env "+e.ID] = e.Result
	}
	for _, e := range r.Staging {
		out["e15 "+e.ID] = e.Result
	}
	out["control false alarms"] = fmt.Sprint(r.Control.FalseAlarms)
	out["safety"] = fmt.Sprint(r.Safety.Zero())
	return out
}

// Diff writes every outcome that differs between a and b and reports
// whether they were identical.
func Diff(a, b *Results, w io.Writer) bool {
	oa, ob := a.outcomes(), b.outcomes()
	keys := map[string]bool{}
	for k := range oa {
		keys[k] = true
	}
	for k := range ob {
		keys[k] = true
	}
	sorted := make([]string, 0, len(keys))
	for k := range keys {
		sorted = append(sorted, k)
	}
	sort.Strings(sorted)
	same := true
	for _, k := range sorted {
		if oa[k] != ob[k] {
			same = false
			fmt.Fprintf(w, "%s: %s -> %s\n", k, orDash(oa[k]), orDash(ob[k]))
		}
	}
	if same {
		fmt.Fprintf(w, "identical: %d outcomes\n", len(sorted))
	}
	return same
}

// orDash returns s, or a dash when it is empty.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
