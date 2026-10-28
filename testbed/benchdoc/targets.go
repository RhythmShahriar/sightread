// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package benchdoc

import (
	"fmt"
	"strings"
	"time"

	"github.com/RhythmShahriar/sightread/testbed/scenario"
)

// Target is one 1.0 target of PRD 19 and qa.md section 9. Met is false
// when something that ran failed it. NotRun lists what it covers that
// did not run on this machine ("" when everything ran): such a target
// is reported as not run, never as met, even when nothing failed.
type Target struct {
	Name   string
	Met    bool
	NotRun string
	Detail string
}

// Result is the target's cell on the page: met, not run or NOT MET.
func (t Target) Result() string {
	switch {
	case !t.Met:
		return "**NOT MET**"
	case t.NotRun != "":
		return "not run"
	}
	return "met"
}

// Targets checks r against every 1.0 target, in the order the page
// lists them.
func (r *Results) Targets() []Target {
	var t []Target
	add := func(name string, met bool, format string, a ...any) {
		t = append(t, Target{Name: name, Met: met, Detail: fmt.Sprintf(format, a...)})
	}

	if r.BinErr != "" {
		add("The binary builds and runs", false, "%s", r.BinErr)
	}

	var bad, caught, pending, good, clean, noReport int
	var mismatched, unstable []string
	for _, s := range r.Scenarios {
		if s.Pending != "" {
			pending++
			continue
		}
		if s.Status == string(scenario.StatusNoReport) {
			noReport++
		}
		switch s.Kind {
		case "bad":
			bad++
			if s.Status == "caught" {
				caught++
			}
		case "good":
			good++
			if s.Status == "clean" {
				clean++
			}
		}
		if len(s.Mismatch()) > 0 {
			mismatched = append(mismatched, s.ID)
		}
		if !s.Reproducible() {
			unstable = append(unstable, s.ID)
		}
	}
	add("Every non-pending bad scenario caught", caught == bad, "%d of %d caught, %d pending shown apart", caught, bad, pending)
	add("Zero false alarms on good scenarios", clean == good, "%d of %d clean", clean, good)
	add("Every run wrote a report", noReport == 0, "%d without a report", noReport)
	add("Exit codes, verdicts and Not checked as expected", len(mismatched) == 0, "%s", listOrNone(mismatched))
	c := r.Control
	add("Zero false alarms in the control pass", c.Rounds > 0 && c.FalseAlarms == 0 && len(c.Unstable) == 0,
		"%d rounds, %d runs, %d false alarms, unstable: %s", c.Rounds, c.Runs, c.FalseAlarms, listOrNone(c.Unstable))
	s := r.Safety
	add("Zero canary, egress, outside-write, unmasked-key and forwarded-token events", s.Zero(),
		"canary %d connections and %d files, egress %d, outside writes %d, unmasked keys %d, tokens sent to codeload %d",
		s.CanaryConnections, len(s.CanaryFiles), len(s.Egress), len(s.OutsideWrites), len(s.Unmasked), len(s.Forwarded))

	var failed, notRun []string
	passed := 0
	envs := append(append([]EnvResult(nil), r.Env...), r.Staging...)
	for _, e := range envs {
		switch e.Result {
		case ResultPass:
			passed++
		case ResultFail:
			failed = append(failed, e.ID)
		case ResultNotRun:
			notRun = append(notRun, e.ID)
		}
	}
	add("Every environment scenario passes", len(failed) == 0, "%d of %d passed; failed: %s; not run here: %s",
		passed, len(envs), listOrNone(failed), listOrNone(notRun))
	t[len(t)-1].NotRun = strings.Join(notRun, ", ")
	add("Cold and warm runs agree", len(unstable) == 0, "differ: %s", listOrNone(unstable))
	l := r.Large
	if l.Ran {
		add("p01-large under 10 s warm and 512 MB RSS", l.Met(), "warm %.1f s, peak %.0f MB (cold %.1f s, %.0f MB), exit %d",
			l.Warm.Seconds, max(l.Warm.RSSMB, l.Cold.RSSMB), l.Cold.Seconds, l.Cold.RSSMB, l.Exit)
	} else {
		add("p01-large under 10 s warm and 512 MB RSS", false, "not run: %s", orDash(l.Note))
	}
	took := time.Duration(r.Seconds * float64(time.Second)).Round(time.Second)
	add("Full benchmark under 10 minutes", took < BenchLimit, "%s", took)
	return t
}

// Met reports whether every target is met by a complete run: nothing
// failed and everything ran. A target not run here is never met.
func (r *Results) Met() bool {
	if r.Partial {
		return false
	}
	for _, t := range r.Targets() {
		if !t.Met || t.NotRun != "" {
			return false
		}
	}
	return true
}

// Failed returns the targets something that ran failed. A complete run
// exits non-zero when there is one; a target that was only not run here
// (e13 off Windows, e15 without the Docker WordPress) does not fail the
// exit. The page and the bench still never call it met.
func (r *Results) Failed() []Target {
	var out []Target
	for _, t := range r.Targets() {
		if !t.Met {
			out = append(out, t)
		}
	}
	return out
}

// NotRunTargets returns the targets nothing failed but some of whose
// cases did not run here.
func (r *Results) NotRunTargets() []Target {
	var out []Target
	for _, t := range r.Targets() {
		if t.Met && t.NotRun != "" {
			out = append(out, t)
		}
	}
	return out
}

// listOrNone joins ss, or says none.
func listOrNone(ss []string) string {
	if len(ss) == 0 {
		return "none"
	}
	return strings.Join(ss, ", ")
}

// PartialFailures lists what failed in a partial run (-only): a scenario
// that ran and was not caught or clean or gave the wrong exit, verdict
// or Not checked reasons, a failed environment or e15 case and any
// safety event. The 1.0 targets are never claimed for a partial run;
// this is what decides its exit code.
func (r *Results) PartialFailures() []string {
	var out []string
	if r.BinErr != "" {
		out = append(out, "binary: "+r.BinErr)
	}
	for _, s := range r.Scenarios {
		if s.Pending != "" {
			continue
		}
		if (s.Kind == "bad" && s.Status != "caught") || (s.Kind == "good" && s.Status != "clean") || len(s.Mismatch()) > 0 {
			out = append(out, s.ID)
		}
	}
	for _, e := range append(append([]EnvResult(nil), r.Env...), r.Staging...) {
		if e.Result == ResultFail {
			out = append(out, e.ID)
		}
	}
	if !r.Safety.Zero() {
		out = append(out, "safety counters")
	}
	return out
}
