// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package scenario

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
)

const (
	manifestPath = "../scenarios.yaml"
	packagesDir  = "../packages"
)

// catalogIDs is the set of signal ids core.Catalog defines.
func catalogIDs(t *testing.T) map[string]bool {
	t.Helper()
	ids := map[string]bool{}
	for _, id := range core.SignalIDs() {
		ids[id] = true
	}
	if len(ids) == 0 {
		t.Fatal("core.Catalog is empty")
	}
	return ids
}

// TestManifest checks that every scenario names a package folder that
// exists, that every expected and forbidden signal is a catalogue id,
// and that every minimum severity is a real rank.
func TestManifest(t *testing.T) {
	m, err := Load(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(m.Scenarios) == 0 {
		t.Fatal("no scenarios")
	}
	ids := catalogIDs(t)
	for _, s := range m.Scenarios {
		for _, pkg := range s.Packages() {
			if _, err := os.Stat(filepath.Join(packagesDir, pkg, "meta.yaml")); err != nil {
				t.Errorf("%s: package folder %q has no meta.yaml: %v", s.ID, pkg, err)
			}
		}
		if s.Kind != KindEnv && s.Package == "" {
			t.Errorf("%s: a %s scenario needs a package", s.ID, s.Kind)
		}
		for _, e := range s.Expect.Signals {
			if !ids[e.ID] {
				t.Errorf("%s: expected signal %q is not in core.Catalog", s.ID, e.ID)
			}
			if e.MinSeverity != "" && severityRank(e.MinSeverity) < 0 {
				t.Errorf("%s: signal %q has an unknown min_severity %q", s.ID, e.ID, e.MinSeverity)
			}
		}
		for _, id := range s.Forbid {
			if !ids[id] {
				t.Errorf("%s: forbidden signal %q is not in core.Catalog", s.ID, id)
			}
		}
		if len(s.Command) == 0 {
			t.Errorf("%s: empty command", s.ID)
		}
	}
}

// TestManifestCoversPRD19 checks the scenario counts match PRD 19: 23
// bad, 15 good, 15 environment.
func TestManifestCoversPRD19(t *testing.T) {
	m, err := Load(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var bad, good, env int
	for _, s := range m.Scenarios {
		switch s.Kind {
		case KindBad:
			bad++
		case KindGood:
			good++
		case KindEnv:
			env++
		}
	}
	if bad != 23 || good != 15 || env != 15 {
		t.Errorf("counts: bad %d good %d env %d; want 23/15/15", bad, good, env)
	}
}

// report builds a review with one update carrying the given findings.
func report(verdict string, findings ...ReportFinding) *Report {
	var sum ReportSummary
	switch verdict {
	case "HOLD":
		sum.Hold = 1
	case "REVIEW":
		sum.Review = 1
	default:
		sum.Routine = 1
	}
	return &Report{
		Schema:  "rhythm-sightread/v1",
		Kind:    "review",
		Summary: sum,
		Data:    ReportData{Updates: []ReportUpdate{{Verdict: verdict, Findings: findings}}},
	}
}

func f(id, sev string) ReportFinding { return ReportFinding{ID: id, Severity: sev} }

func TestEvaluate(t *testing.T) {
	bad := Scenario{ID: "b01", Kind: KindBad, Expect: Expect{Signals: []ExpectSignal{
		{ID: "remote-fetch-exec", MinSeverity: "critical"},
		{ID: "owner-change", MinSeverity: "high"},
	}}}

	t.Run("caught", func(t *testing.T) {
		o := Evaluate(bad, report("HOLD", f("remote-fetch-exec", "critical"), f("owner-change", "high")))
		if o.Status != StatusCaught {
			t.Fatalf("want caught, got %s (missing %v)", o.Status, o.Missing)
		}
	})

	t.Run("missed when clean", func(t *testing.T) {
		o := Evaluate(bad, report("ROUTINE"))
		if o.Status != StatusMissed {
			t.Fatalf("want missed, got %s", o.Status)
		}
	})

	t.Run("found as something else", func(t *testing.T) {
		o := Evaluate(bad, report("REVIEW", f("outbound-new-domain", "medium")))
		if o.Status != StatusFoundOther {
			t.Fatalf("want found-as-something-else, got %s", o.Status)
		}
	})

	t.Run("below rank is missing", func(t *testing.T) {
		o := Evaluate(bad, report("REVIEW", f("remote-fetch-exec", "medium"), f("owner-change", "high")))
		if o.Status != StatusFoundOther {
			t.Fatalf("want found-as-something-else, got %s", o.Status)
		}
		if len(o.Missing) != 1 || o.Missing[0] != "remote-fetch-exec" {
			t.Fatalf("want remote-fetch-exec missing, got %v", o.Missing)
		}
	})

	t.Run("allowed finding is not counted", func(t *testing.T) {
		r := report("ROUTINE")
		r.Data.Updates[0].Findings = []ReportFinding{{ID: "owner-change", Severity: "high", Allowed: []byte(`{"by":"x"}`)}}
		o := Evaluate(bad, r)
		if o.Status != StatusMissed {
			t.Fatalf("an allowed finding should not count, got %s", o.Status)
		}
	})

	good := Scenario{ID: "g01", Kind: KindGood}
	t.Run("good clean", func(t *testing.T) {
		o := Evaluate(good, report("ROUTINE", f("cron-new-hook", "low")))
		if o.Status != StatusClean {
			t.Fatalf("a low finding under a medium gate is clean, got %s %v", o.Status, o.FalseAlarms)
		}
	})
	t.Run("good false alarm", func(t *testing.T) {
		o := Evaluate(good, report("REVIEW", f("data-exfil", "high")))
		if o.Status != StatusFalseAlarm || len(o.FalseAlarms) != 1 {
			t.Fatalf("want one false alarm, got %s %v", o.Status, o.FalseAlarms)
		}
	})
	t.Run("good allows a named signal", func(t *testing.T) {
		g15 := Scenario{ID: "g15", Kind: KindGood, FailOn: "high",
			Expect: Expect{Signals: []ExpectSignal{{ID: "owner-change", MinSeverity: "high"}}}}
		o := Evaluate(g15, report("REVIEW", f("owner-change", "high")))
		if o.Status != StatusClean {
			t.Fatalf("an allowed owner-change is not a false alarm, got %s %v", o.Status, o.FalseAlarms)
		}
	})

	t.Run("pending is set apart", func(t *testing.T) {
		p := Scenario{ID: "bX", Kind: KindBad, Pending: "detector not merged",
			Expect: Expect{Signals: []ExpectSignal{{ID: "owner-change"}}}}
		o := Evaluate(p, report("ROUTINE"))
		if o.Status != StatusPending {
			t.Fatalf("want pending, got %s", o.Status)
		}
	})

	t.Run("forbidden signal on a bad scenario", func(t *testing.T) {
		b := Scenario{ID: "b17", Kind: KindBad, Forbid: []string{"remote-fetch-exec"},
			Expect: Expect{Signals: []ExpectSignal{{ID: "integrity-mismatch", MinSeverity: "critical"}}}}
		o := Evaluate(b, report("HOLD", f("integrity-mismatch", "critical"), f("remote-fetch-exec", "critical")))
		if len(o.Forbidden) != 1 {
			t.Fatalf("want a forbidden hit, got %v", o.Forbidden)
		}
		if o.Status == StatusCaught {
			t.Fatal("a forbidden hit must not count as caught")
		}
	})
}

func TestScoreboard(t *testing.T) {
	outcomes := []Outcome{
		Evaluate(Scenario{ID: "b01", Kind: KindBad, Title: "backdoor",
			Expect: Expect{Signals: []ExpectSignal{{ID: "remote-fetch-exec", MinSeverity: "critical"}}}},
			report("HOLD", f("remote-fetch-exec", "critical"))),
		Evaluate(Scenario{ID: "b02", Kind: KindBad, Title: "exfil",
			Expect: Expect{Signals: []ExpectSignal{{ID: "data-exfil", MinSeverity: "high"}}}},
			report("ROUTINE")),
		Evaluate(Scenario{ID: "g01", Kind: KindGood, Title: "feature"}, report("ROUTINE")),
		Evaluate(Scenario{ID: "g02", Kind: KindGood, Title: "noisy"}, report("REVIEW", f("data-exfil", "high"))),
	}
	md := Scoreboard(outcomes)
	for _, want := range []string{"## Scoreboard", "b01", "caught", "MISSED", "FALSE ALARM", "### Bad scenarios", "### Good scenarios"} {
		if !strings.Contains(md, want) {
			t.Errorf("scoreboard missing %q\n%s", want, md)
		}
	}
	tally := TallyOf(outcomes)
	if tally.Caught != 1 || tally.Missed != 1 || tally.Clean != 1 || tally.FalseAlarm != 1 {
		t.Errorf("tally: %+v", tally)
	}
	if tally.Pass() {
		t.Error("a tally with a miss and a false alarm must not pass")
	}
}
