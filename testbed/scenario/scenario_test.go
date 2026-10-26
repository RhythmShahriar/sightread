// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package scenario

import (
	"fmt"
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
// exists, that every expected and forbidden signal is a catalogue id
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

// TestLoadRejectsUnusedExpectations keeps the manifest honest: an
// assertion the evaluator would ignore is an error, not a comment.
func TestLoadRejectsUnusedExpectations(t *testing.T) {
	cases := map[string]string{
		"env with expect.exit":  "  - {id: e01, kind: env, command: [x], expect: {exit: 0}, env: {exit: 3}}\n",
		"exact on a bad one":    "  - {id: b01, kind: bad, command: [x], expect: {exact: true, signals: [{id: owner-change}]}}\n",
		"exact with no signals": "  - {id: g15, kind: good, command: [x], expect: {exact: true}}\n",
	}
	for name, entry := range cases {
		p := filepath.Join(t.TempDir(), "scenarios.yaml")
		if err := os.WriteFile(p, []byte("scenarios:\n"+entry), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Errorf("%s: Load accepted it", name)
		}
	}
	ok := "  - {id: e01, kind: env, command: [x], env: {exit: 3}}\n" +
		"  - {id: g15, kind: good, command: [x], expect: {exit: 1, exact: true, signals: [{id: owner-change}]}}\n"
	p := filepath.Join(t.TempDir(), "scenarios.yaml")
	if err := os.WriteFile(p, []byte("scenarios:\n"+ok), 0o600); err != nil {
		t.Fatal(err)
	}
	m, err := Load(p)
	if err != nil {
		t.Fatalf("a valid manifest was rejected: %v", err)
	}
	if got := m.Scenarios[1].Expect.WantExit(); got != 1 {
		t.Errorf("WantExit = %d, want 1", got)
	}
	if got := m.Scenarios[0].Expect.WantExit(); got != 0 {
		t.Errorf("WantExit with no exit = %d, want 0", got)
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

	exact := Scenario{ID: "g15", Kind: KindGood, FailOn: "high",
		Expect: Expect{Exact: true, Signals: []ExpectSignal{{ID: "owner-change", MinSeverity: "high"}}}}
	t.Run("exact clean with only its signal", func(t *testing.T) {
		o := Evaluate(exact, report("REVIEW", f("owner-change", "high")))
		if o.Status != StatusClean {
			t.Fatalf("owner-change alone is clean, got %s %v %v", o.Status, o.FalseAlarms, o.Missing)
		}
	})
	t.Run("exact flags an extra finding below the gate", func(t *testing.T) {
		o := Evaluate(exact, report("REVIEW", f("owner-change", "high"), f("cron-new-hook", "low")))
		if o.Status != StatusFalseAlarm || len(o.FalseAlarms) != 1 || o.FalseAlarms[0] != "cron-new-hook" {
			t.Fatalf("a low extra finding breaks an exact scenario, got %s %v", o.Status, o.FalseAlarms)
		}
	})
	t.Run("exact requires its signal", func(t *testing.T) {
		o := Evaluate(exact, report("ROUTINE"))
		if o.Status != StatusMissed || len(o.Missing) != 1 {
			t.Fatalf("an exact scenario without owner-change is missed, got %s %v", o.Status, o.Missing)
		}
		o = Evaluate(exact, report("REVIEW", f("owner-change", "medium")))
		if o.Status != StatusMissed {
			t.Fatalf("owner-change below its rank is missed, got %s", o.Status)
		}
	})
	t.Run("non-exact good does not require its signal", func(t *testing.T) {
		g05 := Scenario{ID: "g05", Kind: KindGood, Expect: Expect{Signals: []ExpectSignal{{ID: "cron-new-hook", MinSeverity: "low"}}}}
		if o := Evaluate(g05, report("ROUTINE")); o.Status != StatusClean {
			t.Fatalf("an allowed signal may be absent, got %s", o.Status)
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

// TestScoreboardNoReport shows a run without a report apart: not a miss,
// not a false alarm and never a pass.
func TestScoreboardNoReport(t *testing.T) {
	outcomes := []Outcome{
		{Scenario: Scenario{ID: "b01", Kind: KindBad, Title: "backdoor"}, Status: StatusNoReport},
		{Scenario: Scenario{ID: "g01", Kind: KindGood, Title: "feature"}, Status: StatusNoReport},
	}
	tally := TallyOf(outcomes)
	if tally.NoReport != 2 || tally.Missed != 0 || tally.FalseAlarm != 0 {
		t.Errorf("tally: %+v", tally)
	}
	if tally.Pass() {
		t.Error("runs without a report must not pass")
	}
	md := Scoreboard(outcomes)
	for _, want := range []string{"no report 2", "NO REPORT", "### No report"} {
		if !strings.Contains(md, want) {
			t.Errorf("scoreboard missing %q\n%s", want, md)
		}
	}
	if strings.Contains(md, "FALSE ALARM") || strings.Contains(md, "MISSED") {
		t.Errorf("a missing report was shown as a miss or a false alarm\n%s", md)
	}

	clean := TallyOf([]Outcome{{Scenario: Scenario{ID: "g01", Kind: KindGood}, Status: StatusClean}})
	if !clean.Pass() || strings.Contains(Scoreboard([]Outcome{{Scenario: Scenario{ID: "g01", Kind: KindGood}, Status: StatusClean}}), "### No report") {
		t.Error("a clean run shows a no-report section or fails")
	}
}

// TestREADMEListsEveryScenario keeps the README scenario table in step
// with the manifest.
func TestREADMEListsEveryScenario(t *testing.T) {
	m, err := Load("../scenarios.yaml")
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatal(err)
	}
	readme := string(b)
	for _, s := range m.Scenarios {
		row := fmt.Sprintf("| %s | %s | %s |", s.ID, s.Kind, s.Title)
		if !strings.Contains(readme, row) {
			t.Errorf("README has no row starting %q", row)
		}
	}
}
