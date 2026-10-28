// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package benchdoc

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// passing is a complete run where nothing fails. e13 is not run, as on
// any machine but Windows; ranEverything runs it too.
func passing() *Results {
	ok := func(id, kind, status string, exit int) ScenarioResult {
		return ScenarioResult{ID: id, Kind: kind, Title: id + " title", Status: status, Verdict: "HOLD", WantVerdict: "HOLD",
			Exit: exit, WantExit: exit, NotCheckedOK: true, WarmStatus: status, WarmExit: exit,
			Cold: Timing{Seconds: 0.8, RSSMB: 60}, Warm: Timing{Seconds: 0.2, RSSMB: 40},
			Tools: map[string]string{"npm audit": ToolMissed}}
	}
	g := ok("g01", "good", "clean", 0)
	g.Verdict, g.WantVerdict = "ROUTINE", "ROUTINE"
	return &Results{
		Schema:    Schema,
		Started:   time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC),
		Seconds:   252,
		Version:   "rhythm-sightread 1.0.0",
		Machine:   "linux/amd64, 4 CPUs",
		Scenarios: []ScenarioResult{ok("b01", "bad", "caught", 1), g},
		Control:   Control{Rounds: 10, Runs: 10},
		Env:       []EnvResult{{ID: "e01", Title: "registry down", Result: ResultPass}, {ID: "e13", Title: "Windows", Result: ResultNotRun, Notes: []string{"Windows only"}}},
		Staging:   []EnvResult{{ID: "applies", Title: "update lands in the container", Result: ResultPass}},
		Large:     Large{Ran: true, Files: 4021, MB: 41, Cold: Timing{3, 300}, Warm: Timing{1.5, 280}},
		Tools:     []Tool{{Name: "npm audit", Version: "11.0.0", Scope: "npm lockfiles"}, {Name: "GuardDog", NotRun: "not installed", Scope: "npm tarballs"}},
	}
}

// ranEverything is passing with every environment scenario run: it
// meets every target.
func ranEverything() *Results {
	r := passing()
	r.Env[1].Result, r.Env[1].Notes = ResultPass, nil
	return r
}

func TestPassingRunMeetsEveryTarget(t *testing.T) {
	r := ranEverything()
	for _, tg := range r.Targets() {
		if !tg.Met || tg.NotRun != "" || tg.Result() != "met" {
			t.Errorf("%s not met: %s", tg.Name, tg.Detail)
		}
	}
	if !r.Met() || len(r.Failed()) != 0 {
		t.Error("Met() = false for a passing run")
	}
	if page := Render(r, CorpusBlock("")); !strings.Contains(page, "**Every target is met.**") {
		t.Error("a run that met every target does not say so")
	}
	r.Partial = true
	if r.Met() {
		t.Error("a partial run claimed the targets")
	}
}

// TestNotRunIsNeverMet: a target whose cases did not all run is reported
// as not run, never as met, though nothing failed.
func TestNotRunIsNeverMet(t *testing.T) {
	r := passing()
	if r.Met() {
		t.Error("Met() = true with e13 not run")
	}
	if f := r.Failed(); len(f) != 0 {
		t.Errorf("not run counted as a failure: %+v", f)
	}
	nr := r.NotRunTargets()
	if len(nr) != 1 || nr[0].Name != "Every environment scenario passes" || nr[0].NotRun != "e13" || nr[0].Result() != "not run" {
		t.Errorf("not run targets %+v", nr)
	}
	page := Render(r, CorpusBlock(""))
	if strings.Contains(page, "**Every target is met.**") || strings.Contains(page, "| Every environment scenario passes | met |") {
		t.Errorf("a run with e13 not run claims every target:\n%s", page)
	}
	for _, want := range []string{"**Not every target was run, so not every target is met.**",
		"Not run on this machine: Every environment scenario passes (e13).",
		"| Every environment scenario passes | not run | 2 of 3 passed; failed: none; not run here: e13 |"} {
		if !strings.Contains(page, want) {
			t.Errorf("page misses %q", want)
		}
	}
}

func TestEachFailureBreaksATarget(t *testing.T) {
	cases := map[string]func(r *Results){
		"missed":          func(r *Results) { r.Scenarios[0].Status, r.Scenarios[0].WarmStatus = "missed", "missed" },
		"false alarm":     func(r *Results) { r.Scenarios[1].Status, r.Scenarios[1].WarmStatus = "false-alarm", "false-alarm" },
		"exit":            func(r *Results) { r.Scenarios[0].Exit, r.Scenarios[0].WarmExit = 0, 0 },
		"verdict":         func(r *Results) { r.Scenarios[0].Verdict = "REVIEW" },
		"not checked":     func(r *Results) { r.Scenarios[0].NotCheckedOK = false },
		"control":         func(r *Results) { r.Control.FalseAlarms = 1 },
		"no control":      func(r *Results) { r.Control.Rounds = 0 },
		"unstable":        func(r *Results) { r.Control.Unstable = []string{"g01"} },
		"canary":          func(r *Results) { r.Safety.CanaryConnections = 1 },
		"canary file":     func(r *Results) { r.Safety.CanaryFiles = []string{"b10"} },
		"egress":          func(r *Results) { r.Safety.Egress = []string{"CONNECT registry.npmjs.org:443 HTTP/1.1"} },
		"outside":         func(r *Results) { r.Safety.OutsideWrites = []string{"b01: added: .config/x"} },
		"unmasked":        func(r *Results) { r.Safety.Unmasked = []string{"b11: report"} },
		"token forwarded": func(r *Results) { r.Safety.Forwarded = []string{"GET localhost:18908/vendor/example/legacy.zip/abc"} },
		"env":             func(r *Results) { r.Env[0].Result = ResultFail },
		"staging":         func(r *Results) { r.Staging[0].Result = ResultFail },
		"cold != warm":    func(r *Results) { r.Scenarios[0].WarmStatus = "missed" },
		"large slow":      func(r *Results) { r.Large.Warm.Seconds = 12 },
		"large big":       func(r *Results) { r.Large.Cold.RSSMB = 600 },
		"large failed":    func(r *Results) { r.Large.Exit = 3 },
		"large absent":    func(r *Results) { r.Large = Large{Note: "binary missing"} },
		"slow bench":      func(r *Results) { r.Seconds = 601 },
		"no binary":       func(r *Results) { r.BinErr = "go build failed" },
		"no report":       func(r *Results) { r.Scenarios[1].Status, r.Scenarios[1].WarmStatus = "no-report", "no-report" },
	}
	for name, breakIt := range cases {
		r := ranEverything()
		breakIt(r)
		if r.Met() || len(r.Failed()) == 0 {
			t.Errorf("%s: the run still meets every target", name)
		}
	}
	// A pending scenario is shown apart and does not fail the gate.
	r := passing()
	r.Scenarios[0].Status, r.Scenarios[0].Pending, r.Scenarios[0].Exit = "pending", "detector not merged", 0
	r.Scenarios[0].WarmStatus, r.Scenarios[0].WarmExit = "pending", 0
	if len(r.Failed()) != 0 {
		t.Errorf("a pending scenario broke the gate: %+v", r.Targets())
	}
}

func TestRender(t *testing.T) {
	r := passing()
	page := Render(r, CorpusBlock(""))
	for _, want := range []string{
		"# Sightread benchmark\n\n" + Header + "\n\n" + Framing,
		"| Binary | rhythm-sightread 1.0.0 |",
		"**Not every target was run, so not every target is met.**",
		"## Scoreboard",
		"| b01 | b01 title | caught |",
		"## False alarms",
		"Control pass: every good scenario again 10 times",
		"| Canary connections | 0 | 0 |",
		"## Environment scenarios",
		"| e13 | Windows | not run | Windows only |",
		"## --soundcheck end to end (e15)",
		"## Reproducibility",
		"p01-large (4021 files, 41 MB",
		"| Scenario | Sightread | npm audit | GuardDog |",
		"| b01 | **caught** | missed | not run |",
		"GuardDog not run (not installed)",
		"## Known gaps",
		CorpusStart,
		"Not run yet.",
		CorpusEnd,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("page misses %q", want)
		}
	}
	if strings.Contains(page, "\u2014") {
		t.Error("the page holds an em dash")
	}

	r.Safety.Egress = []string{"CONNECT api.wordpress.org:443 HTTP/1.1"}
	r.Scenarios[0].Problem = "no JSON report: exit 2"
	page = Render(r, CorpusBlock(""))
	for _, want := range []string{"**Not every target is met.**", "**NOT MET**", "- `CONNECT api.wordpress.org:443 HTTP/1.1`", "| b01 | no JSON report: exit 2 |"} {
		if !strings.Contains(page, want) {
			t.Errorf("failing page misses %q", want)
		}
	}
}

func TestCorpusBlockSurvivesRegeneration(t *testing.T) {
	r := passing()
	page := Render(r, CorpusBlock(""))
	section := "## Real releases (owner-run)\n\nFetched 2026-10-20.\n"
	page = SpliceCorpus(page, section)
	if !strings.Contains(page, "Fetched 2026-10-20.") || strings.Contains(page, "Not run yet.") {
		t.Fatalf("splice did not replace the placeholder:\n%s", page)
	}
	// The bench regenerates the page and keeps the block.
	again := Render(r, CorpusBlock(page))
	if !strings.Contains(again, "Fetched 2026-10-20.") || strings.Count(again, CorpusStart) != 1 {
		t.Errorf("the corpus block was lost or doubled:\n%s", again)
	}
	// A page without markers gets the block appended.
	if got := SpliceCorpus("# Page\n", section); !strings.HasSuffix(got, CorpusEnd+"\n") || !strings.HasPrefix(got, "# Page\n\n"+CorpusStart) {
		t.Errorf("append form: %q", got)
	}
}

func TestDiffAndReadWrite(t *testing.T) {
	a, b := passing(), passing()
	b.Scenarios[0].Cold.Seconds = 9 // times never count
	var out bytes.Buffer
	if !Diff(a, b, &out) || !strings.Contains(out.String(), "identical") {
		t.Errorf("identical runs differ:\n%s", out.String())
	}
	b.Scenarios[0].Status = "missed"
	b.Env[0].Result = ResultFail
	out.Reset()
	if Diff(a, b, &out) {
		t.Fatal("different runs are identical")
	}
	for _, want := range []string{"scenario b01: caught exit 1 verdict HOLD -> missed exit 1 verdict HOLD", "env e01: pass -> fail"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("diff misses %q:\n%s", want, out.String())
		}
	}

	path := filepath.Join(t.TempDir(), "results.json")
	if err := a.Write(path); err != nil {
		t.Fatal(err)
	}
	back, err := Read(path)
	if err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if !Diff(a, back, &out) {
		t.Errorf("a written run reads back different:\n%s", out.String())
	}
	a.Schema = "other/v1"
	if err := a.Write(path); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err == nil {
		t.Error("Read accepted a foreign schema")
	}
}

// TestPartialFailures decides a partial run's exit: clean when what ran
// passed, failing on any scenario, environment or safety problem.
func TestPartialFailures(t *testing.T) {
	r := passing()
	r.Partial = true
	if got := r.PartialFailures(); len(got) != 0 {
		t.Fatalf("a passing partial run lists failures: %v", got)
	}
	// e13 not run on this machine is not a failure of a partial run.
	cases := map[string]func(r *Results){
		"missed":    func(r *Results) { r.Scenarios[0].Status = "missed" },
		"no report": func(r *Results) { r.Scenarios[1].Status = "no-report" },
		"exit":      func(r *Results) { r.Scenarios[0].Exit = 3 },
		"env":       func(r *Results) { r.Env[0].Result = ResultFail },
		"staging":   func(r *Results) { r.Staging[0].Result = ResultFail },
		"canary":    func(r *Results) { r.Safety.CanaryConnections = 1 },
		"binary":    func(r *Results) { r.BinErr = "go build failed" },
	}
	for name, breakIt := range cases {
		r := passing()
		r.Partial = true
		breakIt(r)
		if len(r.PartialFailures()) == 0 {
			t.Errorf("%s: no failure listed", name)
		}
	}
	r = passing()
	r.Partial = true
	r.Scenarios[0].Status, r.Scenarios[0].Pending = "missed", "detector not merged"
	if got := r.PartialFailures(); len(got) != 0 {
		t.Errorf("a pending scenario failed a partial run: %v", got)
	}
}

// TestNoReportNotCheckedMessage: a run without a report that expects no
// Not checked reason is not told one is missing.
func TestNoReportNotCheckedMessage(t *testing.T) {
	s := ScenarioResult{ID: "g01", Kind: "good", Status: "no-report", Exit: 2, WantExit: 0, NotCheckedOK: true}
	for _, m := range s.Mismatch() {
		if strings.Contains(m, "Not checked") {
			t.Errorf("unexpected %q", m)
		}
	}
}
