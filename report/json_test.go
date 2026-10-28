// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package report

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
	_ "github.com/RhythmShahriar/sightread/policy" // the baseline reader, for the round trip
)

const schemaPath = "../docs/schema/rhythm-sightread-v1.json"

var testOpts = core.WriteOptions{Version: "1.0.0", Program: "rhythm sightread"}

func writeWith(t testing.TB, format string, r *core.Report, o core.WriteOptions) []byte {
	t.Helper()
	w := core.WriterFor(format)
	if w == nil {
		t.Fatalf("no %s writer registered", format)
	}
	var b bytes.Buffer
	if err := w.Write(&b, r, o); err != nil {
		t.Fatalf("%s: %v", format, err)
	}
	return b.Bytes()
}

func writeDoc(t testing.TB, env core.Envelope) []byte {
	t.Helper()
	dw, ok := core.WriterFor(core.FormatJSON).(DocumentWriter)
	if !ok {
		t.Fatal("the json writer is not a DocumentWriter")
	}
	var b bytes.Buffer
	if err := dw.WriteDocument(&b, env, testOpts); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// smallReport is a report with one clean update and nothing else.
func smallReport() *core.Report {
	r := &core.Report{Kind: core.KindReview, Target: core.Target{Path: "/srv/site", Kind: "npm"}, Started: coretest.SampleTime,
		Complete: true, Updates: []core.Update{{Eco: core.NPM, Name: "left-pad",
			From: core.Side{Version: "1.3.0", Verified: core.BySignature}, To: core.Side{Version: "1.3.1", Verified: core.BySignature},
			Verdict: core.Routine}}}
	coretest.FakeScorer{}.Summarise(r)
	r.Complete = true
	return r
}

// everyDocument is one document of every kind, the review ones built from
// SampleReport and a small fixture.
func everyDocument(t testing.TB) map[string][]byte {
	t.Helper()
	sample := coretest.SampleReport()
	sig, _ := core.Signal("eval-dynamic")
	f := sample.Updates[0].Findings[0]
	return map[string][]byte{
		"review sample": writeWith(t, core.FormatJSON, sample, testOpts),
		"review small":  writeWith(t, core.FormatJSON, smallReport(), testOpts),
		"review empty":  writeWith(t, core.FormatJSON, &core.Report{Kind: core.KindReview}, testOpts),
		"jsonl close":   writeWith(t, core.FormatJSONL, sample, testOpts),
		"allowed": writeDoc(t, core.Envelope{Kind: core.KindAllowed, Complete: true, Data: core.AllowedData{File: ".sightread/allowed.yaml",
			Entries: []core.AllowEntry{{Package: "npm:left-pad", Version: "1.3.1", SHA256: strings.Repeat("a", 64), Hash: core.HashArchive,
				Reason: "read the diff", By: "Ann", Date: "2026-10-20"}}}}),
		"allowed empty": writeDoc(t, core.Envelope{Kind: core.KindAllowed, Complete: true, Data: &core.AllowedData{}}),
		"watch": writeDoc(t, core.Envelope{Kind: core.KindWatch, Complete: true, Verdict: core.VerdictFindings,
			Summary: sample.Summary, Data: core.WatchData{Name: "nightly", Sites: 2, Updates: 6, Review: 1, Hold: 1, Report: "r.html"}}),
		"signals": writeDoc(t, core.Envelope{Kind: core.KindSignals, Complete: true, Data: core.SignalsData{Signals: core.Catalog}}),
		"explain": writeDoc(t, core.Envelope{Kind: core.KindExplain, Complete: true, Data: core.ExplainData{Signal: sig,
			Explain: core.Explain{Why: "Code built at run time can be anything."}}}),
		"explain finding": writeDoc(t, core.Envelope{Kind: core.KindExplain, Complete: true, Data: &core.ExplainData{Signal: sig,
			Finding: &f, Hunks: sample.Updates[0].Hunks}}),
		"doctor": writeDoc(t, core.Envelope{Kind: core.KindDoctor, Complete: true, Data: core.DoctorData{Checks: []core.DoctorCheck{
			{Name: "cache", Status: core.DoctorOK, Detail: "~/.cache/rhythm/sightread"}}}}),
		"verify": writeDoc(t, core.Envelope{Kind: core.KindVerify, Complete: true, Data: core.VerifyData{File: "r.json",
			Key: "ed25519:abc", Trusted: true, Valid: true}}),
	}
}

func TestEveryKindMatchesSchema(t *testing.T) {
	schema := loadSchema(t, schemaPath)
	if schema["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Errorf("$schema = %v", schema["$schema"])
	}
	kinds := map[string]bool{}
	for name, doc := range everyDocument(t) {
		if errs := validateStrict(schema, doc); len(errs) > 0 {
			t.Errorf("%s: %s\n%s", name, strings.Join(errs, "\n"), doc)
		}
		var head struct{ Kind string }
		_ = json.Unmarshal(doc, &head)
		kinds[head.Kind] = true
	}
	for _, k := range []string{core.KindReview, core.KindAllowed, core.KindWatch, core.KindSignals, core.KindExplain, core.KindDoctor, core.KindVerify} {
		if !kinds[k] {
			t.Errorf("no %s document was validated", k)
		}
	}
}

func TestJSONLLinesMatchSchema(t *testing.T) {
	schema := loadSchema(t, schemaPath)
	r := coretest.SampleReport()
	var b bytes.Buffer
	w := JSONLWriter{}
	for i := range r.Updates {
		if err := w.WriteUpdate(&b, &r.Updates[i], testOpts); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Write(&b, r, testOpts); err != nil {
		t.Fatal(err)
	}
	out := bytes.Clone(b.Bytes())
	sc := bufio.NewScanner(&b)
	sc.Buffer(nil, 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Bytes()
		if errs := validateStrict(schema, line); len(errs) > 0 {
			t.Errorf("line %d: %s\n%s", n, strings.Join(errs, "\n"), line)
		}
		var head struct {
			Kind string
			Data map[string]json.RawMessage
		}
		if err := json.Unmarshal(line, &head); err != nil {
			t.Fatalf("line %d: %v", n, err)
		}
		switch {
		case n <= len(r.Updates) && head.Kind != "update":
			t.Errorf("line %d kind %q, want update", n, head.Kind)
		case n == len(r.Updates)+1:
			if head.Kind != core.KindReview {
				t.Errorf("closing line kind %q", head.Kind)
			}
			if _, ok := head.Data["updates"]; ok {
				t.Errorf("the closing envelope repeats data.updates")
			}
		}
	}
	if n != len(r.Updates)+1 {
		t.Errorf("%d lines, want %d", n, len(r.Updates)+1)
	}
	coretest.Golden(t, "sample.jsonl", out)
}

// The validator must reject what the schema forbids, or the tests above
// prove nothing.
func TestSchemaRejectsDrift(t *testing.T) {
	schema := loadSchema(t, schemaPath)
	good := string(writeWith(t, core.FormatJSON, coretest.SampleReport(), testOpts))
	for name, doc := range map[string]string{
		"missing field":   strings.Replace(good, `"complete": false,`, "", 1),
		"unknown field":   strings.Replace(good, `"complete": false,`, `"complete": false, "surprise": 1,`, 1),
		"bad severity":    strings.Replace(good, `"severity": "critical"`, `"severity": "severe"`, 1),
		"string count":    strings.Replace(good, `"updates": 6`, `"updates": "6"`, 1),
		"bad verdict":     strings.Replace(good, `"verdict": "hold"`, `"verdict": "safe"`, 1),
		"null summary":    strings.Replace(good, `"critical": `, `"critical": null, "x": `, 1),
		"bad fingerprint": strings.Replace(good, `"fingerprint": "`, `"fingerprint": "zz`, 1),
		"wrong kind data": strings.Replace(good, `"kind": "review"`, `"kind": "doctor"`, 1),
	} {
		if doc == good {
			t.Fatalf("%s: the replacement did nothing", name)
		}
		if errs := validateStrict(schema, []byte(doc)); len(errs) == 0 {
			t.Errorf("%s: validated, want an error", name)
		}
	}
	extra := strings.Replace(good, `"complete": false,`, `"complete": false, "surprise": 1,`, 1)
	if errs := validate(schema, []byte(extra)); len(errs) > 0 {
		t.Errorf("published schema refuses a new field: %s", strings.Join(errs, "\n"))
	}
}

func TestJSONGolden(t *testing.T) {
	coretest.Golden(t, "sample.json", writeWith(t, core.FormatJSON, coretest.SampleReport(), testOpts))
	coretest.Golden(t, "small.json", writeWith(t, core.FormatJSON, smallReport(), testOpts))
}

func TestJSONFieldOrder(t *testing.T) {
	doc := string(writeWith(t, core.FormatJSON, smallReport(), testOpts))
	order := []string{`"schema"`, `"kind"`, `"tool"`, `"version"`, `"complete"`, `"summary"`, `"verdict"`, `"data"`,
		`"target"`, `"started"`, `"duration_ms"`, `"updates"`, `"ecosystem"`, `"from"`, `"to"`, `"installed"`,
		`"diff"`, `"findings"`, `"soundcheck"`, `"not_checked"`, `"warnings"`, `"errors"`, `"notes"`}
	last := -1
	for _, k := range order {
		i := strings.Index(doc[last+1:], k)
		if i < 0 {
			t.Fatalf("%s missing or out of order:\n%s", k, doc)
		}
		last += 1 + i
	}
	again := string(writeWith(t, core.FormatJSON, smallReport(), testOpts))
	if again != doc {
		t.Error("two writes of one report differ")
	}
}

// withoutHiddenFindings turns doc into a report written before hidden
// findings were kept: the findings marked hidden and the flag removed.
func withoutHiddenFindings(t *testing.T, doc []byte) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(doc, &m); err != nil {
		t.Fatal(err)
	}
	for _, u := range m["data"].(map[string]any)["updates"].([]any) {
		u := u.(map[string]any)
		var kept []any
		for _, f := range u["findings"].([]any) {
			f := f.(map[string]any)
			if f["hidden"] == true {
				continue
			}
			delete(f, "hidden")
			kept = append(kept, f)
		}
		u["findings"] = append([]any{}, kept...)
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestSummaryHasEveryKey(t *testing.T) {
	doc := writeWith(t, core.FormatJSON, &core.Report{Kind: core.KindReview}, testOpts)
	var r struct {
		Summary map[string]*int `json:"summary"`
	}
	if err := json.Unmarshal(doc, &r); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"updates", "hold", "review", "routine", "allowed", "unverified", "critical", "high", "medium",
		"low", "info", "baselined", "allowed_findings", "ignored", "demoted", "not_checked", "from_cache", "hidden",
		"counted", "counted_hidden", "not_counted_severe"} {
		if n := r.Summary[k]; n == nil || *n != 0 {
			t.Errorf("summary.%s = %v, want 0", k, n)
		}
	}
	if len(r.Summary) != 21 {
		t.Errorf("summary has %d keys, want 21", len(r.Summary))
	}
	if !bytes.Contains(doc, []byte(`"updates": []`)) || !bytes.Contains(doc, []byte(`"errors": []`)) {
		t.Errorf("empty lists are not written as []:\n%s", doc)
	}
}

func TestEnvelopeVerdict(t *testing.T) {
	counted := core.Finding{ID: "eval-dynamic", Severity: cli.SeverityHigh}
	allowed := counted
	allowed.Allowed = &core.AllowMatch{By: "a"}
	for _, c := range []struct {
		name string
		r    core.Report
		want string
	}{
		{"clean", core.Report{}, core.VerdictOK},
		{"counted finding", core.Report{Updates: []core.Update{{Findings: []core.Finding{counted}}}}, core.VerdictFindings},
		{"only allowed", core.Report{Updates: []core.Update{{Findings: []core.Finding{allowed}}}}, core.VerdictOK},
		{"findings beat errors", core.Report{Errors: []core.ErrorEntry{{Code: core.ENetwork}}, Updates: []core.Update{{Findings: []core.Finding{counted}}}}, core.VerdictFindings},
		{"report error", core.Report{Errors: []core.ErrorEntry{{Code: core.ENetwork}}}, core.VerdictError},
		{"update error", core.Report{Updates: []core.Update{{Errors: []core.ErrorEntry{{Code: core.EUnverifiable}}}}}, core.VerdictError},
		{"interrupted", core.Report{StoppedBy: "interrupted"}, core.VerdictError},
		{"not checked only", core.Report{NotChecked: []core.NotChecked{{Name: "x"}}}, core.VerdictOK},
		{"hidden counted finding", core.Report{Updates: []core.Update{{Hidden: []core.Finding{counted}}}}, core.VerdictFindings},
		{"blank hidden stand-in", core.Report{Updates: []core.Update{{Hidden: []core.Finding{{}}}}}, core.VerdictOK},
	} {
		if got := envelopeVerdict(&c.r); got != c.want {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
}

// TestJSONHiddenFindings: hidden findings stay in data.updates[].findings
// marked hidden. The summary counts them as the verdict does.
func TestJSONHiddenFindings(t *testing.T) {
	doc := writeWith(t, core.FormatJSON, hiddenReport(), testOpts)
	var r struct {
		Summary map[string]int `json:"summary"`
		Verdict string         `json:"verdict"`
		Data    struct {
			Updates []struct {
				Findings []struct {
					ID     string `json:"id"`
					Hidden bool   `json:"hidden"`
				} `json:"findings"`
				Hidden int `json:"hidden"`
			} `json:"updates"`
		} `json:"data"`
	}
	if err := json.Unmarshal(doc, &r); err != nil {
		t.Fatal(err)
	}
	fs := r.Data.Updates[0].Findings
	if len(fs) != 1 || fs[0].ID != "cron-new-hook" || !fs[0].Hidden || r.Data.Updates[0].Hidden != 1 {
		t.Errorf("findings %+v hidden %d, want the hidden finding marked", fs, r.Data.Updates[0].Hidden)
	}
	if s := r.Summary; s["low"] != 1 || s["counted"] != 1 || s["counted_hidden"] != 1 || s["hidden"] != 1 {
		t.Errorf("summary %v, want the hidden low finding counted", s)
	}
	if r.Verdict != core.VerdictFindings {
		t.Errorf("verdict %q, want findings", r.Verdict)
	}
}

func TestRedactPaths(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home folder")
	}
	site := filepath.Join(home, "sites", "shop")
	r := coretest.SampleReport()
	r.Target.Path = site
	r.Updates[0].Installed.Path = filepath.Join(site, "wp-content", "plugins", "x")
	r.Updates[0].Soundcheck = &core.SoundcheckResult{Report: filepath.Join(home, "reports", "sc.html")}
	r.Warnings = append(r.Warnings, "couldn't read "+filepath.Join(site, "wp-config.php"))
	// JSON escapes the backslashes of a Windows path, so look for home
	// as JSON writes it.
	q, _ := json.Marshal(home)
	jsonHome := q[1 : len(q)-1]
	o := testOpts
	o.RedactPaths = true
	doc := writeWith(t, core.FormatJSON, r, o)
	if bytes.Contains(doc, jsonHome) {
		t.Errorf("the home path is still in the report:\n%s", doc)
	}
	for _, want := range []string{`"path": "."`, `"path": "wp-content/plugins/x"`, `"report": "~/reports/sc.html"`, `couldn't read wp-config.php`} {
		if !bytes.Contains(doc, []byte(want)) {
			t.Errorf("redacted report lacks %s", want)
		}
	}
	plain := writeWith(t, core.FormatJSON, r, testOpts)
	if !bytes.Contains(plain, jsonHome) {
		t.Errorf("without RedactPaths the path should stay")
	}

	// JSONL update lines redact like json once they know the target.
	var line bytes.Buffer
	if err := (JSONLWriter{}).WriteUpdateIn(&line, &r.Updates[0], site, o); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(line.Bytes(), jsonHome) || !bytes.Contains(line.Bytes(), []byte(`"path":"wp-content/plugins/x"`)) {
		t.Errorf("jsonl line not redacted like json:\n%s", line.String())
	}
	// Without the target only the home prefix can go.
	line.Reset()
	if err := (JSONLWriter{}).WriteUpdate(&line, &r.Updates[0], o); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(line.Bytes(), []byte(`"path":"~/sites/shop/wp-content/plugins/x"`)) {
		t.Errorf("jsonl line without target:\n%s", line.String())
	}
}

func TestNoFakeSecrets(t *testing.T) {
	r := coretest.SampleReport()
	u := &r.Updates[1]
	u.Changelog = append(u.Changelog, core.ChangelogEntry{Version: "1.5.0", Text: "token " + coretest.FakeKey(coretest.KeyGitHub)})
	u.To.Publisher = []string{"ann <ann@example.com>"}
	u.Hunks = append(u.Hunks, core.Hunk{Path: "a.js", Lines: []string{"+const k = '" + coretest.FakeKey(coretest.KeyAWS) + "'"}})
	r.Warnings = append(r.Warnings, "slack "+coretest.FakeKey(coretest.KeySlack))
	for _, format := range core.Formats() {
		out := writeWith(t, format, r, testOpts)
		for _, kind := range coretest.FakeKeyKinds() {
			if bytes.Contains(out, []byte(coretest.FakeKey(kind))) {
				t.Errorf("%s: the fake %s key is in the output", format, kind)
			}
		}
		if bytes.Contains(out, []byte("ann@example.com")) {
			t.Errorf("%s: the e-mail address is not masked", format)
		}
	}
}

func TestReadReportRoundTrip(t *testing.T) {
	withFunc := coretest.SampleReport()
	withFunc.Updates[0].Findings[0].Func = "Share_Kit::sync"
	withFunc.Updates[0].Hunks = append(withFunc.Updates[0].Hunks, core.Hunk{Path: "dist/app.min.js", OldStart: 7, OldLines: 1,
		NewStart: 7, NewLines: 1, Tokens: true, Lines: []string{"-a;", "+b;"}})
	for name, r := range map[string]*core.Report{"sample": coretest.SampleReport(), "small": smallReport(),
		"empty": {Kind: core.KindReview}, "func": withFunc} {
		doc := writeWith(t, core.FormatJSON, r, testOpts)
		got, err := ReadReport(bytes.NewReader(doc))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !reflect.DeepEqual(got, r) {
			again := writeWith(t, core.FormatJSON, got, testOpts)
			t.Errorf("%s: the report read back differs:\n%s", name, firstLineDiff(doc, again))
		}
	}
	// Hidden findings come back whole, as hidden ones.
	hid := hiddenReport()
	got, err := ReadReport(bytes.NewReader(writeWith(t, core.FormatJSON, hid, testOpts)))
	if err != nil {
		t.Fatal(err)
	}
	if h := got.Updates[0].Hidden; len(h) != 1 || h[0].ID != "cron-new-hook" || h[0].Severity != cli.SeverityLow ||
		len(got.Updates[0].Findings) != len(hid.Updates[0].Findings) || got.Summary.Hidden != 1 || got.Summary.CountedHidden != 1 {
		t.Errorf("hidden read back as %+v, summary %+v", h, got.Summary)
	}
	// A report from before the hidden flag kept only their number: blank
	// findings stand in for them.
	got, err = ReadReport(bytes.NewReader(withoutHiddenFindings(t, writeWith(t, core.FormatJSON, hid, testOpts))))
	if err != nil {
		t.Fatal(err)
	}
	if h := got.Updates[0].Hidden; len(h) != 1 || h[0].Severity != cli.SeverityNone {
		t.Errorf("older hidden read back as %+v", h)
	}
	bad := bytes.ReplaceAll(writeWith(t, core.FormatJSON, hid, testOpts), []byte(`"hidden": 1`), []byte(`"hidden": -1`))
	if _, err := ReadReport(bytes.NewReader(bad)); err == nil || !strings.Contains(err.Error(), "hidden -1") {
		t.Errorf("negative hidden: %v", err)
	}
	// Through the registry, as cmd reads it.
	if _, err := core.ReadReport(bytes.NewReader(writeWith(t, core.FormatJSON, smallReport(), testOpts))); err != nil {
		t.Fatal(err)
	}
}

func firstLineDiff(a, b []byte) string {
	al, bl := strings.Split(string(a), "\n"), strings.Split(string(b), "\n")
	for i := range min(len(al), len(bl)) {
		if al[i] != bl[i] {
			return al[i] + "\n" + bl[i]
		}
	}
	return "(the JSON is the same; a field the writer leaves out differs)"
}

func TestReadReportErrors(t *testing.T) {
	good := string(writeWith(t, core.FormatJSON, smallReport(), testOpts))
	dir := t.TempDir()
	t.Chdir(dir)
	for _, c := range []struct{ name, doc, want string }{
		{"other schema", `{"schema":"rhythm-tuner/v1","kind":"review"}`, "x.json is not a rhythm-sightread report"},
		{"no schema", `{}`, "x.json is not a rhythm-sightread report"},
		{"other kind", strings.Replace(good, `"kind": "review"`, `"kind": "allowed"`, 1), `x.json is a rhythm-sightread "allowed" document, not a review report`},
		{"corrupt", `{"schema": "rhythm-sightread/v1", "kind": `, "x.json is not valid JSON (the file ends early)"},
		{"not json", `hello`, "x.json is not valid JSON (invalid character 'h' looking for beginning of value)"},
		{"unknown field", strings.Replace(good, `"complete": true,`, `"complete": true, "surprise": 1,`, 1), `x.json is not a rhythm-sightread review report (unknown field "surprise")`},
		{"unknown data field", strings.Replace(good, `"duration_ms"`, `"surprise": 1, "duration_ms"`, 1), `x.json is not a rhythm-sightread review report (unknown field "surprise")`},
		{"bad severity", strings.Replace(writeOne(t), `"severity": "high"`, `"severity": "severe"`, 1), `x.json is not a rhythm-sightread review report (data.updates[0]: findings[0]: severity "severe": want info, low, medium, high or critical)`},
		{"bad time", strings.Replace(good, `"started": "2026-10-26T09:12:03Z"`, `"started": "yesterday"`, 1), `x.json is not a rhythm-sightread review report (data.started "yesterday" is not an RFC 3339 time)`},
	} {
		path := filepath.Join(dir, "x.json")
		if err := os.WriteFile(path, []byte(c.doc), 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path) //nolint:gosec // the test's own file
		if err != nil {
			t.Fatal(err)
		}
		_, err = ReadReport(f)
		_ = f.Close()
		var e *core.Error
		if !errors.As(err, &e) {
			t.Fatalf("%s: %v, want a *core.Error", c.name, err)
		}
		if e.Code != core.EBadConfig || e.ExitCode() != cli.ExitUsage {
			t.Errorf("%s: code %s exit %d", c.name, e.Code, e.ExitCode())
		}
		if e.What != c.want {
			t.Errorf("%s:\n got %q\nwant %q", c.name, e.What, c.want)
		}
		if len(e.Hint) != 1 || e.Hint[0] != "give the JSON a review wrote, such as -o sightread.json" {
			t.Errorf("%s: hint %q", c.name, e.Hint)
		}
	}
	// A reader without a name.
	_, err := ReadReport(strings.NewReader(`{}`))
	if err == nil || !strings.Contains(err.Error(), "the report is not a rhythm-sightread report") {
		t.Errorf("unnamed reader: %v", err)
	}
}

// writeOne is a review whose only finding is high.
func writeOne(t *testing.T) string {
	r := smallReport()
	r.Updates[0].Findings = []core.Finding{{ID: "eval-dynamic", Title: "Runs code built at run time", Severity: cli.SeverityHigh,
		Confidence: core.Confirmed, Fingerprint: "0123456789abcdef"}}
	return string(writeWith(t, core.FormatJSON, r, testOpts))
}

func TestBaselineReadsTheWriterOutput(t *testing.T) {
	p := core.GetPolicy()
	if p == nil {
		t.Skip("policy not linked in this test binary")
	}
	r := coretest.SampleReport()
	path := filepath.Join(t.TempDir(), "base.json")
	if err := os.WriteFile(path, writeWith(t, core.FormatJSON, r, testOpts), 0o600); err != nil {
		t.Fatal(err)
	}
	set, err := p.LoadBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, u := range r.Updates {
		for _, f := range u.Findings {
			n++
			if !set[f.Fingerprint] {
				t.Errorf("%s %s missing from the baseline", u.Name, f.ID)
			}
		}
	}
	if len(set) == 0 || len(set) > n {
		t.Errorf("%d fingerprints for %d findings", len(set), n)
	}
}

func TestWriteDocumentRefusesUnknownData(t *testing.T) {
	var b bytes.Buffer
	err := JSONWriter{}.WriteDocument(&b, core.Envelope{Kind: core.KindDoctor, Data: map[string]int{}}, testOpts)
	if err == nil || !strings.Contains(err.Error(), "no JSON form for map[string]int") {
		t.Errorf("err = %v", err)
	}
	if err := (JSONWriter{}).WriteDocument(&b, core.Envelope{}, testOpts); err == nil {
		t.Error("a document without a kind was written")
	}
}

func TestTimesAreUTC(t *testing.T) {
	r := smallReport()
	r.Started = time.Date(2026, 10, 26, 11, 12, 3, 0, time.FixedZone("CEST", 2*3600))
	doc := writeWith(t, core.FormatJSON, r, testOpts)
	if !bytes.Contains(doc, []byte(`"started": "2026-10-26T09:12:03Z"`)) {
		t.Errorf("started not in UTC:\n%s", doc)
	}
}

// TestJSONSoundcheckNotCompared: a --soundcheck run that stopped before
// the comparison writes summary null and its error. It reads back the
// same; a finished one keeps its zero counts.
func TestJSONSoundcheckNotCompared(t *testing.T) {
	r := coretest.SampleReport()
	r.Updates[0].Soundcheck = &core.SoundcheckResult{Staging: "https://staging.example", NotCompared: true,
		Error: "rhythm-soundcheck compare couldn't run"}
	doc := writeWith(t, core.FormatJSON, r, testOpts)
	for _, want := range []string{`"summary": null`, `"error": "rhythm-soundcheck compare couldn't run"`} {
		if !bytes.Contains(doc, []byte(want)) {
			t.Errorf("missing %s in\n%s", want, doc)
		}
	}
	if errs := validateStrict(loadSchema(t, schemaPath), doc); len(errs) > 0 {
		t.Errorf("schema: %v", errs)
	}
	back, err := ReadReport(bytes.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	if sc := back.Updates[0].Soundcheck; sc == nil || !sc.NotCompared || sc.Error != "rhythm-soundcheck compare couldn't run" {
		t.Errorf("read back %+v", sc)
	}
	r.Updates[0].Soundcheck = &core.SoundcheckResult{Staging: "https://staging.example"}
	doc = writeWith(t, core.FormatJSON, r, testOpts)
	if !bytes.Contains(doc, []byte(`"broke": 0`)) || !bytes.Contains(doc, []byte(`"error": ""`)) {
		t.Errorf("a finished comparison lost its counts:\n%s", doc)
	}
	if errs := validateStrict(loadSchema(t, schemaPath), doc); len(errs) > 0 {
		t.Errorf("schema: %v", errs)
	}
}

// TestReplacePrefix: a path in a message loses its prefix and keeps
// forward slashes up to the punctuation that ends it.
func TestReplacePrefix(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"can't read /home/u/other/x.php: denied", "can't read ~/other/x.php: denied"},
		{"\"/home/u/a b\" and /home/u/c, /home/u/d)", "\"~/a b\" and ~/c, ~/d)"},
		{"nothing here", "nothing here"},
	} {
		if got := replacePrefix(c.in, "/home/u/", "~/"); got != c.want {
			t.Errorf("replacePrefix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
