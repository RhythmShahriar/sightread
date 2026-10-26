// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

const sarifSchemaPath = "testdata/sarif-2.1.0-subset.json"

func readSARIF(t *testing.T, doc []byte) sarifLog {
	t.Helper()
	var l sarifLog
	if err := json.Unmarshal(doc, &l); err != nil {
		t.Fatalf("%v\n%s", err, doc)
	}
	if len(l.Runs) != 1 {
		t.Fatalf("%d runs, want 1", len(l.Runs))
	}
	return l
}

func TestSARIFGoldenAndSchema(t *testing.T) {
	doc := writeWith(t, core.FormatSARIF, coretest.SampleReport(), testOpts)
	coretest.Golden(t, "sample.sarif", doc)
	schema := loadSchema(t, sarifSchemaPath)
	if errs := validateStrict(schema, doc); len(errs) > 0 {
		t.Errorf("%s", strings.Join(errs, "\n"))
	}
	// The validator must catch what the schema forbids.
	for name, bad := range map[string]string{
		"no fingerprint": strings.Replace(string(doc), `"sightreadFinding/v1"`, `"other/v1"`, 1),
		"bad level":      strings.Replace(string(doc), `"level": "error"`, `"level": "fatal"`, 1),
		"file uri":       strings.Replace(string(doc), `"uri": "package-lock.json"`, `"uri": "file:///etc/passwd"`, 1),
	} {
		if bad == string(doc) {
			t.Fatalf("%s: the replacement did nothing", name)
		}
		if errs := validateStrict(schema, []byte(bad)); len(errs) == 0 {
			t.Errorf("%s: validated, want an error", name)
		}
	}
}

func TestSARIFResults(t *testing.T) {
	r := coretest.SampleReport()
	l := readSARIF(t, writeWith(t, core.FormatSARIF, r, testOpts))
	run := l.Runs[0]
	if run.Tool.Driver.Name != "rhythm-sightread" || run.Tool.Driver.Version != "1.0.0" {
		t.Errorf("driver %+v", run.Tool.Driver)
	}
	counted := 0
	for _, u := range r.Updates {
		for _, f := range u.Findings {
			if f.Counted() {
				counted++
			}
		}
	}
	if len(run.Results) != counted {
		t.Errorf("%d results, want the %d counted findings", len(run.Results), counted)
	}
	rules := map[string]sarifRule{}
	for _, rule := range run.Tool.Driver.Rules {
		rules[rule.ID] = rule
	}
	byFP := map[string]sarifResult{}
	for _, res := range run.Results {
		byFP[res.PartialFingerprints[core.FingerprintKey]] = res
		if _, ok := rules[res.RuleID]; !ok {
			t.Errorf("result %s has no rule", res.RuleID)
		}
	}
	// Left out: allowed, ignored, baselined and below confidence.
	for _, u := range r.Updates {
		for _, f := range u.Findings {
			if _, in := byFP[f.Fingerprint]; in != f.Counted() {
				t.Errorf("%s %s (%s): in SARIF %v, counted %v", u.Name, f.ID, f.File, in, f.Counted())
			}
		}
	}
	rule := rules["remote-fetch-exec"]
	if rule.ShortDescription.Text != "Fetches remote code and runs it" || rule.DefaultConfiguration.Level != "error" ||
		rule.Properties["security-severity"] != "9.5" ||
		rule.HelpURI != "https://github.com/RhythmShahriar/rhythm/wiki/Sightread-Signal-Reference#remote-fetch-exec" {
		t.Errorf("rule %+v", rule)
	}
	if rules["fresh-release"].DefaultConfiguration.Level != "warning" || rules["license-change"].DefaultConfiguration.Level != "note" {
		t.Error("rule default levels")
	}
	hold := r.Updates[0]
	res := byFP[hold.Findings[0].Fingerprint]
	f := hold.Findings[0]
	want := "countdown-timer-ultimate 2.6.7 → 2.6.8: " + f.Title + " (" + f.File + ":10). Verdict HOLD."
	if res.Message.Text != want {
		t.Errorf("message\n got %q\nwant %q", res.Message.Text, want)
	}
	if res.Properties["package_path"] != f.File || res.Properties["verdict"] != "hold" || res.Properties["ecosystem"] != "wp-plugin" ||
		res.Properties["from"] != "2.6.7" || res.Properties["to"] != "2.6.8" || res.Properties["package"] != "countdown-timer-ultimate" {
		t.Errorf("properties %v", res.Properties)
	}
	// The site at /var/www/shop is not in a repository: the target folder.
	if loc := res.Locations[0].PhysicalLocation; loc.ArtifactLocation.URI != "." || loc.ArtifactLocation.URIBaseID != "SRCROOT" || loc.Region != nil {
		t.Errorf("wp-plugin location %+v", loc)
	}
}

func TestSARIFLevels(t *testing.T) {
	for sev, want := range map[cli.Severity]string{cli.SeverityCritical: "error", cli.SeverityHigh: "error",
		cli.SeverityMedium: "warning", cli.SeverityLow: "note", cli.SeverityInfo: "note"} {
		if got := sarifLevel(sev); got != want {
			t.Errorf("%s: %s, want %s", sev, got, want)
		}
	}
}

func TestSARIFLockfileLocation(t *testing.T) {
	r := coretest.SampleReport()
	l := readSARIF(t, writeWith(t, core.FormatSARIF, r, testOpts))
	locs := map[string]sarifPhysical{}
	for _, res := range l.Runs[0].Results {
		locs[res.Properties["package"].(string)] = res.Locations[0].PhysicalLocation
	}
	for name, want := range map[string]struct {
		uri  string
		line int
	}{"@acme/widgets": {"package-lock.json", 42}, "monolog/monolog": {"composer.lock", 7}} {
		got, ok := locs[name]
		if !ok {
			t.Fatalf("no result for %s", name)
		}
		if got.ArtifactLocation.URI != want.uri || got.Region == nil || got.Region.StartLine != want.line {
			t.Errorf("%s: %+v %+v, want %s:%d", name, got.ArtifactLocation, got.Region, want.uri, want.line)
		}
	}
}

func TestSARIFLocationInRepository(t *testing.T) {
	repo := t.TempDir()
	site := filepath.Join(repo, "site")
	for _, p := range []string{".git", "site/wp-content/plugins/hello", "site/wp-content/plugins/odd", "site/wp-content/themes/neve", "site/web"} {
		if err := os.MkdirAll(filepath.Join(repo, filepath.FromSlash(p)), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	for p, body := range map[string]string{
		"site/wp-content/plugins/hello/hello.php":  "<?php\n/* Plugin Name: Hello */",
		"site/wp-content/plugins/odd/a-readme.php": "<?php // nothing",
		"site/wp-content/plugins/odd/main.php":     "<?php\n/**\n * Plugin Name: Odd\n */",
		"site/wp-content/themes/neve/style.css":    "/* Theme Name: Neve */",
	} {
		if err := os.WriteFile(filepath.Join(repo, filepath.FromSlash(p)), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	finding := core.Finding{ID: "eval-dynamic", Title: "Runs code built at run time", Severity: cli.SeverityHigh, File: "x.php", Line: 3}
	up := func(eco core.Ecosystem, name string, inst core.InstalledInfo) core.Update {
		return core.Update{Eco: eco, Name: name, From: core.Side{Version: "1"}, To: core.Side{Version: "2"}, Verdict: core.Review,
			Installed: inst, Findings: []core.Finding{finding}}
	}
	r := &core.Report{Kind: core.KindReview, Target: core.Target{Path: site}, Updates: []core.Update{
		up(core.WPPlugin, "hello", core.InstalledInfo{Path: "wp-content/plugins/hello"}),
		up(core.WPPlugin, "odd", core.InstalledInfo{Path: "wp-content/plugins/odd"}),
		up(core.WPTheme, "neve", core.InstalledInfo{Path: "wp-content/themes/neve"}),
		up(core.WPPlugin, "gone", core.InstalledInfo{Path: "wp-content/plugins/gone"}),
		up(core.NPM, "left-pad", core.InstalledInfo{Lockfile: "web/package-lock.json", LockLine: 9}),
		up(core.NPM, "escape", core.InstalledInfo{Lockfile: "../../outside/package-lock.json", LockLine: 9}),
		up(core.Composer, "abs/olute", core.InstalledInfo{Lockfile: "/etc/composer.lock", LockLine: 2}),
	}}
	l := readSARIF(t, writeWith(t, core.FormatSARIF, r, testOpts))
	want := []string{"site/wp-content/plugins/hello/hello.php", "site/wp-content/plugins/odd/main.php",
		"site/wp-content/themes/neve/style.css", "site", "site/web/package-lock.json", "site", "site"}
	for i, res := range l.Runs[0].Results {
		if got := res.Locations[0].PhysicalLocation.ArtifactLocation.URI; got != want[i] {
			t.Errorf("%s: uri %q, want %q", r.Updates[i].Name, got, want[i])
		}
	}
	doc := writeWith(t, core.FormatSARIF, r, testOpts)
	if bytes.Contains(doc, []byte("file:")) || bytes.Contains(doc, []byte(repo)) {
		t.Errorf("an absolute path or file URI is in the SARIF:\n%s", doc)
	}
}

// TestSARIFRedactedReport: a report saved with --redact-paths keeps the
// target's repository path, so SARIF rendered from it later points at
// the same files as the direct run: in the checkout it finds the main
// file, elsewhere it points at the folder; a repo_path that leaves the
// repository is ignored.
func TestSARIFRedactedReport(t *testing.T) {
	repo := t.TempDir()
	for _, p := range []string{".git", "projects/wp/wp-content/plugins/hello"} {
		if err := os.MkdirAll(filepath.Join(repo, filepath.FromSlash(p)), 0o750); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, "projects/wp/wp-content/plugins/hello/hello.php"), []byte("<?php\n/* Plugin Name: Hello */"), 0o600); err != nil {
		t.Fatal(err)
	}
	finding := core.Finding{ID: "eval-dynamic", Title: "Runs code built at run time", Severity: cli.SeverityHigh, File: "x.php", Line: 3}
	r := &core.Report{Kind: core.KindReview, Target: core.Target{Path: filepath.Join(repo, "projects", "wp")}, Updates: []core.Update{
		{Eco: core.WPPlugin, Name: "hello", From: core.Side{Version: "1"}, To: core.Side{Version: "2"}, Verdict: core.Review,
			Installed: core.InstalledInfo{Path: "wp-content/plugins/hello"}, Findings: []core.Finding{finding}},
		{Eco: core.Composer, Name: "acme/x", From: core.Side{Version: "1"}, To: core.Side{Version: "2"}, Verdict: core.Review,
			Installed: core.InstalledInfo{Lockfile: "composer.lock", LockLine: 4}, Findings: []core.Finding{finding}},
	}}
	o := testOpts
	o.RedactPaths = true
	saved, err := ReadReport(bytes.NewReader(writeWith(t, core.FormatJSON, r, o)))
	if err != nil {
		t.Fatal(err)
	}
	if saved.Target.Path != "." || saved.Target.RepoPath != "projects/wp" {
		t.Fatalf("saved target %+v", saved.Target)
	}
	uris := func(r *core.Report) []string {
		var out []string
		for _, res := range readSARIF(t, writeWith(t, core.FormatSARIF, r, testOpts)).Runs[0].Results {
			out = append(out, res.Locations[0].PhysicalLocation.ArtifactLocation.URI)
		}
		return out
	}
	t.Chdir(repo)
	if got, want := uris(saved), []string{"projects/wp/wp-content/plugins/hello/hello.php", "projects/wp/composer.lock"}; !slices.Equal(got, want) {
		t.Errorf("in the checkout: %q, want %q", got, want)
	}
	t.Chdir(t.TempDir())
	if got, want := uris(saved), []string{"projects/wp/wp-content/plugins/hello", "projects/wp/composer.lock"}; !slices.Equal(got, want) {
		t.Errorf("elsewhere: %q, want %q", got, want)
	}
	for _, bad := range []string{"../outside", "/etc", `projects\wp`} {
		crafted := *saved
		crafted.Target.RepoPath = bad
		if got, want := uris(&crafted), []string{".", "composer.lock"}; !slices.Equal(got, want) {
			t.Errorf("repo_path %q: %q, want %q", bad, got, want)
		}
	}
}

func TestSARIFFingerprintsStable(t *testing.T) {
	a := writeWith(t, core.FormatSARIF, coretest.SampleReport(), testOpts)
	b := writeWith(t, core.FormatSARIF, coretest.SampleReport(), testOpts)
	if !bytes.Equal(a, b) {
		t.Fatal("two runs differ")
	}
	// A finding saved without a fingerprint gets core.Fingerprint's.
	r := coretest.SampleReport()
	f := &r.Updates[0].Findings[0]
	want := f.Fingerprint
	f.Fingerprint = ""
	l := readSARIF(t, writeWith(t, core.FormatSARIF, r, testOpts))
	if got := l.Runs[0].Results[0].PartialFingerprints[core.FingerprintKey]; got != want {
		t.Errorf("fingerprint %q, want %q", got, want)
	}
}

func TestSARIFNotifications(t *testing.T) {
	l := readSARIF(t, writeWith(t, core.FormatSARIF, coretest.SampleReport(), testOpts))
	inv := l.Runs[0].Invocations[0]
	if inv.ExecutionSuccessful {
		t.Error("executionSuccessful with an unverified update")
	}
	var msgs []string
	for _, n := range inv.ToolExecutionNotifications {
		msgs = append(msgs, n.Level+": "+n.Message.Text)
	}
	for _, want := range []string{
		"error: astra 4.8.1 is unverified: couldn't verify astra 4.8.1: wordpress.org checksums answered 503",
		"error: E7 left-pad: can't reach registry.npmjs.org (no such host)",
		"note: gravityforms 2.8.1 not checked: not on WordPress.org",
	} {
		if !strings.Contains(strings.Join(msgs, "\n"), want) {
			t.Errorf("no notification %q in\n%s", want, strings.Join(msgs, "\n"))
		}
	}
	// A clean run is successful and has no notifications.
	clean := readSARIF(t, writeWith(t, core.FormatSARIF, smallReport(), testOpts)).Runs[0].Invocations[0]
	if !clean.ExecutionSuccessful || len(clean.ToolExecutionNotifications) != 0 {
		t.Errorf("clean invocation %+v", clean)
	}
	// Not checked alone does not fail the run; an interruption does.
	r := smallReport()
	r.NotChecked = []core.NotChecked{{Name: "x", Reason: core.Private}}
	if inv := readSARIF(t, writeWith(t, core.FormatSARIF, r, testOpts)).Runs[0].Invocations[0]; !inv.ExecutionSuccessful {
		t.Error("not checked failed the run")
	}
	r.StoppedBy = "interrupted"
	inv = readSARIF(t, writeWith(t, core.FormatSARIF, r, testOpts)).Runs[0].Invocations[0]
	if inv.ExecutionSuccessful || inv.ToolExecutionNotifications[0].Message.Text != "the run was interrupted; the results are partial" {
		t.Errorf("interrupted invocation %+v", inv)
	}
}

func TestSARIFCap(t *testing.T) {
	r := smallReport()
	u := &r.Updates[0]
	for i := range maxSARIFResults + 5 {
		sev := cli.SeverityLow
		if i == maxSARIFResults+4 {
			sev = cli.SeverityCritical // the last one must survive the cut
		}
		u.Findings = append(u.Findings, core.Finding{ID: "license-change", Title: "License changed", Severity: sev,
			File: "f.php", Line: i + 1, Fingerprint: "0123456789abcdef"})
	}
	l := readSARIF(t, writeWith(t, core.FormatSARIF, r, testOpts))
	run := l.Runs[0]
	if len(run.Results) != maxSARIFResults {
		t.Errorf("%d results, want %d", len(run.Results), maxSARIFResults)
	}
	if run.Results[0].Level != "error" {
		t.Error("the critical result was cut")
	}
	n := run.Invocations[0].ToolExecutionNotifications
	if len(n) != 1 || !strings.HasPrefix(n[0].Message.Text, "25005 results, over GitHub's limit of 25000 per run") {
		t.Errorf("notifications %+v", n)
	}
}

func TestSARIFUnknownRule(t *testing.T) {
	r := smallReport()
	r.Updates[0].Findings = []core.Finding{{ID: "acme-custom", Title: "Custom rule", Severity: cli.SeverityMedium, Fingerprint: "0123456789abcdef"}}
	l := readSARIF(t, writeWith(t, core.FormatSARIF, r, testOpts))
	rules := l.Runs[0].Tool.Driver.Rules
	if len(rules) != 1 || rules[0].ID != "acme-custom" || rules[0].DefaultConfiguration.Level != "warning" {
		t.Errorf("rules %+v", rules)
	}
	if msg := l.Runs[0].Results[0].Message.Text; msg != "left-pad 1.3.0 → 1.3.1: Custom rule. Verdict ROUTINE." {
		t.Errorf("message %q", msg)
	}
}
