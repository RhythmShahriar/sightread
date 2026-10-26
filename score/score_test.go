// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package score

import (
	"context"
	"fmt"
	"math/rand/v2"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
	"github.com/RhythmShahriar/sightread/policy"
)

var testNow = time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)

func testScorer() *Scorer { return &Scorer{Now: func() time.Time { return testNow }} }

var (
	shaA = strings.Repeat("a", 64)
	shaB = strings.Repeat("b", 64)
)

func side(v string) core.Side {
	return core.Side{Version: v, SHA256: shaA, HashKind: core.HashArchive, Verified: core.ByChecksums}
}

func upd(eco core.Ecosystem, name string, fs ...core.Finding) *core.Update {
	return &core.Update{Eco: eco, Name: name, From: side("1.0.0"), To: side("1.1.0"), Findings: fs}
}

// fd is a finding as a detector emits it: an ID, a place and evidence,
// with severity and confidence left to the catalogue.
func fd(id, file string, line int) core.Finding {
	return core.Finding{ID: id, File: file, Line: line, Evidence: core.NewSnippet(id + " at " + file)}
}

func find(t *testing.T, u *core.Update, id string) *core.Finding {
	t.Helper()
	for i := range u.Findings {
		if u.Findings[i].ID == id {
			return &u.Findings[i]
		}
	}
	t.Fatalf("no %s finding in %+v", id, u.Findings)
	return nil
}

func score(u *core.Update, cfg *core.Config, allow core.AllowSet, baseline map[string]bool) *Scorer {
	s := testScorer()
	s.Score(context.Background(), u, cfg, allow, baseline)
	return s
}

func TestRegistered(t *testing.T) {
	coretest.NeedScorer(t)
	if _, ok := core.GetScorer().(*Scorer); !ok {
		t.Fatalf("registered scorer is %T", core.GetScorer())
	}
}

func TestDefaultsAndFingerprint(t *testing.T) {
	u := upd(core.NPM, "@acme/widgets", fd("eval-dynamic", "lib/a.js", 3))
	restore := core.SwapExplain("eval-dynamic", core.Explain{Advice: "Read the call."})
	defer restore()
	score(u, nil, nil, nil)
	f := u.Findings[0]
	if f.Title != "Runs code built at run time" || f.Severity != cli.SeverityHigh || f.Confidence != core.Confirmed {
		t.Errorf("defaults not filled: %+v", f)
	}
	if f.Advice != "Read the call." {
		t.Errorf("advice %q", f.Advice)
	}
	if want := core.Fingerprint(core.NPM, "@acme/widgets", "1.1.0", "eval-dynamic", "lib/a.js", f.Evidence); f.Fingerprint != want || len(want) != 16 {
		t.Errorf("fingerprint %q, want %q", f.Fingerprint, want)
	}
	// A detector's own values are kept.
	g := fd("eval-dynamic", "lib/a.js", 3)
	g.Title, g.Severity, g.Advice = "Own title", cli.SeverityMedium, "Own advice"
	u = upd(core.NPM, "x", g)
	score(u, nil, nil, nil)
	if f := u.Findings[0]; f.Title != "Own title" || f.Severity != cli.SeverityMedium || f.Advice != "Own advice" {
		t.Errorf("detector values replaced: %+v", f)
	}
}

func TestSeverityOverrides(t *testing.T) {
	cfg := &core.Config{Signals: core.SignalConfig{Severity: map[string]string{
		"fresh-release": "low", "license-change": "high", "known-malicious": "high", "integrity-mismatch": "critical",
	}}}
	low := fd("integrity-mismatch", "", 0)
	low.Severity = cli.SeverityHigh // a detector can't lower it either
	u := upd(core.NPM, "x", fd("fresh-release", "", 0), fd("license-change", "", 0), fd("known-malicious", "", 0), low)
	score(u, cfg, nil, nil)
	for id, want := range map[string]cli.Severity{
		"fresh-release": cli.SeverityLow, "license-change": cli.SeverityHigh,
		"known-malicious": cli.SeverityCritical, "integrity-mismatch": cli.SeverityCritical,
	} {
		if got := find(t, u, id).Severity; got != want {
			t.Errorf("%s: %v, want %v", id, got, want)
		}
	}
}

func TestOwnerChangeRaises(t *testing.T) {
	// Positive: every listed signal goes up one level.
	u := upd(core.WPPlugin, "p", fd("owner-change", "", 0), fd("eval-dynamic", "a.php", 1),
		fd("outbound-new-domain", "b.php", 2), fd("dormant-release", "", 0), fd("license-change", "", 0))
	score(u, nil, nil, nil)
	for id, want := range map[string]cli.Severity{
		"eval-dynamic": cli.SeverityCritical, "outbound-new-domain": cli.SeverityHigh, "dormant-release": cli.SeverityHigh,
	} {
		f := find(t, u, id)
		if f.Severity != want || !reflect.DeepEqual(f.RaisedBy, []string{"owner-change"}) {
			t.Errorf("%s: %v raised by %v", id, f.Severity, f.RaisedBy)
		}
	}
	// Negative: a signal not on the list stays and so does owner-change itself.
	if f := find(t, u, "license-change"); f.Severity != cli.SeverityLow || f.RaisedBy != nil {
		t.Errorf("license-change raised: %+v", f)
	}
	if f := find(t, u, "owner-change"); f.Severity != cli.SeverityHigh || f.RaisedBy != nil {
		t.Errorf("owner-change raised: %+v", f)
	}
	// Negative: without owner-change nothing is raised.
	u = upd(core.WPPlugin, "p", fd("eval-dynamic", "a.php", 1))
	score(u, nil, nil, nil)
	if f := u.Findings[0]; f.Severity != cli.SeverityHigh || f.RaisedBy != nil {
		t.Errorf("raised without owner-change: %+v", f)
	}
	// Critical stays critical.
	u = upd(core.WPPlugin, "p", fd("owner-change", "", 0), fd("decode-exec", "a.php", 1))
	score(u, nil, nil, nil)
	if f := find(t, u, "decode-exec"); f.Severity != cli.SeverityCritical || f.RaisedBy != nil {
		t.Errorf("decode-exec: %+v", f)
	}
}

// inFunc makes funcOf read the function from a test table by file and
// line, so a table drives the cases below.
func inFunc(t *testing.T, funcs map[string]string) {
	t.Helper()
	old := funcOf
	funcOf = func(f *core.Finding) string { return funcs[f.File+":"+strconv.Itoa(f.Line)] }
	t.Cleanup(func() { funcOf = old })
}

func TestSameFunctionRaises(t *testing.T) {
	inFunc(t, map[string]string{"a.php:10": "boot", "a.php:12": "boot", "a.php:40": "other", "b.php:12": "boot",
		"c.php:1": "f", "c.php:2": "f", "d.php:1": "g", "d.php:5": "g"})
	// Positive: the lower of two code signals in one function goes up.
	u := upd(core.WPPlugin, "p", fd("eval-dynamic", "a.php", 10), fd("outbound-new-domain", "a.php", 12))
	score(u, nil, nil, nil)
	if f := find(t, u, "outbound-new-domain"); f.Severity != cli.SeverityHigh || !reflect.DeepEqual(f.RaisedBy, []string{"eval-dynamic"}) {
		t.Errorf("not raised: %+v", f)
	}
	if f := find(t, u, "eval-dynamic"); f.Severity != cli.SeverityHigh || f.RaisedBy != nil {
		t.Errorf("the higher one changed: %+v", f)
	}
	// Positive: with equal severities the later one is raised.
	u = upd(core.WPPlugin, "p", fd("input-unserialize", "d.php", 5), fd("eval-dynamic", "d.php", 1))
	score(u, nil, nil, nil)
	if f := find(t, u, "input-unserialize"); f.Severity != cli.SeverityCritical || !reflect.DeepEqual(f.RaisedBy, []string{"eval-dynamic"}) {
		t.Errorf("tie: %+v", f)
	}
	// Negative: another function, another file, the same signal twice or
	// a signal that isn't from code.
	for name, fs := range map[string][]core.Finding{
		"other function": {fd("eval-dynamic", "a.php", 10), fd("outbound-new-domain", "a.php", 40)},
		"other file":     {fd("eval-dynamic", "a.php", 10), fd("outbound-new-domain", "b.php", 12)},
		"same signal":    {fd("outbound-new-domain", "c.php", 1), fd("outbound-new-domain", "c.php", 2)},
		"not code":       {fd("eval-dynamic", "c.php", 1), fd("license-change", "c.php", 2)},
	} {
		u := upd(core.WPPlugin, "p", fs...)
		score(u, nil, nil, nil)
		for _, f := range u.Findings {
			if f.RaisedBy != nil {
				t.Errorf("%s: %s raised by %v", name, f.ID, f.RaisedBy)
			}
		}
	}
	// Without a known function the rule never fires.
	funcOf = func(*core.Finding) string { return "" }
	u = upd(core.WPPlugin, "p", fd("eval-dynamic", "a.php", 10), fd("outbound-new-domain", "a.php", 12))
	score(u, nil, nil, nil)
	if f := find(t, u, "outbound-new-domain"); f.RaisedBy != nil {
		t.Errorf("raised without a function: %+v", f)
	}
}

// The rule reads the function the detectors copy onto the finding.
func TestSameFunctionFromFinding(t *testing.T) {
	in := func(f core.Finding, fn string) core.Finding { f.Func = fn; return f }
	u := upd(core.WPPlugin, "p", in(fd("eval-dynamic", "a.php", 10), "boot"), in(fd("outbound-new-domain", "a.php", 12), "boot"))
	score(u, nil, nil, nil)
	if f := find(t, u, "outbound-new-domain"); !reflect.DeepEqual(f.RaisedBy, []string{"eval-dynamic"}) {
		t.Errorf("not raised: %+v", f)
	}
	u = upd(core.WPPlugin, "p", in(fd("eval-dynamic", "a.php", 10), "boot"), in(fd("outbound-new-domain", "a.php", 12), "other"))
	score(u, nil, nil, nil)
	if f := find(t, u, "outbound-new-domain"); f.RaisedBy != nil {
		t.Errorf("raised across functions: %+v", f)
	}
}

func TestVendoredDemotes(t *testing.T) {
	cases := []struct {
		name  string
		eco   core.Ecosystem
		f     core.Finding
		want  cli.Severity
		demot bool
	}{
		{"tests folder", core.NPM, fd("eval-dynamic", "tests/fixture.js", 1), cli.SeverityMedium, true},
		{"nested docs", core.Composer, fd("outbound-new-domain", "src/docs/example.php", 1), cli.SeverityLow, true},
		{"examples", core.NPM, fd("credential-access", "Examples/read.js", 1), cli.SeverityMedium, true},
		{"node_modules in a package", core.NPM, fd("eval-dynamic", "node_modules/x/index.js", 1), cli.SeverityMedium, true},
		{"vendor in a plugin", core.WPPlugin, fd("eval-dynamic", "vendor/lib/a.php", 1), cli.SeverityMedium, true},
		{"vendor in a theme", core.WPTheme, fd("eval-dynamic", "inc/vendor/a.php", 1), cli.SeverityMedium, true},
		{"minified obfuscation", core.WPPlugin, fd("obfuscation", "assets/app.min.js", 1), cli.SeverityMedium, true},
		{"bundled obfuscation", core.NPM, fd("obfuscation", "dist/app.bundle.js", 1), cli.SeverityMedium, true},
		{"critical stops at high", core.NPM, fd("remote-fetch-exec", "test/a.js", 1), cli.SeverityHigh, true},
		{"info stays info", core.Composer, fd("php-requirement", "tests/x.php", 1), cli.SeverityInfo, true},
		{"vendor in composer is the package's own", core.Composer, fd("eval-dynamic", "vendor/a.php", 1), cli.SeverityHigh, false},
		{"a file named test", core.NPM, fd("eval-dynamic", "lib/test.js", 1), cli.SeverityHigh, false},
		{"a folder like tests", core.NPM, fd("eval-dynamic", "contests/a.js", 1), cli.SeverityHigh, false},
		{"minified but not obfuscation", core.NPM, fd("eval-dynamic", "dist/app.min.js", 1), cli.SeverityHigh, false},
		{"unignorable in tests", core.NPM, fd("archive-path-escape", "tests/../../x", 1), cli.SeverityCritical, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			u := upd(tc.eco, "p", tc.f)
			score(u, nil, nil, nil)
			f := u.Findings[0]
			if f.Severity != tc.want || (f.Demoted == "vendored path") != tc.demot {
				t.Errorf("severity %v demoted %q", f.Severity, f.Demoted)
			}
			if f.Demoted != "" && !f.Counted() {
				t.Error("a demoted finding must still count")
			}
		})
	}
}

func TestIgnore(t *testing.T) {
	cfg := &core.Config{Ignore: []core.IgnoreEntry{
		{ID: "outbound-new-domain", Package: "plugin:woo*", Path: "src/Admin/*", Reason: "inbox notes"},
		{ID: "license-change", Reason: "checked", Until: "2026-10-25"},
		{ID: "integrity-mismatch", Reason: "a hand-edited config can't hide this"},
		{ID: "fresh-release", Path: "/", Reason: "matches nothing"},
	}}
	u := upd(core.WPPlugin, "woocommerce",
		fd("outbound-new-domain", "src/Admin/Notes/feed.php", 5), // nested inside the folder
		fd("outbound-new-domain", "src/Payments/api.php", 5),
		fd("license-change", "", 0),
		fd("integrity-mismatch", "a.php", 0),
	)
	s := score(u, cfg, nil, nil)
	if !u.Findings[slices.IndexFunc(u.Findings, func(f core.Finding) bool { return f.File == "src/Admin/Notes/feed.php" })].Ignored {
		t.Error("matching entry did not ignore")
	}
	if u.Findings[slices.IndexFunc(u.Findings, func(f core.Finding) bool { return f.File == "src/Payments/api.php" })].Ignored {
		t.Error("other path ignored")
	}
	if find(t, u, "license-change").Ignored {
		t.Error("expired entry ignored")
	}
	if f := find(t, u, "integrity-mismatch"); f.Ignored || !f.Counted() {
		t.Error("unignorable ignored")
	}
	// Another package isn't covered.
	u = upd(core.WPPlugin, "jetpack", fd("outbound-new-domain", "src/Admin/x.php", 5))
	s.Score(context.Background(), u, cfg, nil, nil)
	if u.Findings[0].Ignored {
		t.Error("other package ignored")
	}
}

// fakeAllow answers Match with fixed values.
type fakeAllow struct {
	match    *core.AllowEntry
	counted  bool
	conflict *core.AllowEntry
}

func (a fakeAllow) Match(core.Ecosystem, string, string, string) (*core.AllowEntry, bool, *core.AllowEntry) {
	return a.match, a.counted, a.conflict
}

func TestAllow(t *testing.T) {
	e := &core.AllowEntry{Package: "npm:sharp", Version: "1.1.0", SHA256: shaA, Reason: "known script", By: "Ann", Date: "2026-10-22", Until: "2027-01-31"}

	// Every finding covered: ALLOWED.
	u := upd(core.NPM, "sharp", fd("npm-install-script-new", "package.json", 3), fd("license-change", "", 0))
	score(u, nil, fakeAllow{match: e, counted: true}, nil)
	if u.Verdict != core.Allowed {
		t.Errorf("verdict %s", u.Verdict)
	}
	want := &core.AllowMatch{By: "Ann", Reason: "known script", Date: "2026-10-22", Until: "2027-01-31"}
	if !reflect.DeepEqual(u.Findings[0].Allowed, want) {
		t.Errorf("allowed %+v", u.Findings[0].Allowed)
	}

	// An entry with signals covers only those.
	es := *e
	es.Signals = []string{"npm-install-script-new"}
	u = upd(core.NPM, "sharp", fd("npm-install-script-new", "package.json", 3), fd("dependency-new", "package.json", 9))
	score(u, nil, fakeAllow{match: &es, counted: true}, nil)
	if find(t, u, "npm-install-script-new").Allowed == nil || find(t, u, "dependency-new").Allowed != nil || u.Verdict != core.Review {
		t.Errorf("signals subset: %+v verdict %s", u.Findings, u.Verdict)
	}

	// Unignorable findings survive an allow entry.
	u = upd(core.NPM, "sharp", fd("version-republished", "", 0), fd("license-change", "", 0))
	score(u, nil, fakeAllow{match: e, counted: true}, nil)
	if f := find(t, u, "version-republished"); f.Allowed != nil || u.Verdict != core.Hold {
		t.Errorf("unignorable allowed: %+v verdict %s", f, u.Verdict)
	}

	// No findings at all: ROUTINE, as nothing was allowed.
	u = upd(core.NPM, "sharp")
	score(u, nil, fakeAllow{match: e, counted: true}, nil)
	if u.Verdict != core.Routine {
		t.Errorf("empty update: %s", u.Verdict)
	}

	// An entry the change added itself matches but doesn't count; the
	// report says so in its notes.
	u = upd(core.NPM, "sharp", fd("npm-install-script-new", "package.json", 3))
	s := score(u, nil, fakeAllow{match: e, counted: false}, nil)
	if f := u.Findings[0]; f.Allowed != nil || !f.Counted() || u.Verdict != core.Review {
		t.Errorf("entry in this change applied: %+v verdict %s", f, u.Verdict)
	}
	r := &core.Report{Updates: []core.Update{*u}}
	s.Summarise(r)
	s.Summarise(r)
	if want := []string{"npm:sharp@1.1.0: allowed in this change, not counted (--trust-pr-allow counts it)"}; !reflect.DeepEqual(r.Notes, want) {
		t.Errorf("notes %q", r.Notes)
	}

	// An entry the change added next to a reviewed entry for another
	// hash: the conflict still raises approved-version-changed and HOLD.
	base := &core.AllowEntry{Package: "npm:sharp", Version: "1.1.0", SHA256: shaB, Reason: "reviewed", By: "Ann", Date: "2026-10-01"}
	u = upd(core.NPM, "sharp", fd("license-change", "", 0))
	score(u, nil, fakeAllow{match: e, counted: false, conflict: base}, nil)
	if f := find(t, u, "approved-version-changed"); f.Allowed != nil || u.Verdict != core.Hold {
		t.Errorf("conflict hidden by an entry in this change: %+v verdict %s", u.Findings, u.Verdict)
	}

	// An update without a hash is never allowed.
	u = upd(core.NPM, "sharp", fd("license-change", "", 0))
	u.To.SHA256, u.To.Verified = "", core.ByNone
	score(u, nil, fakeAllow{match: e, counted: true}, nil)
	if u.Findings[0].Allowed != nil || u.Verdict != core.Unverified {
		t.Errorf("unverified allowed: %+v %s", u.Findings[0], u.Verdict)
	}
}

// allowFile loads a real allow file through package policy.
func allowFile(t *testing.T, entries ...core.AllowEntry) core.AllowSet {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	p := filepath.Join(dir, ".sightread", "allowed.yaml")
	st := &policy.Store{Now: func() time.Time { return testNow }}
	for _, e := range entries {
		if err := st.AddAllow(p, e); err != nil {
			t.Fatal(err)
		}
	}
	set, err := st.LoadAllow(&core.Config{}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// TestApprovedVersionChanged is the fixture set of the policy-emitted
// signal: three cases that must give it and three lookalikes that must
// not (TestEverySignalHasFixtures in detect covers detect signals only).
func TestApprovedVersionChanged(t *testing.T) {
	entry := func(pkg, version, sha, reason string) core.AllowEntry {
		return core.AllowEntry{Package: pkg, Version: version, SHA256: sha, Reason: reason, By: "Ann Reviewer", Date: "2026-10-20"}
	}
	cases := []struct {
		name      string
		allow     []core.AllowEntry
		u         *core.Update
		positive  bool
		lookalike bool
	}{
		{"pos: npm version republished after review",
			[]core.AllowEntry{entry("npm:left-pad", "1.1.0", shaB, "checked")},
			upd(core.NPM, "left-pad"), true, false},
		{"pos: scoped npm package with other findings",
			[]core.AllowEntry{entry("npm:@acme/widgets", "1.1.0", shaB, "checked")},
			upd(core.NPM, "@acme/widgets", fd("license-change", "", 0)), true, false},
		{"pos: WordPress manifest changed, ignore and baseline can't hide it",
			[]core.AllowEntry{entry("wp-plugin:wordfence", "1.1.0", shaB, "checked")},
			upd(core.WPPlugin, "wordfence"), true, false},
		{"neg: same version, same hash, other reason text",
			[]core.AllowEntry{entry("npm:left-pad", "1.1.0", strings.ToUpper(shaA), "a different reason entirely")},
			upd(core.NPM, "left-pad", fd("license-change", "", 0)), false, true},
		{"neg: entry for another version",
			[]core.AllowEntry{entry("npm:left-pad", "1.0.9", shaB, "checked")},
			upd(core.NPM, "left-pad"), false, false},
		{"neg: same name in another ecosystem",
			[]core.AllowEntry{entry("composer:acme/left-pad", "1.1.0", shaB, "checked")},
			upd(core.NPM, "left-pad"), false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set := allowFile(t, tc.allow...)
			cfg := &core.Config{Ignore: []core.IgnoreEntry{{ID: "approved-version-changed", Reason: "tries to hide it"}}}
			// A baseline holding every fingerprint the finding could have.
			base := map[string]bool{}
			probe := upd(tc.u.Eco, tc.u.Name)
			score(probe, nil, set, nil)
			for _, f := range probe.Findings {
				base[f.Fingerprint] = true
			}
			score(tc.u, cfg, set, base)
			idx := slices.IndexFunc(tc.u.Findings, func(f core.Finding) bool { return f.ID == "approved-version-changed" })
			if (idx >= 0) != tc.positive {
				t.Fatalf("approved-version-changed present %v, want %v: %+v", idx >= 0, tc.positive, tc.u.Findings)
			}
			if !tc.positive {
				if tc.lookalike && tc.u.Findings[0].Allowed == nil {
					t.Error("the matching entry did not allow the finding")
				}
				return
			}
			f := tc.u.Findings[idx]
			if f.Severity != cli.SeverityCritical || f.Confidence != core.Confirmed || !f.Counted() || f.Title != "Allowed version now has a different hash" {
				t.Errorf("finding %+v", f)
			}
			if want := "allowed on 2026-10-20 by Ann Reviewer with sha256 bbbbbbbbbbbb; now aaaaaaaaaaaa"; f.Evidence.String() != want {
				t.Errorf("evidence %q", f.Evidence)
			}
			if tc.u.Verdict != core.Hold || idx != 0 {
				t.Errorf("verdict %s, index %d", tc.u.Verdict, idx)
			}
		})
	}
}

// TestAllowHashKind checks an entry is compared only with a hash of its
// own kind: an archive hash never equals a manifest hash of the same
// release, so a mixed pair is no evidence of a change.
func TestAllowHashKind(t *testing.T) {
	entry := func(sha, hash string) core.AllowEntry {
		return core.AllowEntry{Package: "wp-plugin:wordfence", Version: "1.1.0", SHA256: sha, Hash: hash, Reason: "checked", By: "Ann Reviewer", Date: "2026-10-20"}
	}
	cases := []struct {
		name     string
		e        core.AllowEntry
		kind     string
		conflict bool
		allowed  bool
	}{
		{"pos: manifest entry, manifest changed", entry(shaB, core.HashManifest), core.HashManifest, true, false},
		{"pos: archive entry, archive changed", entry(shaB, ""), core.HashArchive, true, false},
		{"pos: manifest entry, same manifest", entry(shaA, core.HashManifest), core.HashManifest, false, true},
		{"neg: archive entry, manifest side", entry(shaB, core.HashArchive), core.HashManifest, false, false},
		{"neg: manifest entry, archive side", entry(shaB, core.HashManifest), core.HashArchive, false, false},
		{"neg: archive entry, same sha but manifest side", entry(shaA, core.HashArchive), core.HashManifest, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			set := allowFile(t, tc.e)
			u := upd(core.WPPlugin, "wordfence", fd("license-change", "", 0))
			u.To.HashKind = tc.kind
			score(u, nil, set, nil)
			got := slices.ContainsFunc(u.Findings, func(f core.Finding) bool { return f.ID == "approved-version-changed" })
			if got != tc.conflict {
				t.Errorf("approved-version-changed %v, want %v", got, tc.conflict)
			}
			if allowed := find(t, u, "license-change").Allowed != nil; allowed != tc.allowed {
				t.Errorf("allowed %v, want %v", allowed, tc.allowed)
			}
		})
	}
}

func TestBaselineAndConfidence(t *testing.T) {
	u := upd(core.NPM, "x", fd("bot-cloaking", "a.js", 1), fd("eval-dynamic", "b.js", 2), fd("integrity-mismatch", "", 0))
	probe := upd(core.NPM, "x", fd("bot-cloaking", "a.js", 1), fd("eval-dynamic", "b.js", 2), fd("integrity-mismatch", "", 0))
	score(probe, nil, nil, nil)
	base := map[string]bool{}
	for _, f := range probe.Findings {
		if f.ID != "bot-cloaking" {
			base[f.Fingerprint] = true
		}
	}
	score(u, &core.Config{MinConfidence: "confirmed"}, nil, base)
	if f := find(t, u, "eval-dynamic"); !f.Baselined || f.Counted() {
		t.Errorf("not baselined: %+v", f)
	}
	if f := find(t, u, "integrity-mismatch"); f.Baselined || !f.Counted() {
		t.Errorf("unignorable baselined: %+v", f)
	}
	if f := find(t, u, "bot-cloaking"); !f.BelowConfidence || f.Counted() {
		t.Errorf("likely finding counted under --min-confidence confirmed: %+v", f)
	}
	// Without --min-confidence confirmed, likely findings count.
	u = upd(core.NPM, "x", fd("bot-cloaking", "a.js", 1))
	score(u, &core.Config{MinConfidence: "likely"}, nil, nil)
	if u.Findings[0].BelowConfidence || u.Verdict != core.Review {
		t.Errorf("likely: %+v %s", u.Findings[0], u.Verdict)
	}
}

func TestVerdicts(t *testing.T) {
	low := fd("license-change", "", 0)
	cases := []struct {
		name string
		u    *core.Update
		want core.Verdict
	}{
		{"none", upd(core.NPM, "x"), core.Routine},
		{"low and info only", upd(core.NPM, "x", low, fd("files-removed", "", 0)), core.Routine},
		{"medium", upd(core.NPM, "x", low, fd("fresh-release", "", 0)), core.Review},
		{"high", upd(core.NPM, "x", fd("eval-dynamic", "a.js", 1)), core.Review},
		{"critical", upd(core.NPM, "x", low, fd("decode-exec", "a.js", 1)), core.Hold},
		{"critical but ignored", upd(core.WPPlugin, "x", fd("wporg-closed", "", 0)), core.Routine},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &core.Config{Ignore: []core.IgnoreEntry{{ID: "wporg-closed", Reason: "we forked it"}}}
			score(tc.u, cfg, nil, nil)
			if tc.u.Verdict != tc.want {
				t.Errorf("verdict %s, want %s", tc.u.Verdict, tc.want)
			}
		})
	}
	for name, mod := range map[string]func(*core.Update){
		"to unverified":   func(u *core.Update) { u.To.Verified = core.ByNone },
		"from unverified": func(u *core.Update) { u.From.Verified = core.ByNone },
	} {
		u := upd(core.NPM, "x", fd("decode-exec", "a.js", 1))
		mod(u)
		score(u, nil, nil, nil)
		if u.Verdict != core.Unverified || len(u.Findings) != 1 || u.Findings[0].Fingerprint == "" {
			t.Errorf("%s: verdict %s, findings %+v", name, u.Verdict, u.Findings)
		}
	}
	// A package the update adds has no from side to verify.
	u := upd(core.NPM, "x")
	u.From = core.Side{}
	score(u, nil, nil, nil)
	if u.Verdict != core.Routine {
		t.Errorf("added package: %s", u.Verdict)
	}
}

func TestSortIsDeterministic(t *testing.T) {
	var fs []core.Finding
	for _, s := range core.Catalog {
		fs = append(fs, fd(s.ID, "f/"+s.ID+".php", len(s.ID)), fd(s.ID, "a.php", 3))
	}
	want := slices.Clone(fs)
	score(&core.Update{Eco: core.NPM, Name: "x", To: side("1"), From: side("0"), Findings: want}, nil, nil, nil)
	for seed := range uint64(20) {
		got := slices.Clone(fs)
		rand.New(rand.NewPCG(seed, 1)).Shuffle(len(got), func(i, j int) { got[i], got[j] = got[j], got[i] })
		u := &core.Update{Eco: core.NPM, Name: "x", To: side("1"), From: side("0"), Findings: got}
		score(u, nil, nil, nil)
		if !reflect.DeepEqual(u.Findings, want) {
			t.Fatalf("seed %d: order depends on input order", seed)
		}
	}
	for i := 1; i < len(want); i++ {
		a, b := want[i-1], want[i]
		if a.Severity < b.Severity || a.Severity == b.Severity && a.Confidence == core.Likely && b.Confidence == core.Confirmed {
			t.Fatalf("out of order at %d: %s %v %s, %s %v %s", i, a.ID, a.Severity, a.Confidence, b.ID, b.Severity, b.Confidence)
		}
	}
}

func TestSummarise(t *testing.T) {
	r := coretest.SampleReport()
	s := testScorer()
	r.Summary = core.Summary{}
	s.Summarise(r)
	sum := r.Summary
	if sum.Updates != 6 || sum.Hold != 1 || sum.Review != 1 || sum.Routine != 2 || sum.Allowed != 1 || sum.Unverified != 1 {
		t.Errorf("verdict counts %+v", sum)
	}
	if sum.Baselined != 1 || sum.Ignored != 1 || sum.AllowedFindings != 1 || sum.Demoted != 1 || sum.NotChecked != 1 || sum.FromCache != 1 {
		t.Errorf("treatment counts %+v", sum)
	}
	total := 0
	for _, u := range r.Updates {
		for _, f := range u.Findings {
			if f.Counted() {
				total++
			}
		}
	}
	if got := sum.Critical + sum.High + sum.Medium + sum.Low + sum.Info; got != total {
		t.Errorf("severity counts add to %d, want %d counted findings", got, total)
	}
	if r.Complete {
		t.Error("a report with UNVERIFIED, Not checked and errors is complete")
	}

	for name, c := range map[string]struct {
		mod  func(*core.Report)
		want bool
	}{
		"clean":       {func(*core.Report) {}, true},
		"unverified":  {func(r *core.Report) { r.Updates[0].Verdict = core.Unverified }, false},
		"not checked": {func(r *core.Report) { r.NotChecked = []core.NotChecked{{Name: "x"}} }, false},
		"core and mu-plugin only": {func(r *core.Report) {
			r.NotChecked = []core.NotChecked{{Name: "wordpress", Reason: core.Core}, {Name: "loader", Reason: core.MUPlugin}}
		}, true},
		"core and premium": {func(r *core.Report) {
			r.NotChecked = []core.NotChecked{{Name: "wordpress", Reason: core.Core}, {Name: "gravityforms", Reason: core.NotWPOrg}}
		}, false},
		"run error": {func(r *core.Report) { r.Errors = []core.ErrorEntry{{Code: core.ENetwork}} }, false},
		"update error": {func(r *core.Report) {
			r.Updates[0].Errors = []core.ErrorEntry{{Code: core.ERateLimited}}
		}, false},
		"interrupted": {func(r *core.Report) { r.StoppedBy = "interrupted" }, false},
	} {
		r := &core.Report{Updates: []core.Update{{Verdict: core.Routine}}}
		c.mod(r)
		s.Summarise(r)
		if r.Complete != c.want {
			t.Errorf("%s: complete %v", name, r.Complete)
		}
		if want := core.CountNotChecked(r.NotChecked); r.Summary.NotChecked != want {
			t.Errorf("%s: summary not_checked %d, want %d", name, r.Summary.NotChecked, want)
		}
	}
}

func TestUnanalysedNote(t *testing.T) {
	cfg := &core.Config{Signals: core.SignalConfig{Severity: map[string]string{"unanalysed": "medium"}}}
	s := testScorer()
	r := &core.Report{Notes: []string{"--skip-roadie-verify was used"}}
	for _, name := range []string{"a", "b"} {
		u := upd(core.NPM, name, fd("unanalysed", "big.js", 0))
		s.Score(context.Background(), u, cfg, nil, nil)
		if u.Findings[0].Severity != cli.SeverityMedium {
			t.Errorf("severity %v", u.Findings[0].Severity)
		}
		r.Updates = append(r.Updates, *u)
	}
	s.Summarise(r)
	want := []string{"--skip-roadie-verify was used", "unanalysed lowered to medium by .sightread/config.yaml"}
	if !reflect.DeepEqual(r.Notes, want) {
		t.Errorf("notes %q", r.Notes)
	}
	// Raising it is not lowering it: no note.
	cfg.Signals.Severity["unanalysed"] = "critical"
	u := upd(core.NPM, "c")
	s.Score(context.Background(), u, cfg, nil, nil)
	r = &core.Report{Updates: []core.Update{*u}}
	s.Summarise(r)
	if len(r.Notes) != 0 {
		t.Errorf("notes %q", r.Notes)
	}
}

// TestGateMatrix runs every --fail-on level against every mix of
// findings and every partial state, with and without the flags that
// accept a partial run.
func TestGateMatrix(t *testing.T) {
	levels := []cli.Severity{cli.SeverityNone, cli.SeverityInfo, cli.SeverityLow, cli.SeverityMedium, cli.SeverityHigh, cli.SeverityCritical}
	findingsAt := []cli.Severity{cli.SeverityNone, cli.SeverityInfo, cli.SeverityLow, cli.SeverityMedium, cli.SeverityHigh, cli.SeverityCritical}
	states := []string{"complete", "unverified", "not-checked", "fetch-error", "interrupted", "deadline", "unverified+not-checked"}
	s := testScorer()
	for _, failOn := range levels {
		for _, worst := range findingsAt {
			for _, state := range states {
				for _, flags := range [][2]bool{{false, false}, {true, false}, {false, true}, {true, true}} {
					r := &core.Report{}
					u := core.Update{Eco: core.NPM, Name: "x", Verdict: core.Routine}
					if worst != cli.SeverityNone {
						u.Findings = []core.Finding{{ID: "x", Severity: worst}}
						// A finding set aside never counts.
						u.Findings = append(u.Findings, core.Finding{ID: "y", Severity: cli.SeverityCritical, Ignored: true})
					}
					unverified, partial := false, false
					switch state {
					case "unverified":
						u.Verdict, unverified = core.Unverified, true
						u.Errors = []core.ErrorEntry{{Code: core.EUnverifiable}}
					case "not-checked":
						r.NotChecked, partial = []core.NotChecked{{Name: "y"}}, true
					case "fetch-error":
						r.Errors, partial = []core.ErrorEntry{{Code: core.ENetwork}}, true
					case "interrupted", "deadline":
						r.StoppedBy, partial = state, true
					case "unverified+not-checked":
						u.Verdict, unverified = core.Unverified, true
						r.NotChecked, partial = []core.NotChecked{{Name: "y"}}, true
					}
					r.Updates = []core.Update{u}
					o := core.GateOptions{FailOn: failOn, AllowUnverified: flags[0], AllowPartial: flags[1]}
					want := cli.ExitOK
					switch {
					case failOn != cli.SeverityNone && worst != cli.SeverityNone && worst >= failOn:
						want = cli.ExitFindings
					case failOn != cli.SeverityNone && (unverified && !flags[0] || partial && !flags[1]):
						want = cli.ExitUnavailable
					}
					got, reason := s.Gate(r, o)
					if got != want {
						t.Errorf("fail-on %v, findings %v, %s, allow-unverified %v, allow-partial %v: exit %d, want %d (%s)",
							failOn, worst, state, flags[0], flags[1], got, want, reason)
					}
					if (got != cli.ExitOK) != (reason != "") {
						t.Errorf("exit %d with reason %q", got, reason)
					}
				}
			}
		}
	}
}

func TestGateReasons(t *testing.T) {
	s := testScorer()
	high := core.GateOptions{FailOn: cli.SeverityHigh}
	unv := core.Update{Verdict: core.Unverified}
	cases := []struct {
		name string
		r    *core.Report
		o    core.GateOptions
		exit int
		want string
	}{
		{"findings", &core.Report{Updates: []core.Update{{Findings: []core.Finding{{Severity: cli.SeverityHigh}, {Severity: cli.SeverityCritical}, {Severity: cli.SeverityLow}}}}},
			high, 1, "2 findings at or above --fail-on high"},
		{"one finding", &core.Report{Updates: []core.Update{{Findings: []core.Finding{{Severity: cli.SeverityCritical}}}}},
			high, 1, "1 finding at or above --fail-on high"},
		{"new findings", &core.Report{Updates: []core.Update{{Findings: []core.Finding{{Severity: cli.SeverityMedium}, {Severity: cli.SeverityHigh, Baselined: true}}}}},
			core.GateOptions{FailOnNew: cli.SeverityMedium}, 1, "1 new finding at or above --fail-on-new medium"},
		{"unverified", &core.Report{Updates: []core.Update{unv, unv}},
			high, 3, "2 updates couldn't be verified, so --fail-on high can't pass it\nadd --allow-unverified to accept them"},
		{"not checked", &core.Report{NotChecked: []core.NotChecked{{}}},
			high, 3, "1 package wasn't checked, so --fail-on high can't pass it\nadd --allow-partial to accept them"},
		{"core and mu-plugin pass", &core.Report{Updates: []core.Update{{Verdict: core.Routine}},
			NotChecked: []core.NotChecked{{Name: "wordpress", Reason: core.Core}, {Name: "loader", Reason: core.MUPlugin}}},
			high, 0, ""},
		{"core does not hide a premium plugin", &core.Report{
			NotChecked: []core.NotChecked{{Name: "wordpress", Reason: core.Core}, {Name: "gravityforms", Reason: core.NotWPOrg}}},
			high, 3, "1 package wasn't checked, so --fail-on high can't pass it\nadd --allow-partial to accept them"},
		{"interrupted", &core.Report{StoppedBy: "interrupted"},
			high, 3, "the run was interrupted, so --fail-on high can't pass it\nadd --allow-partial to accept a partial run"},
		{"everything", &core.Report{Updates: []core.Update{unv, {Errors: []core.ErrorEntry{{Code: core.ERateLimited}}}},
			NotChecked: []core.NotChecked{{}, {}}, StoppedBy: "deadline"},
			high, 3, "1 update couldn't be verified, 2 packages weren't checked, 1 package couldn't be fetched and the run hit its --deadline, so --fail-on high can't pass it\nadd --allow-unverified and --allow-partial to accept them"},
		{"findings beat gaps", &core.Report{Updates: []core.Update{unv, {Findings: []core.Finding{{Severity: cli.SeverityHigh}}}}},
			high, 1, "1 finding at or above --fail-on high"},
		{"no --fail-on", &core.Report{Updates: []core.Update{unv, {Findings: []core.Finding{{Severity: cli.SeverityCritical}}}}},
			core.GateOptions{}, 0, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exit, reason := s.Gate(tc.r, tc.o)
			if exit != tc.exit || reason != tc.want {
				t.Errorf("exit %d %q, want %d %q", exit, reason, tc.exit, tc.want)
			}
		})
	}
}

func TestNotesLifetime(t *testing.T) {
	lowered := &core.Config{Signals: core.SignalConfig{Severity: map[string]string{"unanalysed": "low"}}}
	s := testScorer()
	s.SetConfigPath("ci/sightread.yaml")
	u := upd(core.NPM, "a", fd("unanalysed", "big.js", 0))
	s.Score(context.Background(), u, lowered, nil, nil)
	r := &core.Report{Updates: []core.Update{*u}}
	s.Summarise(r)
	if want := []string{"unanalysed lowered to low by ci/sightread.yaml"}; !reflect.DeepEqual(r.Notes, want) {
		t.Errorf("notes %q, want %q", r.Notes, want)
	}

	// Scoring again with a config that no longer lowers it drops the note.
	u = upd(core.NPM, "a", fd("unanalysed", "big.js", 0))
	s.Score(context.Background(), u, lowered, nil, nil)
	s.Score(context.Background(), u, &core.Config{}, nil, nil)
	r = &core.Report{Updates: []core.Update{*u}}
	s.Summarise(r)
	if len(r.Notes) != 0 {
		t.Errorf("a stale note survived rescoring: %q", r.Notes)
	}

	// Notes of updates scored but never summarised (a long watch) stay
	// bounded. Summarise can't drop them all: another report scored at
	// the same time may still be waiting for its own.
	for i := range maxNoteUpdates + 10 {
		s.Score(context.Background(), upd(core.NPM, fmt.Sprintf("p%d", i)), lowered, nil, nil)
	}
	if n := len(s.notes); n > maxNoteUpdates {
		t.Errorf("%d updates' notes kept, cap %d", n, maxNoteUpdates)
	}
}
