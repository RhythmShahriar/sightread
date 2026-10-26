// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package pairs

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// writeCase writes body as <root>/<signal>/<name>/case.yaml.
func writeCase(t *testing.T, root, signal, name, body string) string {
	t.Helper()
	dir := filepath.Join(root, signal, name)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "case.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadCase(t *testing.T) {
	root := t.TempDir()
	p := writeCase(t, root, "eval-dynamic", "pos-1", `
eco: plugin
note: the plain case
old: {a.php: "<?php echo 1;"}
new: {a.php: "<?php eval($_POST['x']);"}
meta_old: {ref: {version: 1.2.0}, maintainers: [{name: ann}]}
meta_new:
  requires_php: "8.1"
  closed_reason: author request
  deps: {left_pad: ^1.0.0}
  dep_info: {left_pad: {has_install_script: true}}
  published: 2026-10-20T08:00:00Z
lock_new: {resolved_kind: foreign}
integrity_new: {by: failed, mismatch: [a.php]}
issues: [{kind: collision, path: a.php, other: A.php}]
drift: {differ: [a.php]}
config: {min_age: 72h, signals: {domains_ok: ["*.acme.test"]}}
features_new:
  - {kind: eval, key: eval, path: a.php, line: 1, attrs: {source: request}, func: run}
features_old: {found: [], minified: [a.min.js], unanalysed: [{path: b.php, reason: too big}]}
expect: [{id: eval-dynamic, min_severity: high}]
forbid: [decode-exec]
`)
	c, err := LoadCase(p)
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case c.Signal != "eval-dynamic" || c.Kind != Pos || c.Name != "pos-1" || c.Eco != core.WPPlugin:
		t.Errorf("identity: %+v", c)
	case c.MetaNew.RequiresPHP != "8.1" || c.MetaNew.ClosedReason != "author request":
		t.Errorf("snake_case meta keys: %+v", c.MetaNew)
	case c.MetaNew.Deps["left_pad"] != "^1.0.0" || !c.MetaNew.DepInfo["left_pad"].HasInstallScript:
		t.Errorf("map keys must keep their underscores: %+v", c.MetaNew.Deps)
	case c.MetaNew.Published.Day() != 20 || c.MetaOld.Ref.Version != "1.2.0" || c.MetaOld.Maintainers[0].Name != "ann":
		t.Errorf("meta: %+v %+v", c.MetaNew, c.MetaOld)
	case c.LockNew.ResolvedKind != core.ResolvedForeign || c.IntegrityNew.By != core.ByFailed:
		t.Errorf("lock or integrity: %+v %+v", c.LockNew, c.IntegrityNew)
	case len(c.Issues) != 1 || c.Issues[0].Kind != core.IssueCollision || c.Drift.Differ[0] != "a.php":
		t.Errorf("issues or drift: %+v %+v", c.Issues, c.Drift)
	case c.Config.MinAge != "72h" || c.Config.Signals.DomainsOK[0] != "*.acme.test":
		t.Errorf("config: %+v", c.Config)
	case !c.FeaturesNew.Has(core.FEval, "eval") || c.FeaturesOld.Minified[0] != "a.min.js" || c.FeaturesOld.Unanalysed[0].Reason != "too big":
		t.Errorf("features: %+v %+v", c.FeaturesNew, c.FeaturesOld)
	case len(c.Expect) != 1 || c.Expect[0].Min != cli.SeverityHigh || c.Forbid[0] != "decode-exec":
		t.Errorf("expect or forbid: %+v %+v", c.Expect, c.Forbid)
	}
	f := c.FeaturesNew.ByKey["eval:eval"][0]
	if f.Context != core.CtxCode || f.Ev.EndLine != 1 || f.Ev.Func != "run" || f.Ev.Snippet.String() != "eval eval" {
		t.Errorf("feature defaults: %+v", f)
	}
}

// Every malformed case fails with the file and the key in the message.
func TestLoadCaseErrors(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       []string
	}{
		{"unknown top key", "eco: npm\nexpekt: []\n", []string{`line 2: unknown key "expekt"`}},
		{"unknown nested key", "eco: npm\nmeta_new:\n  publisher: {nam: x}\n", []string{"meta_new: publisher:", `line 3: unknown key "nam"`}},
		{"unknown key in a list", "eco: npm\nmeta_new: {maintainers: [{name: a}, {emial: b}]}\n", []string{"meta_new: maintainers: entry 2:", `unknown key "emial"`}},
		{"wrong type", "eco: npm\nnow: yesterday\n", []string{"now:", "line 2"}},
		{"missing eco", "forbid: [eval-dynamic]\n", []string{"eco: missing"}},
		{"bad eco", "eco: pypi\n", []string{"eco:", `unknown ecosystem "pypi"`}},
		{"unknown expect ID", "eco: npm\nexpect: [{id: eval-dynamc}]\nforbid: [eval-dynamic]\n", []string{"expect: entry 1:", `unknown signal ID "eval-dynamc"`}},
		{"unknown forbid ID", "eco: npm\nforbid: [eval-dynamic, nope]\n", []string{"forbid: entry 2:", `unknown signal ID "nope"`}},
		{"bad severity", "eco: npm\nexpect: [{id: eval-dynamic, min_severity: severe}]\nforbid: [eval-dynamic]\n", []string{"min_severity", `"severe"`}},
		{"neg without forbid", "eco: npm\n", []string{"forbid:", "must forbid it"}},
		{"neg cap not below default", "eco: npm\nexpect: [{id: eval-dynamic, max_severity: high}]\n", []string{"forbid:"}},
		{"old and old_dir", "eco: npm\nold: {}\nold_dir: x\nforbid: [eval-dynamic]\n", []string{"old: give old or old_dir"}},
		{"old_dir escapes", "eco: npm\nold_dir: ../../x\nforbid: [eval-dynamic]\n", []string{"old_dir:", "leaves the case folder"}},
		{"feature kind", "eco: npm\nfeatures_new: [{kind: evil, path: a.js}]\nforbid: [eval-dynamic]\n", []string{"features_new: feature 1:", `unknown kind "evil"`}},
		{"feature key", "eco: npm\nfeatures_new: [{kind: eval, path: a.js, lien: 3}]\nforbid: [eval-dynamic]\n", []string{"features_new:", `unknown key "lien"`}},
		{"feature context", "eco: npm\nfeatures_new: [{kind: eval, path: a.js, context: prose}]\nforbid: [eval-dynamic]\n", []string{`unknown context "prose"`}},
		{"duplicate key", "eco: npm\neco: npm\nforbid: [eval-dynamic]\n", []string{"line 2"}},
		{"placeholder", "eco: npm\nnew: {a.js: \"{{fakekey:paypal}}\"}\nforbid: [eval-dynamic]\n", []string{"line 2:", `unknown fake key kind "paypal"`}},
		{"not a mapping", "- eco\n", []string{"a case is a mapping"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := writeCase(t, t.TempDir(), "eval-dynamic", "neg-1", tc.body)
			_, err := LoadCase(p)
			if err == nil {
				t.Fatal("no error")
			}
			msg := err.Error()
			if !strings.HasPrefix(msg, p+": ") {
				t.Errorf("error %q does not start with the file", msg)
			}
			for _, w := range tc.want {
				if !strings.Contains(msg, w) {
					t.Errorf("error %q lacks %q", msg, w)
				}
			}
		})
	}
}

func TestLoadCaseLookalikeOnNegOnly(t *testing.T) {
	p := writeCase(t, t.TempDir(), "eval-dynamic", "pos-1", "eco: npm\nlookalike: true\nexpect: [{id: eval-dynamic}]\n")
	if _, err := LoadCase(p); err == nil || !strings.Contains(err.Error(), "lookalike: only a neg case") {
		t.Errorf("err = %v", err)
	}
	p = writeCase(t, t.TempDir(), "eval-dynamic", "pos-1", "eco: npm\nforbid: [eval-dynamic]\n")
	if _, err := LoadCase(p); err == nil || !strings.Contains(err.Error(), "must expect eval-dynamic") {
		t.Errorf("err = %v", err)
	}
}

func TestExpand(t *testing.T) {
	root := t.TempDir()
	p := writeCase(t, root, "secret-added", "pos-1",
		"eco: npm\nnew: {a.js: \"const k = '{{fakekey:npm}}'\"}\nexpect: [{id: secret-added}]\n")
	c, err := LoadCase(p)
	if err != nil {
		t.Fatal(err)
	}
	if want := "const k = '" + coretest.FakeKey(coretest.KeyNPM) + "'"; c.New["a.js"] != want {
		t.Errorf("a.js = %q, want %q", c.New["a.js"], want)
	}
	raw, _ := os.ReadFile(p)
	if strings.Contains(string(raw), coretest.FakeKey(coretest.KeyNPM)) {
		t.Error("the case file itself holds the key")
	}
	for _, kind := range coretest.FakeKeyKinds() {
		out, err := Expand([]byte("x {{fakekey:" + kind + "}} y"))
		if err != nil || string(out) != "x "+coretest.FakeKey(kind)+" y" {
			t.Errorf("%s: %q, %v", kind, out, err)
		}
	}
}

// old_dir and new_dir read a folder next to case.yaml, with the
// placeholders expanded there too.
func TestDirs(t *testing.T) {
	root := t.TempDir()
	p := writeCase(t, root, "secret-added", "pos-1", "eco: npm\nold_dir: old\nnew_dir: new\nexpect: [{id: secret-added}]\n")
	dir := filepath.Dir(p)
	for name, body := range map[string]string{"old/index.js": "1", "new/index.js": "2", "new/lib/k.js": "{{fakekey:github}}"} {
		fp := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(fp), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fp, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	c, err := LoadCase(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Old["index.js"] != "1" || c.New["index.js"] != "2" || c.New["lib/k.js"] != coretest.FakeKey(coretest.KeyGitHub) {
		t.Errorf("old %v new %v", c.Old, c.New)
	}
}

func TestLoad(t *testing.T) {
	root := t.TempDir()
	writeCase(t, root, "eval-dynamic", "pos-1", "eco: npm\nexpect: [{id: eval-dynamic}]\n")
	writeCase(t, root, "eval-dynamic", "neg-1", "eco: npm\nlookalike: true\nforbid: [eval-dynamic]\n")
	if err := os.WriteFile(filepath.Join(root, "README.md"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if n := Counts(cases)["eval-dynamic"]; n != (Count{Pos: 1, Neg: 1, Lookalike: 1}) {
		t.Errorf("counts %+v", n)
	}

	bad := t.TempDir()
	writeCase(t, bad, "eval-dynamc", "pos-1", "eco: npm\n")
	if _, err := Load(bad); err == nil || !strings.Contains(err.Error(), `unknown signal ID "eval-dynamc"`) {
		t.Errorf("unknown signal folder: %v", err)
	}
	bad = t.TempDir()
	writeCase(t, bad, "eval-dynamic", "positive-1", "eco: npm\n")
	if _, err := Load(bad); err == nil || !strings.Contains(err.Error(), "pos-<n> or neg-<n>") {
		t.Errorf("bad case folder: %v", err)
	}
}

func TestShortfalls(t *testing.T) {
	counts := map[string]Count{"a": {3, 3, 1}, "b": {3, 3, 0}, "c": {2, 4, 2}}
	got := Shortfalls([]string{"a", "b", "c", "d"}, counts)
	want := []string{
		"b: no neg case with lookalike: true",
		"c: 2 of 3 pos cases",
		"d: 0 of 3 pos cases, 0 of 3 neg cases, no neg case with lookalike: true",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestCheck(t *testing.T) {
	c := &Case{
		Expect: []Expect{{ID: "eval-dynamic", Min: cli.SeverityHigh}, {ID: "outbound-new-domain", Min: cli.SeverityInfo, Max: cli.SeverityInfo}},
		Forbid: []string{"decode-exec"},
	}
	ok := []core.Finding{{ID: "eval-dynamic", Severity: cli.SeverityHigh}, {ID: "outbound-new-domain", Severity: cli.SeverityInfo}}
	if p := c.Check(ok); len(p) != 0 {
		t.Errorf("clean findings: %v", p)
	}
	bad := []core.Finding{
		{ID: "eval-dynamic", Severity: cli.SeverityMedium},
		{ID: "outbound-new-domain", Severity: cli.SeverityMedium, File: "a.php", Line: 3},
		{ID: "decode-exec", Severity: cli.SeverityCritical},
	}
	got := strings.Join(c.Check(bad), "\n")
	for _, w := range []string{
		"want eval-dynamic at high or worse, it did not fire",
		"outbound-new-domain fired at medium, want at most info (a.php:3)",
		"decode-exec fired at critical, want none",
	} {
		if !strings.Contains(got, w) {
			t.Errorf("problems %q lack %q", got, w)
		}
	}
}

// The subject fills names, versions and the clock, keeps an added
// package's old side empty and uses the case's features.
func TestSubject(t *testing.T) {
	c := &Case{Signal: "eval-dynamic", Name: "pos-1", Eco: core.Composer,
		New:         map[string]string{"src/a.php": "<?php"},
		FeaturesNew: coretest.Features(coretest.Feat(core.FEval, "eval", "src/a.php", 1))}
	s := c.Subject(t)
	if s.Old != nil || s.OldTree != nil || s.OldFeatures != nil {
		t.Errorf("added package has an old side: %+v", s.Old)
	}
	if s.Update.String() != "composer:acme/fixture@2.0.0" || !s.Now.Equal(DefaultNow) || s.Config == nil {
		t.Errorf("defaults: %v %v", s.Update, s.Now)
	}
	if len(s.Diff.Changes) != 1 || s.Diff.Changes[0].Kind != core.Added {
		t.Errorf("diff: %+v", s.Diff.Changes)
	}
	if len(s.NewFeatures.NewIn(s.OldFeatures)) != 1 {
		t.Error("the case's features were not used")
	}

	c = &Case{Signal: "owner-change", Name: "pos-1", Eco: core.NPM, MetaOld: &core.Meta{}}
	s = c.Subject(t)
	if s.Old == nil || s.Old.Ref.Version != "1.0.0" || s.OldTree == nil || len(s.OldFeatures.ByKey) != 0 {
		t.Errorf("meta-only old side: %+v", s.Old)
	}
}

func TestRunWithFakeDetector(t *testing.T) {
	(&coretest.FakeDetector{Name: "fake", Findings: []core.Finding{{ID: "eval-dynamic", Severity: cli.SeverityHigh}}}).Install(t)
	if !Emitted()["eval-dynamic"] || Emitted()["decode-exec"] {
		t.Errorf("emitted %v", Emitted())
	}
	c := &Case{Signal: "eval-dynamic", Name: "pos-1", Eco: core.NPM, FeaturesNew: core.NewFeatureSet(),
		Expect: []Expect{{ID: "eval-dynamic", Min: cli.SeverityHigh}}}
	Run(t, c)
}

func TestSnake(t *testing.T) {
	for in, want := range map[string]string{
		"RequiresPHP": "requires_php", "EndLine": "end_line", "OldIntegrity": "old_integrity",
		"URL": "url", "DepInfo": "dep_info", "HasInstallScript": "has_install_script", "GitTag": "git_tag",
	} {
		if got := snake(in); got != want {
			t.Errorf("snake(%s) = %s, want %s", in, got, want)
		}
	}
}
