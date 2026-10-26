// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package code

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// fileSubject is an update from old to new files with the given
// candidate features and none installed.
func fileSubject(t *testing.T, old, new map[string]string, feats *core.FeatureSet) *core.Subject {
	t.Helper()
	s := &core.Subject{Update: core.Ref{Eco: core.WPPlugin, Name: "x", Version: "2"},
		NewTree: coretest.Tree(new), OldFeatures: coretest.Features(), NewFeatures: feats, Config: &core.Config{}}
	ot := coretest.Tree(old)
	if old != nil {
		s.Old, s.OldTree = &core.Meta{}, ot
	}
	d, err := coretest.FakeDiffer{}.Diff(context.Background(), ot, s.NewTree)
	if err != nil {
		t.Fatal(err)
	}
	s.Diff = d
	return s
}

func TestBuiltinRules(t *testing.T) {
	want := map[string]string{
		"eval-base64": SigDecodeExec, "gzinflate-base64": SigDecodeExec, "create-function-input": SigEvalDynamic,
		"assert-request": SigEvalDynamic, "preg-replace-e": SigEvalDynamic, "mu-hidden-admin": SigAdminUserHidden,
		"webshell": SigRemoteFetchExec,
	}
	rs := BuiltinRules()
	if len(rs) != len(want) {
		t.Errorf("%d rules, want %d", len(rs), len(want))
	}
	for _, r := range rs {
		if want[r.ID] != r.Signal {
			t.Errorf("%s fires %s, want %s", r.ID, r.Signal, want[r.ID])
		}
		b, err := fs.ReadFile(embeddedRules, "rules/"+r.ID+".yaml")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "# Derived from tuner/local/rules/local-malware-"+r.ID+".yaml") {
			t.Errorf("%s: no Derived from line naming its Tuner rule", r.ID)
		}
	}
}

func TestParseRuleErrors(t *testing.T) {
	const ok = "id: x\nname: X\nsignal: eval-dynamic\nfiles: ['**/*.php']\nmatch: {regex: ['eval\\(']}\n"
	if _, err := ParseRule("x.yaml", []byte(ok)); err != nil {
		t.Fatalf("valid rule: %v", err)
	}
	for _, c := range []struct{ body, want string }{
		{strings.Replace(ok, "eval-dynamic", "evl-dynamic", 1), `x.yaml: signal: "evl-dynamic" is not a signal ID a detector emits`},
		{strings.Replace(ok, "eval-dynamic", "approved-version-changed", 1), `x.yaml: signal: "approved-version-changed" is not a signal ID`},
		{strings.Replace(ok, "signal: eval-dynamic\n", "", 1), "x.yaml: signal: missing"},
		{ok + "sevrity: high\n", `x.yaml: line 6: unknown key "sevrity"`},
		{strings.Replace(ok, "regex:", "regx:", 1), `x.yaml: match: line 5: unknown key "regx"`},
		{strings.Replace(ok, `eval\(`, `eval(`, 1), "x.yaml: match.regex: "},
		{ok + "side: removed\n", `x.yaml: side: "removed": want added or any`},
		{ok + "severity: severe\n", `x.yaml: severity: "severe"`},
		{strings.Replace(ok, "id: x", "id: X Y", 1), `x.yaml: id: "X Y"`},
		{strings.Replace(ok, "files: ['**/*.php']\n", "", 1), "x.yaml: files: missing"},
		{strings.Replace(ok, "'**/*.php'", "'/abs/*.php'", 1), "x.yaml: files: glob"},
		{strings.Replace(ok, "{regex: ['eval\\(']}", "{not: ['x']}", 1), "x.yaml: match: give filename, regex, words or magic"},
		{"- a\n- b\n", "x.yaml: a rule is a mapping"},
		{ok + "id: y\n", "x.yaml: id: line 6: given twice"},
	} {
		_, err := ParseRule("x.yaml", []byte(c.body))
		if err == nil || !strings.HasPrefix(err.Error(), c.want) {
			t.Errorf("got %v\nwant prefix %s", err, c.want)
		}
	}
}

func writeRule(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A bad --signals file is E12 (exit 2) naming the file and the key.
func TestLoadRuleDirsE12(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "bad.yaml", "id: bad\nname: B\nsignal: evl-dynamic\nfiles: ['**/*.php']\nmatch: {words: [x]}\n")
	_, err := LoadRuleDirs([]string{dir})
	if core.CodeOf(err) != core.EBadConfig {
		t.Fatalf("code %q: %v", core.CodeOf(err), err)
	}
	var e *core.Error
	if !errors.As(err, &e) || e.ExitCode() != cli.ExitUsage {
		t.Fatalf("exit: %v", err)
	}
	want := filepath.Join(dir, "bad.yaml") + `: signal: "evl-dynamic" is not a signal ID a detector emits (rhythm sightread signals lists them)`
	if e.What != want || e.Hint[0] != "fix the rule file or leave its folder out of --signals" {
		t.Errorf("what %q hint %q", e.What, e.Hint)
	}

	dup := t.TempDir()
	writeRule(t, dup, "a.yaml", "id: webshell\nname: W\nsignal: eval-dynamic\nfiles: ['**/*.php']\nmatch: {words: [x]}\n")
	if _, err := LoadRuleDirs([]string{dup}); err == nil || !strings.Contains(err.Error(), `id: "webshell" is already used by rules`) {
		t.Errorf("duplicate of a shipped ID: %v", err)
	}
}

// An extra rule from --signals fires through the subject's config; its
// test fixtures (*_test.yaml) are not rules.
func TestExtraRuleFires(t *testing.T) {
	dir := t.TempDir()
	writeRule(t, dir, "beacon.yaml", "id: beacon\nname: Beacon call\nsignal: outbound-new-domain\nseverity: low\nfiles: ['**/*.js']\nmatch: {regex: ['beacon\\(']}\n")
	writeRule(t, dir, "beacon_test.yaml", "not: a rule\n")
	if _, err := LoadRuleDirs([]string{dir}); err != nil {
		t.Fatal(err)
	}
	s := fileSubject(t, map[string]string{}, map[string]string{"a.js": "x();\nbeacon('/p');\n"}, coretest.Features())
	s.Update.Eco = core.NPM
	s.Config.Signals.Dirs = []string{dir}
	got := detectAll(t, ruleDetector{}, s)
	if len(got) != 1 || got[0].ID != SigOutboundNewDomain || got[0].Severity != cli.SeverityLow || got[0].Line != 2 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Evidence.String() != "Beacon call: beacon('/p');" {
		t.Errorf("evidence %q", got[0].Evidence)
	}
}

// A rule match where the Go detector already fired on the same file and
// line is dropped: one finding, not two.
func TestRuleNotDoubled(t *testing.T) {
	files := map[string]string{"a.php": "<?php\neval(base64_decode($x));\n"}
	feat := coretest.Feat(core.FEval, "eval", "a.php", 2, AttrArg, "base64_decode($x)", AttrSource, SrcDecode)
	both := func(s *core.Subject) []core.Finding {
		return append(detectAll(t, execDetector{}, s), detectAll(t, ruleDetector{}, s)...)
	}
	if got := ids(both(fileSubject(t, map[string]string{}, files, coretest.Features(feat)))); got != SigDecodeExec {
		t.Errorf("with the feature: %s", got)
	}
	if got := ids(both(fileSubject(t, map[string]string{}, files, coretest.Features()))); got != SigDecodeExec {
		t.Errorf("rule alone: %s", got)
	}
	// eval-dynamic from the Go detector covers an execution rule too.
	dyn := coretest.Feat(core.FEval, "eval", "a.php", 2, AttrSource, SrcVariable)
	if got := ids(both(fileSubject(t, map[string]string{}, files, coretest.Features(dyn)))); got != SigEvalDynamic {
		t.Errorf("eval-dynamic on the line: %s", got)
	}
	// A Go finding on another line does not hide the rule's.
	other := coretest.Feat(core.FEval, "eval", "a.php", 9, AttrSource, SrcVariable)
	if got := ids(both(fileSubject(t, map[string]string{}, files, coretest.Features(other)))); got != "eval-dynamic,decode-exec" {
		t.Errorf("other line: %s", got)
	}
}

// Side any looks at files the update left alone; side added does not.
func TestRuleSides(t *testing.T) {
	files := map[string]string{"a.php": "<?php $default_action = 'FilesMan';"}
	s := fileSubject(t, files, files, coretest.Features())
	if got := detectAll(t, ruleDetector{}, s); len(got) != 0 {
		t.Errorf("side added on an unchanged file: %v", ids(got))
	}
	dir := t.TempDir()
	writeRule(t, dir, "any.yaml", "id: shell-any\nname: Shell\nsignal: remote-fetch-exec\nside: any\nfiles: ['**/*.php']\nmatch: {words: [FilesMan]}\n")
	s.Config.Signals.Dirs = []string{dir}
	if got := ids(detectAll(t, ruleDetector{}, s)); got != SigRemoteFetchExec {
		t.Errorf("side any: %q", got)
	}
}

// Matched text is masked before it is cut, so no part of a key shows.
func TestRuleSnippetMasked(t *testing.T) {
	key := coretest.FakeKey(coretest.KeyStripe)
	line := "eval(base64_decode('" + key + "'));"
	got := ruleSnippetAt([]byte(line), 0)
	if strings.Contains(got, key[:12]) {
		t.Errorf("key shows: %q", got)
	}
	long := ruleSnippetAt([]byte("eval("+strings.Repeat("é", 100)+")\nnext"), 0)
	if len(long) > ruleSnippet+len("…") || !strings.HasSuffix(long, "…") {
		t.Errorf("cut: %d bytes %q", len(long), long)
	}
}

func TestGlobMatch(t *testing.T) {
	for _, c := range []struct {
		glob, path string
		want       bool
	}{
		{"**/*.php", "a.php", true},
		{"**/*.php", "a/b/C.PHP", true},
		{"**/*.php", "a.php.txt", false},
		{"vendor/**", "vendor/a/b.php", true},
		{"vendor/**", "src/vendor.php", false},
		{"**/mu-plugins/**/*.php", "mu-plugins/x.php", true},
		{"**/mu-plugins/**/*.php", "a/mu-plugins/b/x.php", true},
		{"**/mu-plugins/**/*.php", "plugins/x.php", false},
		{"**/*.php[0-9]", "x.php7", true},
		{"*.php", "a/b.php", false},
	} {
		if got := newGlob(c.glob).match(c.path); got != c.want {
			t.Errorf("%s ~ %s = %v, want %v", c.glob, c.path, got, c.want)
		}
	}
}

func TestLiteralHints(t *testing.T) {
	h := literalHints(`(?i)\b(?:gzinflate|gzuncompress|gzdecode)\s*\(`)
	if len(h) == 0 {
		t.Fatal("no hints")
	}
	found := map[string]bool{}
	for _, w := range h[0] {
		found[string(w)] = true
	}
	if !found["gzinflate"] || !found["gzdecode"] || found["decode"] {
		t.Errorf("hints %q", h[0])
	}
	if literalHints(`a.b`) != nil {
		t.Error("short literals give no hint")
	}
}

func TestCommentLine(t *testing.T) {
	for l, want := range map[string]bool{
		"// eval(base64_decode($x))":          true,
		"# eval(base64_decode($x))":           true,
		"* eval(base64_decode($x))":           true,
		"#[Attr] eval(base64_decode($x));":    false,
		"*/ eval(base64_decode($x));":         false,
		"// ?> <?php eval(base64_decode($x))": false,
		"eval(base64_decode($x)); // done":    false,
	} {
		if got := commentLine(l); got != want {
			t.Errorf("commentLine(%q) = %v, want %v", l, got, want)
		}
	}
}

// A not exemption counts only when the whole file was read.
func TestNotNeedsWholeFile(t *testing.T) {
	r, err := ParseRule("x.yaml", []byte("id: x\nname: X\nsignal: eval-dynamic\nfiles: ['**']\nmatch: {words: [shell], not: ['harmless']}\n"))
	if err != nil {
		t.Fatal(err)
	}
	b := []byte("shell harmless")
	if r.matches(b, true) != nil {
		t.Error("exempt when whole")
	}
	if r.matches(b, false) == nil {
		t.Error("a cut file can't be shown harmless")
	}
}

// FuzzParseRule: any bytes give a rule or an error naming the file,
// never a panic.
func FuzzParseRule(f *testing.F) {
	for _, r := range BuiltinRules() {
		b, _ := fs.ReadFile(embeddedRules, "rules/"+r.ID+".yaml")
		f.Add(b)
	}
	f.Add([]byte("id: x\nmatch: {regex: ['(']}\n"))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := ParseRule("f.yaml", b)
		if err == nil && (r.Signal == "" || len(r.files) == 0) {
			t.Fatalf("accepted an incomplete rule: %+v", r)
		}
		if err != nil && !strings.HasPrefix(err.Error(), "f.yaml") {
			t.Fatalf("error does not name the file: %v", err)
		}
	})
}
