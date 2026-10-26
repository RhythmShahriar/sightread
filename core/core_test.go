// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

func TestParseRef(t *testing.T) {
	for _, c := range []struct {
		in   string
		want core.Ref
		str  string
	}{
		{"npm:@a/b@1.2.3", core.Ref{Eco: core.NPM, Name: "@a/b", Version: "1.2.3"}, "npm:@a/b@1.2.3"},
		{"npm:@a/b", core.Ref{Eco: core.NPM, Name: "@a/b"}, "npm:@a/b"},
		{"npm:left-pad@1.3.0", core.Ref{Eco: core.NPM, Name: "left-pad", Version: "1.3.0"}, "npm:left-pad@1.3.0"},
		{"wp-plugin:akismet", core.Ref{Eco: core.WPPlugin, Name: "akismet"}, "wp-plugin:akismet"},
		{"plugin:akismet@5.3.5", core.Ref{Eco: core.WPPlugin, Name: "akismet", Version: "5.3.5"}, "wp-plugin:akismet@5.3.5"},
		{"theme:astra@4.8.1", core.Ref{Eco: core.WPTheme, Name: "astra", Version: "4.8.1"}, "wp-theme:astra@4.8.1"},
		{"composer:monolog/monolog@3.12.1", core.Ref{Eco: core.Composer, Name: "monolog/monolog", Version: "3.12.1"}, "composer:monolog/monolog@3.12.1"},
		{"npm:@a/b@1.0.0-beta.1", core.Ref{Eco: core.NPM, Name: "@a/b", Version: "1.0.0-beta.1"}, "npm:@a/b@1.0.0-beta.1"},
	} {
		got, err := core.ParseRef(c.in)
		if err != nil || got != c.want {
			t.Errorf("ParseRef(%q) = %+v, %v; want %+v", c.in, got, err, c.want)
			continue
		}
		if got.String() != c.str {
			t.Errorf("ParseRef(%q).String() = %q, want %q", c.in, got.String(), c.str)
		}
	}
}

func TestParseRefRefuses(t *testing.T) {
	for _, in := range []string{
		"", "akismet", "gem:rails", "npm:", "npm:@a/b@", "npm:@", "npm:@a", "npm:@/b", "npm:a/b",
		"npm:@a/b/c", "composer:monolog", "composer:/x", "composer:a/b/c", "plugin:a/b", "plugin:a b",
		"plugin:a\x1b", "npm:a@1 2", "npm:a@1:2", "plugin:" + strings.Repeat("a", 257),
	} {
		if r, err := core.ParseRef(in); err == nil {
			t.Errorf("ParseRef(%q) = %+v, want an error", in, r)
		}
	}
}

// FuzzParseRef: whatever parses prints back to something that parses to
// the same reference. Nothing panics.
func FuzzParseRef(f *testing.F) {
	for _, s := range []string{"npm:@a/b@1.2.3", "plugin:akismet@5.3.5", "composer:a/b", "theme:x@", "npm:@@", "wp-theme:\u202e"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r, err := core.ParseRef(s)
		if err != nil {
			return
		}
		back, err := core.ParseRef(r.String())
		if err != nil || back != r {
			t.Fatalf("ParseRef(%q) = %+v; its String %q parses to %+v, %v", s, r, r.String(), back, err)
		}
	})
}

func TestParseEcosystem(t *testing.T) {
	for in, want := range map[string]core.Ecosystem{"plugin": core.WPPlugin, "wp-plugin": core.WPPlugin,
		"theme": core.WPTheme, "wp-theme": core.WPTheme, "composer": core.Composer, "npm": core.NPM} {
		if got, err := core.ParseEcosystem(in); err != nil || got != want {
			t.Errorf("ParseEcosystem(%q) = %q, %v", in, got, err)
		}
	}
	if _, err := core.ParseEcosystem("pip"); err == nil {
		t.Error("ParseEcosystem(pip) succeeded")
	}
}

// TestSnippetMasks: every fake key kind is masked and escape bytes and
// bidi overrides never pass through.
func TestSnippetMasks(t *testing.T) {
	for _, kind := range coretest.FakeKeyKinds() {
		key := coretest.FakeKey(kind)
		s := core.NewSnippet("const token = '" + key + "'; // " + kind).String()
		if strings.Contains(s, key) {
			t.Errorf("%s: snippet %q holds the raw key", kind, s)
		}
	}
	s := core.NewSnippet("a\x1b[2Jb\u202ec\u2066d").String()
	if strings.ContainsAny(s, "\x1b\u202e\u2066") {
		t.Errorf("snippet %q holds an escape or bidi character", s)
	}
	if !strings.Contains(s, `\x1b`) {
		t.Errorf("snippet %q doesn't show the escape byte as \\x1b", s)
	}
	// A bidi control is shown as its escape, not dropped: it is what a
	// unicode-hidden finding reports.
	if s != `a\x1b[2Jb\u202ec\u2066d` {
		t.Errorf("snippet %q, want the bidi controls escaped", s)
	}
	var back core.Snippet
	if err := back.UnmarshalJSON([]byte(`"a\\u202eb"`)); err != nil || back.String() != `a\u202eb` {
		t.Errorf("read back %q %v", back.String(), err)
	}
}

func TestSnippetCut(t *testing.T) {
	if s := core.NewSnippet("short").String(); s != "short" {
		t.Errorf("short snippet = %q", s)
	}
	for _, unit := range []string{"a", "é", "日本", "🎵"} {
		raw := strings.Repeat(unit, 400)
		s := core.NewSnippet(raw).String()
		if len(s) > core.SnippetMax || !utf8.ValidString(s) || !strings.HasSuffix(s, "…") {
			t.Errorf("%q x400: %d bytes, valid %v, %q at the end", unit, len(s), utf8.ValidString(s), s[len(s)-6:])
		}
	}
}

// TestSnippetJSON: a snippet read back from a report is the same text,
// and raw text in a report file goes through NewSnippet.
func TestSnippetJSON(t *testing.T) {
	in := core.NewSnippet("eval(base64_decode($x)) " + coretest.FakeKey(coretest.KeyGitHub) + " \x1b")
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var back core.Snippet
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back != in {
		t.Errorf("round trip: %q, want %q", back, in)
	}
	raw, _ := json.Marshal("x \u001b y " + coretest.FakeKey(coretest.KeyNPM))
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(back.String(), "\x1b") || strings.Contains(back.String(), coretest.FakeKey(coretest.KeyNPM)) {
		t.Errorf("raw report text came back unsafe: %q", back)
	}
}

func TestFingerprint(t *testing.T) {
	ev := core.NewSnippet("wp_remote_get($u)  →\n eval($b)")
	fp := core.Fingerprint(core.WPPlugin, "countdown-timer-ultimate", "2.6.8", "remote-fetch-exec", "includes/a.php", ev)
	if len(fp) != 16 {
		t.Fatalf("fingerprint %q is not 16 hex", fp)
	}
	// Pinned: a change here breaks every --baseline and SARIF history.
	if fp != "50beebd155fd8a6a" {
		t.Errorf("fingerprint = %q; it changed", fp)
	}
	same := []string{
		core.Fingerprint(core.WPPlugin, "countdown-timer-ultimate", "2.6.8", "remote-fetch-exec", `includes\a.php`, ev),
		core.Fingerprint(core.WPPlugin, "countdown-timer-ultimate", "2.6.8", "remote-fetch-exec", "/includes/a.php", ev),
		core.Fingerprint(core.WPPlugin, "countdown-timer-ultimate", "2.6.8", "remote-fetch-exec", "includes/./a.php",
			core.NewSnippet("wp_remote_get($u) → eval($b)")),
	}
	for i, s := range same {
		if s != fp {
			t.Errorf("variant %d: %q, want %q", i, s, fp)
		}
	}
	if other := core.Fingerprint(core.WPPlugin, "countdown-timer-ultimate", "2.6.9", "remote-fetch-exec", "includes/a.php", ev); other == fp {
		t.Error("another version gives the same fingerprint")
	}
}

func TestManifestHash(t *testing.T) {
	a := coretest.Tree(map[string]string{"a.php": "<?php echo 1;", "b/c.js": "x()"})
	files := slices.Clone(a.Files)
	slices.Reverse(files)
	if core.ManifestHash(files) != core.ManifestHash(a.Files) {
		t.Error("ManifestHash depends on order")
	}
	got := core.ManifestHash(a.Files)
	// Pinned: allow entries with hash: manifest are bound to this.
	if h := hex.EncodeToString(got[:4]); h != "b0a3c216" {
		t.Errorf("ManifestHash starts %s; it changed", h)
	}
	b := coretest.Tree(map[string]string{"a.php": "<?php echo 2;", "b/c.js": "x()"})
	if core.ManifestHash(b.Files) == got {
		t.Error("a changed file gives the same manifest hash")
	}
}

func TestTreeLookup(t *testing.T) {
	tr := coretest.Tree(map[string]string{"z.php": "z", "a.php": "a", "m/n.js": "n"})
	for _, p := range []string{"a.php", "m/n.js", "z.php"} {
		if f, ok := tr.Lookup(p); !ok || f.Path != p {
			t.Errorf("Lookup(%q) = %+v, %v", p, f, ok)
		}
	}
	if _, ok := tr.Lookup("b.php"); ok {
		t.Error("Lookup found a missing file")
	}
}

func TestFeatureSetNewIn(t *testing.T) {
	old := coretest.Features(
		coretest.Feat(core.FDomain, "example.com", "a.php", 3),
		coretest.Feat(core.FEval, "eval", "a.php", 9),
	)
	cur := coretest.Features(
		coretest.Feat(core.FDomain, "example.com", "moved.php", 1), // moved: not new
		coretest.Feat(core.FDomain, "evil.example", "b.php", 7),
		coretest.Feat(core.FDomain, "evil.example", "a.php", 20),
		coretest.Feat(core.FCron, "hourly", "a.php", 2),
	)
	var got []string
	for _, f := range cur.NewIn(old) {
		got = append(got, f.Ev.Path+":"+strconv.Itoa(f.Ev.Line)+":"+f.SetKey())
	}
	want := []string{"a.php:2:cron:hourly", "a.php:20:domain:evil.example", "b.php:7:domain:evil.example"}
	if !slices.Equal(got, want) {
		t.Errorf("NewIn = %v, want %v", got, want)
	}
	if n := len(cur.NewIn(nil)); n != 4 {
		t.Errorf("NewIn(nil) gave %d features, want all 4", n)
	}
	if !cur.Has(core.FCron, "hourly") || cur.Has(core.FEval, "eval") {
		t.Error("Has is wrong")
	}
	var nilSet *core.FeatureSet
	if nilSet.Has(core.FEval, "eval") || nilSet.NewIn(old) != nil {
		t.Error("a nil set has features")
	}
}

// catalogueIDs is PRD section 12.1, in order.
var catalogueIDs = []string{
	"integrity-mismatch", "version-republished", "approved-version-changed", "known-malicious", "wporg-closed",
	"archive-path-escape", "remote-fetch-exec", "decode-exec", "admin-user-hidden", "lockfile-source-change",
	"archive-link", "archive-collision", "unanalysed", "eval-dynamic", "obfuscation", "input-unserialize",
	"write-outside-package", "admin-user-create", "capability-change", "update-suppression", "bot-cloaking",
	"credential-access", "data-exfil", "code-in-asset", "npm-install-script-new", "composer-plugin-new",
	"owner-change", "provenance-dropped", "typosquat", "known-vulnerable", "dependency-confusion",
	"outbound-new-domain", "rest-open-route", "changelog-mismatch", "dependency-new", "composer-autoload-files",
	"fresh-release", "dormant-release", "git-tag-missing", "size-jump", "unicode-hidden", "secret-added",
	"cron-new-hook", "license-change", "abandoned", "local-drift", "php-requirement", "files-removed",
}

func TestCatalog(t *testing.T) {
	if got := core.SignalIDs(); !slices.Equal(got, catalogueIDs) {
		t.Fatalf("catalogue IDs differ from PRD 12.1:\n got %v\nwant %v", got, catalogueIDs)
	}
	if len(core.Catalog) != 48 {
		t.Errorf("catalogue has %d signals, want 48", len(core.Catalog))
	}
	var unign []string
	for _, s := range core.Catalog {
		if s.Title == "" || s.Severity == cli.SeverityNone || len(s.Ecosystems) == 0 {
			t.Errorf("%s: missing title, severity or ecosystems", s.ID)
		}
		if _, ok := core.ParseConfidence(string(s.Confidence)); !ok {
			t.Errorf("%s: confidence %q", s.ID, s.Confidence)
		}
		if strings.ContainsRune(s.Title, 0x2014) || strings.Contains(strings.ToLower(s.Title), "malware") || strings.Contains(strings.ToLower(s.Title), "backdoor") {
			t.Errorf("%s: title %q names intent or breaks the writing rules", s.ID, s.Title)
		}
		want := core.EmitDetect
		if s.ID == "approved-version-changed" {
			want = core.EmitPolicy
		}
		if s.Emitter != want {
			t.Errorf("%s: emitter %q, want %q", s.ID, s.Emitter, want)
		}
		if s.Unignorable {
			unign = append(unign, s.ID)
			if s.Severity != cli.SeverityCritical {
				t.Errorf("%s: unignorable but not critical", s.ID)
			}
		}
	}
	wantUnign := []string{"integrity-mismatch", "version-republished", "approved-version-changed", "known-malicious", "archive-path-escape"}
	if !slices.Equal(unign, wantUnign) {
		t.Errorf("unignorable = %v, want %v", unign, wantUnign)
	}
	if !core.Unignorable("known-malicious") || core.Unignorable("eval-dynamic") || core.Unignorable("nope") {
		t.Error("Unignorable is wrong")
	}
	if s, ok := core.Signal("typosquat"); !ok || s.Severity != cli.SeverityHigh || s.Confidence != core.Likely {
		t.Errorf("Signal(typosquat) = %+v, %v", s, ok)
	}
	if _, ok := core.Signal("nope"); ok {
		t.Error("Signal found an unknown ID")
	}
}

// dots is a tiny version scheme: dot-separated numbers, "-" starts a
// prerelease, a constraint is ">=<version>".
type dots struct{}

func (dots) Valid(v string) bool {
	main, _, _ := strings.Cut(v, "-")
	for _, p := range strings.Split(main, ".") {
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	return true
}

func (dots) Prerelease(v string) bool { return strings.Contains(v, "-") }

func (dots) Compare(a, b string) int {
	am, _, _ := strings.Cut(a, "-")
	bm, _, _ := strings.Cut(b, "-")
	ap, bp := strings.Split(am, "."), strings.Split(bm, ".")
	for i := 0; i < max(len(ap), len(bp)); i++ {
		var x, y int
		if i < len(ap) {
			x, _ = strconv.Atoi(ap[i])
		}
		if i < len(bp) {
			y, _ = strconv.Atoi(bp[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

func (d dots) Satisfies(v, c string) (bool, error) {
	min, ok := strings.CutPrefix(c, ">=")
	if !ok || !d.Valid(min) {
		return false, errors.New("bad constraint")
	}
	return d.Compare(v, min) >= 0, nil
}

func TestNewest(t *testing.T) {
	vs := []string{"1.0", "1.10", "1.9", "2.0-beta", "junk", "1.2"}
	for _, c := range []struct {
		constraint string
		pre        bool
		want       string
	}{
		{"", false, "1.10"},
		{"", true, "2.0-beta"},
		{">=1.9", false, "1.10"},
		{">=3.0", false, ""},
		{"~bad", false, ""},
	} {
		if got := core.Newest(dots{}, vs, c.constraint, c.pre); got != c.want {
			t.Errorf("Newest(%q, pre %v) = %q, want %q", c.constraint, c.pre, got, c.want)
		}
	}
	if got := core.Newest(dots{}, nil, "", false); got != "" {
		t.Errorf("Newest(nil) = %q", got)
	}
}

func TestErrorText(t *testing.T) {
	t.Setenv(cli.InvokedAsEnv, "rhythm sightread")
	cause := errors.New("dial tcp: connection refused")
	e := &core.Error{Code: core.EVersionMissing, Exit: cli.ExitUsage, Command: "plugin",
		What: "akismet has no version 9.9.9 on wordpress.org",
		Hint: []string{"newest: 5.3.5 · see them all: rhythm sightread plugin akismet --to list"}, Err: cause}
	want := "rhythm sightread plugin: akismet has no version 9.9.9 on wordpress.org\n" +
		"  newest: 5.3.5 · see them all: rhythm sightread plugin akismet --to list"
	if e.Error() != want {
		t.Errorf("Error() =\n%s\nwant\n%s", e.Error(), want)
	}
	if !errors.Is(e, cause) || core.CodeOf(e) != core.EVersionMissing || e.ExitCode() != cli.ExitUsage {
		t.Error("Unwrap, CodeOf or ExitCode is wrong")
	}
	tool := &core.Error{Code: core.ENetwork, What: "can't reach registry.npmjs.org (no such host)"}
	if tool.Error() != "rhythm sightread: can't reach registry.npmjs.org (no such host)" {
		t.Errorf("tool-wide Error() = %q", tool.Error())
	}
	if tool.ExitCode() != cli.ExitUnavailable {
		t.Errorf("zero Exit gives %d, want 3", tool.ExitCode())
	}
	if core.CodeOf(errors.New("x")) != "" {
		t.Error("CodeOf of a plain error")
	}
}

func TestDefaultLimits(t *testing.T) {
	l := core.DefaultLimits()
	if l.Download != 256<<20 || l.Uncompressed != 1<<30 || l.EntryStored != 64<<20 || l.EntryAnalysed != 4<<20 ||
		l.JSON != 32<<20 || l.Entries != 100000 || l.Ratio != 200 || l.FileBudget.Seconds() != 2 {
		t.Errorf("DefaultLimits = %+v", l)
	}
}

func TestIntegrityPartial(t *testing.T) {
	if !(core.Integrity{By: core.ByNone}).Partial() || (core.Integrity{By: core.ByFailed}).Partial() {
		t.Error("Partial is wrong: none is partial, failed never is")
	}
}

func TestFindingCounted(t *testing.T) {
	for _, f := range []core.Finding{{Allowed: &core.AllowMatch{}}, {Ignored: true}, {Baselined: true}, {BelowConfidence: true}} {
		if f.Counted() {
			t.Errorf("%+v counts", f)
		}
	}
	if f := (core.Finding{}); !f.Counted() {
		t.Error("a plain finding doesn't count")
	}
}

// TestInLockfile: only the lockfile signals on a lockfile path are
// outside the package; a package that ships a lockfile keeps its diff.
func TestInLockfile(t *testing.T) {
	for _, c := range []struct {
		f    core.Finding
		want bool
	}{
		{core.Finding{ID: "dependency-new", File: "package-lock.json"}, true},
		{core.Finding{ID: "version-republished", File: "api/composer.lock"}, true},
		{core.Finding{ID: "lockfile-source-change", File: "yarn.lock"}, true},
		{core.Finding{ID: "dependency-new", File: "package.json"}, false},
		{core.Finding{ID: "eval-dynamic", File: "package-lock.json"}, false},
		{core.Finding{ID: "dependency-new"}, false},
	} {
		if got := c.f.InLockfile(); got != c.want {
			t.Errorf("%s %q: %v, want %v", c.f.ID, c.f.File, got, c.want)
		}
	}
}
