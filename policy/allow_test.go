// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package policy

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/core"
)

var (
	shaA = strings.Repeat("a", 64)
	shaB = strings.Repeat("b", 64)
)

func entry(pkg, version, sha string) core.AllowEntry {
	return core.AllowEntry{Package: pkg, Version: version, SHA256: sha,
		Reason: "checked the code", By: "Ann Reviewer", Date: "2026-10-20"}
}

const allowYAML = `# Versions someone reviewed.
allowed:
  - package: wp-plugin:wordfence
    version: 7.11.7
    sha256: ` + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + `
    hash: manifest
    reason: new cron hook is the scheduled scan, checked the code
    by: Rhythm Shahriar
    date: 2026-10-20
  - package: npm:sharp
    version: 0.33.5
    sha256: ` + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + `
    signals: [npm-install-script-new]
    reason: prebuilt binary download, known install script
    by: Rhythm Shahriar
    date: 2026-10-22
    until: 2027-01-31
  - package: plugin:old-thing
    version: "1.0"
    sha256: ` + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc" + `
    reason: reviewed long ago
    by: Rhythm Shahriar
    date: 2026-01-01
    until: 2026-10-25
`

func loadAllowIn(t *testing.T, dir, content string) *AllowSet {
	t.Helper()
	writeFile(t, filepath.Join(dir, Dir, AllowName), content)
	set, err := testStore(nil).LoadAllow(&core.Config{}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	return set.(*AllowSet)
}

func TestAllowMatch(t *testing.T) {
	dir := inProject(t)
	set := loadAllowIn(t, dir, allowYAML)
	cases := []struct {
		name                   string
		eco                    core.Ecosystem
		pkg, version, sha      string
		match, counted, confl  bool
		wantSignals            []string
		wantSourceForMatchFile bool
	}{
		{"exact, hash in another case", core.WPPlugin, "wordfence", "7.11.7", shaA, true, true, false, nil, true},
		{"same version other hash", core.WPPlugin, "wordfence", "7.11.7", shaB, false, false, true, nil, false},
		{"other version", core.WPPlugin, "wordfence", "7.11.8", shaA, false, false, false, nil, false},
		{"other ecosystem", core.WPTheme, "wordfence", "7.11.7", shaA, false, false, false, nil, false},
		{"no hash", core.WPPlugin, "wordfence", "7.11.7", "", false, false, true, nil, false},
		{"signals kept", core.NPM, "sharp", "0.33.5", shaB, true, true, false, []string{"npm-install-script-new"}, true},
		{"expired entry", core.WPPlugin, "old-thing", "1.0", strings.Repeat("c", 64), false, false, false, nil, false},
		{"expired entry is no conflict", core.WPPlugin, "old-thing", "1.0", shaA, false, false, false, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, counted, conflict := set.Match(tc.eco, tc.pkg, tc.version, tc.sha)
			if (m != nil) != tc.match || counted != tc.counted || (conflict != nil) != tc.confl {
				t.Fatalf("match %v counted %v conflict %v", m, counted, conflict)
			}
			if m != nil && !reflect.DeepEqual(m.Signals, tc.wantSignals) {
				t.Errorf("signals %v", m.Signals)
			}
			if m != nil && set.Source(m) != ".sightread/allowed.yaml" {
				t.Errorf("source %q", set.Source(m))
			}
		})
	}
	if got := len(set.Entries()); got != 3 {
		t.Errorf("entries %d", got)
	}
	// The package is stored with its full ecosystem ID.
	if got := set.Entries()[2].Package; got != "wp-plugin:old-thing" {
		t.Errorf("package %q", got)
	}
}

func TestAllowUntilToday(t *testing.T) {
	dir := inProject(t)
	e := entry("npm:a", "1.0.0", shaA)
	e.Until = "2026-10-26"
	set := loadAllowIn(t, dir, mustAllowYAML(t, e))
	if m, counted, _ := set.Match(core.NPM, "a", "1.0.0", shaA); m == nil || !counted {
		t.Fatal("an entry applies through its until day")
	}
}

func TestAllowReReviewedHasNoConflict(t *testing.T) {
	dir := inProject(t)
	set := loadAllowIn(t, dir, mustAllowYAML(t, entry("npm:a", "1.0.0", shaA), entry("npm:a", "1.0.0", shaB)))
	m, counted, conflict := set.Match(core.NPM, "a", "1.0.0", shaB)
	if m == nil || !counted || conflict != nil {
		t.Fatalf("match %v counted %v conflict %v", m, counted, conflict)
	}
}

func mustAllowYAML(t *testing.T, entries ...core.AllowEntry) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "a.yaml")
	for _, e := range entries {
		if err := testStore(nil).AddAllow(p, e); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(p) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestAllowFrom(t *testing.T) {
	dir := inProject(t)
	writeConfig(t, dir, "allow_from: [../shared/allowed.yaml]\nallow_file: reviews.yaml\n")
	writeFile(t, filepath.Join(dir, "reviews.yaml"), mustAllowYAML(t, entry("npm:a", "1.0.0", shaA)))
	shared := filepath.Join(filepath.Dir(dir), "shared", "allowed.yaml")
	writeFile(t, shared, mustAllowYAML(t, entry("npm:b", "2.0.0", shaB)))
	t.Cleanup(func() { _ = os.RemoveAll(filepath.Dir(shared)) })

	s := testStore(nil)
	cfg, cp, err := s.LoadConfig(dir, "", false)
	if err != nil {
		t.Fatal(err)
	}
	set, err := s.LoadAllow(cfg, cp, "")
	if err != nil {
		t.Fatal(err)
	}
	if m, _, _ := set.Match(core.NPM, "a", "1.0.0", shaA); m == nil {
		t.Error("allow_file entry not loaded")
	}
	m, _, _ := set.Match(core.NPM, "b", "2.0.0", shaB)
	if m == nil {
		t.Fatal("allow_from entry not loaded")
	}
	if got := set.(*AllowSet).Source(m); got != filepath.ToSlash(shared) {
		t.Errorf("source %q", got)
	}

	// A missing allow_from file is an error; a missing allow file isn't.
	if err := os.Remove(shared); err != nil {
		t.Fatal(err)
	}
	_, err = s.LoadAllow(cfg, cp, "")
	if err == nil || !strings.HasSuffix(err.Error(), "shared/allowed.yaml: no such file") {
		t.Fatalf("missing allow_from: %v", err)
	}
	if _, err := s.LoadAllow(&core.Config{}, "", ""); err != nil {
		t.Fatalf("missing allow file: %v", err)
	}
}

// fakeGit serves allow files at a base ref.
type fakeGit struct {
	files map[string]string // "<ref>:<path>"
	calls []string
	mu    sync.Mutex
}

func (g *fakeGit) show(_ context.Context, repo, ref, path string) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls = append(g.calls, ref+":"+path)
	if c, ok := g.files[ref+":"+path]; ok {
		return []byte(c), nil
	}
	return nil, fmt.Errorf("fatal: path '%s' does not exist in '%s'", path, ref)
}

func TestAllowPullRequestRule(t *testing.T) {
	dir := inProject(t)
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o750); err != nil {
		t.Fatal(err)
	}
	old := entry("npm:a", "1.0.0", shaA)
	added := entry("npm:evil", "6.6.6", shaB)
	widened := entry("npm:c", "1.0.0", shaA)
	widened.Signals = []string{"npm-install-script-new"}
	base := mustAllowYAML(t, old, entry("npm:c", "1.0.0", shaA))
	writeFile(t, filepath.Join(dir, Dir, AllowName), mustAllowYAML(t, old, added, widened, entry("npm:a", "2.0.0", shaB)))

	g := &fakeGit{files: map[string]string{"origin/main:.sightread/allowed.yaml": base}}
	t.Cleanup(core.SwapGitShow(g.show))
	s := testStore(nil)

	set, err := s.LoadAllow(&core.Config{}, "", "origin/main")
	if err != nil {
		t.Fatal(err)
	}
	if m, counted, _ := set.Match(core.NPM, "a", "1.0.0", shaA); m == nil || !counted {
		t.Error("an entry the base has must count")
	}
	m, counted, _ := set.Match(core.NPM, "evil", "6.6.6", shaB)
	if m == nil || counted {
		t.Errorf("an entry the change added must match and not count: %v %v", m, counted)
	}
	if !set.(*AllowSet).InThisChange(m) {
		t.Error("InThisChange false")
	}
	if _, counted, _ := set.Match(core.NPM, "c", "1.0.0", shaA); counted {
		t.Error("an entry the change widened must not count")
	}
	// A conflicting entry the change added is not evidence of anything.
	if _, _, conflict := set.Match(core.NPM, "a", "2.0.0", shaA); conflict != nil {
		t.Errorf("conflict from an entry in this change: %v", conflict)
	}
	if len(g.calls) != 1 || g.calls[0] != "origin/main:.sightread/allowed.yaml" {
		t.Errorf("git show calls %v", g.calls)
	}

	// --trust-pr-allow passes no base ref: every entry counts.
	set, err = s.LoadAllow(&core.Config{}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, counted, _ := set.Match(core.NPM, "evil", "6.6.6", shaB); !counted {
		t.Error("with trust the entry counts")
	}

	// No allow file at the base: nothing counts.
	g.files = nil
	set, err = s.LoadAllow(&core.Config{}, "", "origin/main")
	if err != nil {
		t.Fatal(err)
	}
	if _, counted, _ := set.Match(core.NPM, "a", "1.0.0", shaA); counted {
		t.Error("an entry missing at the base must not count")
	}
}

func TestAllowPullRequestRuleOutsideRepo(t *testing.T) {
	dir := inProject(t)
	repo := filepath.Join(dir, "repo")
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o750); err != nil {
		t.Fatal(err)
	}
	writeConfig(t, repo, "allow_from: [../shared.yaml]\n")
	writeFile(t, filepath.Join(dir, "shared.yaml"), mustAllowYAML(t, entry("npm:a", "1.0.0", shaA)))
	g := &fakeGit{}
	t.Cleanup(core.SwapGitShow(g.show))
	s := testStore(nil)
	cfg, cp, err := s.LoadConfig(repo, "", false)
	if err != nil {
		t.Fatal(err)
	}
	set, err := s.LoadAllow(cfg, cp, "origin/main")
	if err != nil {
		t.Fatal(err)
	}
	if _, counted, _ := set.Match(core.NPM, "a", "1.0.0", shaA); !counted {
		t.Error("a file outside the repository can't be changed by it and counts")
	}
}

func TestAllowPullRequestRuleNeedsGit(t *testing.T) {
	inProject(t)
	t.Cleanup(core.SwapGitShow(nil))
	_, err := testStore(nil).LoadAllow(&core.Config{}, "", "origin/main")
	if !errors.Is(err, core.ErrNotLinked) {
		t.Fatalf("got %v", err)
	}
}

func TestAllowEntryRules(t *testing.T) {
	const pre = "rhythm sightread: .sightread/allowed.yaml: "
	full := func(over string) string {
		fields := map[string]string{
			"package": "npm:left-pad", "version": "1.4.0", "sha256": shaA,
			"reason": "checked", "by": "Ann", "date": "2026-10-20",
		}
		var b strings.Builder
		b.WriteString("allowed:\n  - package: npm:other\n    version: 1.0.0\n    sha256: " + shaB + "\n    reason: ok\n    by: Ann\n    date: 2026-10-20\n  - ")
		first := true
		for _, k := range []string{"package", "version", "sha256", "reason", "by", "date"} {
			v := fields[k]
			if strings.HasPrefix(over, k+"=") {
				v = strings.TrimPrefix(over, k+"=")
			}
			if v == "" {
				continue
			}
			if !first {
				b.WriteString("    ")
			}
			first = false
			fmt.Fprintf(&b, "%s: %q\n", k, v)
		}
		if strings.Contains(over, ":") && !strings.Contains(over, "=") {
			b.WriteString("    " + over + "\n")
		}
		return b.String()
	}
	cases := []struct{ over, want string }{
		{"package=", "entry 2 needs a package such as npm:left-pad"},
		{"package=pip:left-pad", `entry 2: package "pip:left-pad": unknown ecosystem "pip": want wp-plugin, wp-theme, composer or npm`},
		{"package=npm:left-pad@1.4.0", `entry 2: package "npm:left-pad@1.4.0" holds a version; put it in version`},
		{"version=", "entry 2 (npm:left-pad) needs a version"},
		{"version=1.0 beta", `entry 2 (npm:left-pad): version "1.0 beta" is not a version`},
		{"sha256=5d2c0f", "entry 2 (npm:left-pad@1.4.0): sha256 must be the 64 hex characters of the reviewed archive's hash"},
		{"sha256=" + strings.Repeat("g", 64), "entry 2 (npm:left-pad@1.4.0): sha256 must be the 64 hex characters of the reviewed archive's hash"},
		{"reason=", "entry 2 (npm:left-pad@1.4.0) needs a reason, so the next person knows why it is allowed"},
		{"by=", "entry 2 (npm:left-pad@1.4.0) needs by, the person who reviewed it"},
		{"date=", "entry 2 (npm:left-pad@1.4.0) needs a date, the day it was reviewed, such as 2026-10-20"},
		{"date=20 Oct", `entry 2 (npm:left-pad@1.4.0): date "20 Oct": want a date such as 2026-10-20`},
		{"hash: sha1", `entry 2 (npm:left-pad@1.4.0): hash "sha1": want archive or manifest`},
		{"until: soon", `entry 2 (npm:left-pad@1.4.0): until "soon": want a date such as 2027-01-31`},
		{"signals: [eval-dynamc]", `entry 2 (npm:left-pad@1.4.0): signals: no signal "eval-dynamc" (did you mean eval-dynamic?)`},
		{"signals: [integrity-mismatch]", "entry 2 (npm:left-pad@1.4.0): signals: integrity-mismatch can't be allowed; it says the bytes are not the ones published or reviewed"},
		{"reviewer: x", "unknown key reviewer in allowed 2 (line 14)"},
	}
	for _, tc := range cases {
		t.Run(tc.over, func(t *testing.T) {
			dir := inProject(t)
			writeFile(t, filepath.Join(dir, Dir, AllowName), full(tc.over))
			_, err := testStore(nil).LoadAllow(&core.Config{}, "", "")
			if err == nil {
				t.Fatalf("no error\n%s", full(tc.over))
			}
			if err.Error() != pre+tc.want {
				t.Errorf("\n got %q\nwant %q", err, pre+tc.want)
			}
			if core.CodeOf(err) != core.EBadConfig {
				t.Errorf("code %q", core.CodeOf(err))
			}
		})
	}
}

func TestAddAllow(t *testing.T) {
	dir := inProject(t)
	p := filepath.Join(dir, Dir, AllowName)
	s := testStore(nil)
	b := entry("npm:b", "1.10.0", shaB)
	a2 := entry("npm:a", "2.0.0", shaA)
	a1 := entry("npm:a", "1.0.0", shaA)
	a1.Signals = []string{"npm-install-script-new"}
	a1.Until = "2027-01-31"
	for _, e := range []core.AllowEntry{b, a2, a1} {
		if err := s.AddAllow(p, e); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(p) //nolint:gosec // test file
	if err != nil {
		t.Fatal(err)
	}
	want := allowHeader + `allowed:
  - package: npm:a
    version: 1.0.0
    sha256: ` + shaA + `
    signals:
      - npm-install-script-new
    reason: checked the code
    by: Ann Reviewer
    date: "2026-10-20"
    until: "2027-01-31"
  - package: npm:a
    version: 2.0.0
    sha256: ` + shaA + `
    reason: checked the code
    by: Ann Reviewer
    date: "2026-10-20"
  - package: npm:b
    version: 1.10.0
    sha256: ` + shaB + `
    reason: checked the code
    by: Ann Reviewer
    date: "2026-10-20"
`
	if string(data) != want {
		t.Errorf("file\n%s\nwant\n%s", data, want)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != 0o644 {
			t.Errorf("mode %v %v", fi.Mode(), err)
		}
	}

	// The same version and hash again is refused, whatever the reason.
	dup := entry("npm:a", "2.0.0", strings.ToUpper(shaA))
	dup.Reason = "another look"
	err = s.AddAllow(p, dup)
	wantErr := "rhythm sightread: .sightread/allowed.yaml: npm:a@2.0.0 with sha256 aaaaaaaaaaaa is already allowed (entry 2)"
	if err == nil || err.Error() != wantErr {
		t.Errorf("duplicate: %v", err)
	}
	// An invalid entry is refused with the same text LoadAllow gives.
	bad := entry("plugin:x", "1.0", shaA)
	bad.Reason = " "
	err = s.AddAllow(p, bad)
	wantErr = "rhythm sightread: .sightread/allowed.yaml: the new entry (wp-plugin:x@1.0) needs a reason, so the next person knows why it is allowed"
	if err == nil || err.Error() != wantErr {
		t.Errorf("invalid: %v", err)
	}
	if _, err := os.Stat(p + ".lock"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("lock file left behind: %v", err)
	}
}

func TestAddAllowKeepsHeader(t *testing.T) {
	dir := inProject(t)
	p := filepath.Join(dir, "allowed.yaml")
	writeFile(t, p, "# Agency reviews. Ask Ann before adding.\n\n# Second line.\nallowed: []\n")
	if err := testStore(nil).AddAllow(p, entry("npm:a", "1.0.0", shaA)); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(p) //nolint:gosec // test file
	if !strings.HasPrefix(string(data), "# Agency reviews. Ask Ann before adding.\n\n# Second line.\nallowed:\n") {
		t.Errorf("header lost:\n%s", data)
	}
}

func TestAddAllowRefusesBrokenFile(t *testing.T) {
	dir := inProject(t)
	p := filepath.Join(dir, Dir, AllowName)
	writeFile(t, p, "allowed:\n  - package: npm:a\n")
	err := testStore(nil).AddAllow(p, entry("npm:b", "1.0.0", shaA))
	if err == nil || err.Error() != "rhythm sightread: .sightread/allowed.yaml: entry 1 (npm:a) needs a version" {
		t.Fatalf("got %v", err)
	}
	data, _ := os.ReadFile(p) //nolint:gosec // test file
	if string(data) != "allowed:\n  - package: npm:a\n" {
		t.Errorf("a broken file was rewritten:\n%s", data)
	}
}

func TestAddAllowConcurrent(t *testing.T) {
	dir := inProject(t)
	p := filepath.Join(dir, Dir, AllowName)
	s := testStore(nil)
	const each = 15
	var wg sync.WaitGroup
	errs := make(chan error, 2*each)
	for g := range 2 {
		wg.Go(func() {
			for i := range each {
				errs <- s.AddAllow(p, entry(fmt.Sprintf("npm:g%d", g), fmt.Sprintf("1.0.%d", i), shaA))
			}
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	set, err := s.LoadAllow(&core.Config{AllowFile: p}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got := len(set.(*AllowSet).Entries()); got != 2*each {
		t.Fatalf("%d entries, want %d: an edit was lost", got, 2*each)
	}
}

func TestAllowStaleLock(t *testing.T) {
	dir := inProject(t)
	p := filepath.Join(dir, Dir, AllowName)
	writeFile(t, p+".lock", "123\n")
	old := time.Now().Add(-2 * lockStale)
	if err := os.Chtimes(p+".lock", old, old); err != nil {
		t.Fatal(err)
	}
	if err := testStore(nil).AddAllow(p, entry("npm:a", "1.0.0", shaA)); err != nil {
		t.Fatal(err)
	}
}

func TestRemoveAllow(t *testing.T) {
	dir := inProject(t)
	p := filepath.Join(dir, Dir, AllowName)
	s := testStore(nil)
	for _, e := range []core.AllowEntry{entry("npm:a", "1.0.0", shaA), entry("npm:a", "2.0.0", shaA), entry("npm:b", "1.0.0", shaA)} {
		if err := s.AddAllow(p, e); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.RemoveAllow(p, core.Ref{Eco: core.NPM, Name: "a", Version: "2.0.0"}); err != nil {
		t.Fatal(err)
	}
	set, _ := s.LoadAllow(&core.Config{}, "", "")
	if got := len(set.(*AllowSet).Entries()); got != 2 {
		t.Fatalf("%d entries", got)
	}
	if err := s.RemoveAllow(p, core.Ref{Eco: core.NPM, Name: "a"}); err != nil {
		t.Fatal(err)
	}
	err := s.RemoveAllow(p, core.Ref{Eco: core.NPM, Name: "a"})
	if err == nil || err.Error() != "rhythm sightread: .sightread/allowed.yaml: no entry for npm:a" {
		t.Fatalf("got %v", err)
	}
}

func TestImportAllow(t *testing.T) {
	dir := inProject(t)
	p := filepath.Join(dir, Dir, AllowName)
	s := testStore(nil)
	if err := s.AddAllow(p, entry("npm:a", "1.0.0", shaA)); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "agency.yaml"), mustAllowYAML(t, entry("npm:a", "1.0.0", shaA), entry("npm:b", "1.0.0", shaB)))
	n, err := s.ImportAllow(p, "agency.yaml")
	if err != nil || n != 1 {
		t.Fatalf("imported %d, %v", n, err)
	}
	n, err = s.ImportAllow(p, "agency.yaml")
	if err != nil || n != 0 {
		t.Fatalf("second import added %d, %v", n, err)
	}
	set, _ := s.LoadAllow(&core.Config{}, "", "")
	m, _, _ := set.Match(core.NPM, "b", "1.0.0", shaB)
	if m == nil || m.ImportedFrom != "agency.yaml" {
		t.Fatalf("imported entry %+v", m)
	}
	_, err = s.ImportAllow(p, "missing.yaml")
	if err == nil || err.Error() != "rhythm sightread: missing.yaml: no such file" {
		t.Fatalf("missing: %v", err)
	}
}

// FuzzAllowFile checks that an allow file that loads is written back so
// that it loads to the same entries: load, save, load is stable.
func FuzzAllowFile(f *testing.F) {
	f.Add([]byte(allowYAML))
	f.Add([]byte("allowed: []\n"))
	f.Add([]byte("allowed:\n  - {package: \"npm:@a/b\", version: \"1\", sha256: " + shaA + ", reason: r, by: b, date: 2026-01-01, hash: archive}\n"))
	f.Add([]byte("allowed:\n  - package: npm:x\n"))
	f.Add([]byte("allowed:\n  - {package: \"npm:a\", version: \"1\", sha256: " + shaA + ", reason: r, by: b, date: 2026-01-01, signals: []}\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		entries, err := parseAllow(data)
		if err != nil {
			return
		}
		p := filepath.Join(t.TempDir(), "allowed.yaml")
		writeFile(t, p, string(data))
		if err := editAllow(p, func(e []core.AllowEntry) ([]core.AllowEntry, error) { return e, nil }); err != nil {
			t.Fatalf("save: %v", err)
		}
		again, err := readAllowFile(p)
		if err != nil {
			t.Fatalf("reload: %v", err)
		}
		sortEntries(entries)
		if len(entries) == 0 && len(again) == 0 {
			return
		}
		if !reflect.DeepEqual(entries, again) {
			t.Fatalf("not stable:\n%+v\n%+v", entries, again)
		}
	})
}
