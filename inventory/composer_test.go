// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// byName indexes Packages.Installed by name.
func byName(p *Packages) map[string]core.Installed {
	m := map[string]core.Installed{}
	for _, in := range p.Installed {
		m[in.Ref.Name] = in
	}
	return m
}

// lineOf is the 1-based line of the first line holding s, found apart
// from the parser.
func lineOf(t *testing.T, data []byte, s string) int {
	t.Helper()
	i := bytes.Index(data, []byte(s))
	if i < 0 {
		t.Fatalf("%q not in the fixture", s)
	}
	return bytes.Count(data[:i], []byte("\n")) + 1
}

func TestComposerLaravel(t *testing.T) {
	p, err := ReadComposer("testdata/composer/laravel", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Installed) != 111 || len(p.NotChecked) != 0 || len(p.Warnings) != 0 {
		t.Fatalf("%d installed, not checked %v, warnings %q", len(p.Installed), p.NotChecked, p.Warnings)
	}
	lock, _ := os.ReadFile("testdata/composer/laravel/composer.lock")
	got := byName(p)
	dev := 0
	for _, in := range p.Installed {
		if in.ResolvedKind != core.ResolvedRegistry || in.Private || in.Integrity != "" || len(in.Reference) != 40 || in.Lockfile != "composer.lock" {
			t.Errorf("%s = %+v", in.Ref.Name, in)
		}
		if in.Dev {
			dev++
		}
	}
	if dev != 35 {
		t.Errorf("dev packages = %d, want 35", dev)
	}
	for _, name := range []string{"brick/math", "laravel/framework", "theseer/tokenizer"} {
		if want := lineOf(t, lock, `"name": "`+name+`"`); got[name].LockLine != want {
			t.Errorf("%s LockLine = %d, want %d", name, got[name].LockLine, want)
		}
	}
	fw := got["laravel/framework"]
	if !fw.Direct || fw.Dev || fw.Constraint != "^12.0" || !strings.HasPrefix(fw.Resolved, "https://api.github.com/repos/laravel/framework/zipball/") {
		t.Errorf("laravel/framework = %+v", fw)
	}
	if pu := got["phpunit/phpunit"]; !pu.Direct || !pu.Dev || pu.Constraint != "^11.5.3" {
		t.Errorf("phpunit/phpunit = %+v", pu)
	}
	if pl := got["psr/log"]; pl.Direct || pl.Constraint != "" {
		t.Errorf("transitive psr/log = %+v", pl)
	}
}

func TestComposerRepositories(t *testing.T) {
	p, err := ReadComposer("testdata/composer/repos", Options{ComposerRepos: []string{"https://satis.agency.example"}})
	if err != nil {
		t.Fatal(err)
	}
	got := byName(p)
	for name, want := range map[string]struct {
		kind    string
		private bool
		direct  bool
		dev     bool
		path    string
	}{
		"acme/billing":     {core.ResolvedRegistry, true, true, false, ""},
		"acme/forked-lib":  {core.ResolvedGit, false, true, false, ""},
		"acme/legacy-zip":  {core.ResolvedTarball, false, true, false, ""},
		"acme/utils":       {core.ResolvedFile, false, true, false, ""}, // its install-path leaves the project
		"agency/theme-kit": {core.ResolvedRegistry, true, true, false, ""},
		"monolog/monolog":  {core.ResolvedRegistry, false, true, false, "lib/vendor/monolog/monolog"},
		"psr/log":          {core.ResolvedGit, false, false, false, ""},
		"phpunit/phpunit":  {core.ResolvedRegistry, false, true, true, "lib/vendor/phpunit/phpunit"},
	} {
		in := got[name]
		if in.ResolvedKind != want.kind || in.Private != want.private || in.Direct != want.direct || in.Dev != want.dev || in.Path != want.path {
			t.Errorf("%s = %+v, want %+v", name, in, want)
		}
	}
	if len(got) != 8 {
		t.Errorf("installed = %d, want 8", len(got))
	}
	if c := got["monolog/monolog"].Constraint; c != "^3.0" {
		t.Errorf("a mixed-case require key: constraint %q, want ^3.0", c)
	}
	if r := got["psr/log"].Reference; r != "f16e1d5863e37f8d8c2a01719f5b34baa2b714d3" {
		t.Errorf("source reference fallback = %q", r)
	}
	nc := notCheckedBy(p.NotChecked)
	for name, want := range map[string]core.NotCheckedReason{
		"acme/billing": core.Private, "acme/forked-lib": core.VCS, "acme/legacy-zip": core.VCS, "acme/utils": core.VCS, "psr/log": core.VCS,
	} {
		if nc["composer:"+name].Reason != want {
			t.Errorf("not checked %s = %+v, want %s", name, nc["composer:"+name], want)
		}
	}
	if len(nc) != 5 {
		t.Errorf("not checked = %+v", p.NotChecked)
	}
	if h := nc["composer:acme/utils"]; h.Text != "git, path or tarball dependency" || h.Hint != "Sightread reviews registry releases only" {
		t.Errorf("vcs text = %+v", h)
	}

	// Negative: without the config entry the agency repository is
	// private and not checked too.
	p, err = ReadComposer("testdata/composer/repos", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if nc := notCheckedBy(p.NotChecked)["composer:agency/theme-kit"]; nc.Reason != core.Private {
		t.Errorf("unconfigured repository: %+v", nc)
	}
}

func TestComposerBOMAndCRLF(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"composer.lock", "composer.json"} {
		b, err := os.ReadFile(filepath.Join("testdata/composer/laravel", name))
		if err != nil {
			t.Fatal(err)
		}
		b = append([]byte("\ufeff"), bytes.ReplaceAll(b, []byte("\n"), []byte("\r\n"))...)
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p, err := ReadComposer(dir, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := ReadComposer("testdata/composer/laravel", Options{})
	if len(p.Installed) != len(want.Installed) {
		t.Fatalf("%d installed, want %d", len(p.Installed), len(want.Installed))
	}
	for i := range p.Installed {
		if p.Installed[i] != want.Installed[i] {
			t.Errorf("entry %d = %+v, want %+v", i, p.Installed[i], want.Installed[i])
		}
	}
}

func TestComposerPackagistOff(t *testing.T) {
	lock := []byte(`{"packages": [{"name": "a/b", "version": "1.0.0", "dist": {"type": "zip", "url": "https://mirror.example/a-b.zip"}}]}`)
	for _, c := range []struct {
		manifest string
		kind     string
	}{
		{`{"repositories": {"packagist.org": false}}`, core.ResolvedForeign},
		{`{"repositories": [{"packagist.org": false}]}`, core.ResolvedForeign},
		{`{"repositories": [{"type": "composer", "url": "https://repo.packagist.org"}]}`, core.ResolvedRegistry},
		{`{}`, core.ResolvedRegistry},
	} {
		p, err := ParseComposer("composer.lock", lock, []byte(c.manifest), nil, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if got := p.Installed[0].ResolvedKind; got != c.kind {
			t.Errorf("%s: kind %s, want %s", c.manifest, got, c.kind)
		}
	}
}

func TestInstalledJSONv1(t *testing.T) {
	got, err := parseInstalledJSON([]byte(`[{"name": "A/B", "version": "1.0"}, {"name": ""}]`), "vendor")
	if err != nil || len(got) != 1 || got["a/b"] != "vendor/a/b" {
		t.Errorf("v1 = %v, %v", got, err)
	}
	got, err = parseInstalledJSON([]byte(`{"packages": [{"name": "x/y", "install-path": "/etc"}, {"name": "x/z", "install-path": "../x/z"}]}`), "vendor")
	if err != nil || len(got) != 1 || got["x/z"] != "vendor/x/z" {
		t.Errorf("v2 = %v, %v", got, err)
	}
	if _, err := parseInstalledJSON([]byte(`{"packages": 3}`), "vendor"); err == nil {
		t.Error("a bad installed.json parsed")
	}
}

// Negative: bad JSON, bad names and a credential in a URL.
func TestComposerRefuses(t *testing.T) {
	if _, err := ParseComposer("composer.lock", []byte(`{"packages": [`), nil, nil, Options{}); err == nil {
		t.Error("truncated lock parsed")
	}
	if _, err := ParseComposer("composer.lock", []byte(`{}`), []byte(`{"repositories": 3}`), nil, Options{}); err == nil {
		t.Error("bad repositories parsed")
	}
	if _, err := ReadComposer(t.TempDir(), Options{}); !os.IsNotExist(err) {
		t.Errorf("no lock: %v, want not exist", err)
	}
	token := coretest.FakeKey(coretest.KeyGitHub)
	lock := `{"packages": [
		{"name": "bad name/x", "version": "1"},
		{"name": "a/b\u001b", "version": "1"},
		{"name": "c/d", "version": "1 2"},
		{"name": "e/f", "version": "1.0.0", "dist": {"type": "zip", "url": "https://user:` + token + `@repo.example/e-f.zip?access_token=` + token + `"}, "notification-url": "https://packagist.org/downloads/"}
	]}`
	p, err := ParseComposer("composer.lock", []byte(lock), nil, nil, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Installed) != 1 || len(p.Warnings) != 3 {
		t.Fatalf("installed %+v, warnings %q", p.Installed, p.Warnings)
	}
	for _, w := range p.Warnings {
		if strings.ContainsRune(w, 0x1b) {
			t.Errorf("warning holds a raw escape: %q", w)
		}
	}
	if r := p.Installed[0].Resolved; strings.Contains(r, token) || strings.Contains(r, "user") {
		t.Errorf("credential in Resolved: %s", r)
	}
}

func TestScanJSONKeys(t *testing.T) {
	data := []byte("{\n \"a\": [\n  {\"b\": 1},\n  {\"c\": {\"d\": null}}\n ],\n \"e\": \"x\"\n}")
	var got []string
	if err := scanJSONKeys(data, func(p []string, line int) {
		got = append(got, strings.Join(p, ".")+"@"+string(rune('0'+line)))
	}); err != nil {
		t.Fatal(err)
	}
	if want := "a@2 a.0.b@3 a.1.c@4 a.1.c.d@4 e@6"; strings.Join(got, " ") != want {
		t.Errorf("keys = %s, want %s", strings.Join(got, " "), want)
	}
	if err := scanJSONKeys([]byte(`{"a": [}`), func([]string, int) {}); err == nil {
		t.Error("bad JSON scanned")
	}
}

// FuzzComposerLock: never panics; every entry has a valid name and a
// LockLine inside the input.
func FuzzComposerLock(f *testing.F) {
	for _, p := range []string{"testdata/composer/repos/composer.lock"} {
		b, err := os.ReadFile(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b, []byte(`{"require": {"a/b": "^1"}, "repositories": [{"type": "composer", "url": "https://r.example"}]}`))
	}
	f.Add([]byte(`{"packages": [{"name": "a/b", "version": "1.0.0", "dist": {"type": "path", "url": "x"}}]}`), []byte(`{"repositories": {"x": false}}`))
	f.Fuzz(func(t *testing.T, lock, manifest []byte) {
		p, err := ParseComposer("composer.lock", lock, manifest, nil, Options{})
		if err != nil {
			return
		}
		lines := bytes.Count(lock, []byte("\n")) + 1
		for _, in := range p.Installed {
			if !validRef(core.Composer, in.Ref.Name, in.Ref.Version) {
				t.Fatalf("bad ref %+v", in.Ref)
			}
			if in.LockLine < 0 || in.LockLine > lines {
				t.Fatalf("LockLine %d past %d lines", in.LockLine, lines)
			}
		}
	})
}
