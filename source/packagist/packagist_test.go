// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package packagist

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
	_ "github.com/RhythmShahriar/sightread/diff" // the one drift rule VerifyLocal uses
)

// Made-up commits in the shape of monolog's.
const (
	commit381 = "aef6ee73a77a66e404dd6540934a9ef1b3c855b4"
	commit380 = "32e515fdc02cdafbe4593e30a9350d486b125b67"
	commit370 = "f4393b648b78a5408747de94fca38beb5f7e9ef8"
	otherSHA  = "0123456789abcdef0123456789abcdef01234567"
)

// monologP2 is a p2 answer in the shape repo.packagist.org serves for
// monolog/monolog (copied by hand, cut short, values made up): minified,
// with an empty shasum on GitHub zipballs, later versions inheriting
// fields and require-dev unset on the oldest.
func monologP2(shasum381 string) string {
	return `{"packages":{"monolog/monolog":[
{"name":"monolog/monolog","description":"Sends your logs to files, sockets, inboxes, databases and various web services",
 "keywords":["log","logging","psr-3"],"homepage":"https://github.com/Seldaek/monolog","version":"3.8.1","version_normalized":"3.8.1.0",
 "license":["MIT"],"authors":[{"name":"Jordi Boggiano","email":"j.boggiano@seld.be","homepage":"https://seld.be"}],
 "source":{"url":"https://github.com/Seldaek/monolog.git","type":"git","reference":"` + commit381 + `"},
 "dist":{"url":"https://api.github.com/repos/Seldaek/monolog/zipball/` + commit381 + `","type":"zip","shasum":"` + shasum381 + `","reference":"` + commit381 + `"},
 "type":"library","time":"2024-12-05T17:15:07+00:00","autoload":{"psr-4":{"Monolog\\":"src/Monolog"}},
 "require":{"php":">=8.1","psr/log":"^2.0 || ^3.0"},"require-dev":{"phpunit/phpunit":"^10.5.17"},
 "provide":{"psr/log-implementation":"3.0.0"},"suggest":{"ext-curl":"Required to send log messages using the IFTTTHandler"}},
{"version":"3.8.0","version_normalized":"3.8.0.0",
 "source":{"url":"https://github.com/Seldaek/monolog.git","type":"git","reference":"` + commit380 + `"},
 "dist":{"url":"https://api.github.com/repos/Seldaek/monolog/zipball/` + commit380 + `","type":"zip","shasum":"","reference":"` + commit380 + `"},
 "time":"2024-11-12T13:57:08+00:00"},
{"version":"3.7.0","version_normalized":"3.7.0.0","license":"MIT",
 "source":{"url":"https://github.com/Seldaek/monolog.git","type":"git","reference":"` + commit370 + `"},
 "dist":{"url":"https://api.github.com/repos/Seldaek/monolog/zipball/` + commit370 + `","type":"zip","shasum":"","reference":"` + commit370 + `"},
 "time":"2024-06-28T09:40:51+00:00","require-dev":"__unset"}
]},"minified":"composer/2.0"}`
}

const monologDev = `{"packages":{"monolog/monolog":[
{"name":"monolog/monolog","version":"dev-main","version_normalized":"dev-main",
 "source":{"url":"https://github.com/Seldaek/monolog.git","type":"git","reference":"` + otherSHA + `"},
 "dist":{"url":"https://api.github.com/repos/Seldaek/monolog/zipball/` + otherSHA + `","type":"zip","shasum":"","reference":"` + otherSHA + `"},
 "extra":{"branch-alias":{"dev-main":"3.x-dev"}},"time":"2024-12-20T10:00:00+00:00","type":"library"}
]},"minified":"composer/2.0"}`

const monologMeta = `{"package":{"name":"monolog/monolog","description":"Sends your logs","time":"2011-09-27T00:35:19+00:00",
 "maintainers":[{"name":"Seldaek","avatar_url":"https://www.gravatar.com/avatar/x"}],
 "versions":{},"type":"library","repository":"https://github.com/Seldaek/monolog","abandoned":false,"downloads":{"total":1}}}`

// monologFiles is what the zipball holds.
var monologFiles = map[string]string{
	"composer.json": `{"name":"monolog/monolog","type":"library","license":"MIT",
 "require":{"php":">=8.1","psr/log":"^2.0 || ^3.0"},"require-dev":{"phpunit/phpunit":"^10.5.17"},
 "autoload":{"psr-4":{"Monolog\\":"src/Monolog"},"files":["src/functions.php"]},
 "scripts":{"test":"phpunit","post-install-cmd":["@test","echo done"]}}`,
	"src/Monolog/Logger.php": "<?php namespace Monolog; class Logger {}",
	"src/functions.php":      "<?php // helpers",
	"README.md":              "# Monolog",
	"CHANGELOG.md":           "### 3.8.1 (2024-12-05)\n\n  * Fixed unsupported operand error\n\n### 3.8.0 (2024-11-12)\n\n  * Added PHP 8.4 support\n",
}

// monolog serves monolog/monolog on pub with the 3.8.1 zip under top.
func monolog(t *testing.T, pub *server, shasum381, top string) []byte {
	t.Helper()
	zip := makeZip(t, top, monologFiles)
	pub.set("/p2/monolog/monolog.json", monologP2(shasum381))
	pub.set("/p2/monolog/monolog~dev.json", monologDev)
	pub.set("/packages/monolog/monolog.json", monologMeta)
	pub.redirect["/repos/Seldaek/monolog/zipball/"+commit381] = "/Seldaek/monolog/legacy.zip/" + commit381
	pub.setBytes("/Seldaek/monolog/legacy.zip/"+commit381, zip)
	return zip
}

func TestExpand(t *testing.T) {
	in := []map[string]json.RawMessage{
		{"version": json.RawMessage(`"2.0"`), "type": json.RawMessage(`"library"`), "require-dev": json.RawMessage(`{"a":"1"}`)},
		{"version": json.RawMessage(`"1.1"`)},
		{"version": json.RawMessage(`"1.0"`), "require-dev": json.RawMessage(`"__unset"`), "type": json.RawMessage(`"composer-plugin"`)},
		{"version": json.RawMessage(`"0.9"`)},
	}
	out := Expand(in)
	if len(out) != 4 {
		t.Fatalf("got %d versions", len(out))
	}
	if string(out[1]["type"]) != `"library"` || string(out[1]["require-dev"]) != `{"a":"1"}` {
		t.Errorf("1.1 did not inherit: %v", out[1])
	}
	if _, ok := out[2]["require-dev"]; ok || string(out[2]["type"]) != `"composer-plugin"` {
		t.Errorf("1.0 = %v", out[2])
	}
	if _, ok := out[3]["require-dev"]; ok || string(out[3]["type"]) != `"composer-plugin"` {
		t.Errorf("0.9 = %v, want the 1.0 fields", out[3])
	}
	out[0]["mutated"] = json.RawMessage(`1`)
	for i := 1; i < len(out); i++ {
		if _, ok := out[i]["mutated"]; ok {
			t.Errorf("version %d shares its map with version 0", i)
		}
	}
}

func FuzzP2Expand(f *testing.F) {
	f.Add(`[{"version":"1.0","a":"x"},{"version":"0.9","a":"__unset"},{"b":"y"}]`)
	f.Add(`[{}]`)
	f.Add(`[]`)
	f.Add(monologP2("")[len(`{"packages":{"monolog/monolog":`) : len(monologP2(""))-len(`},"minified":"composer/2.0"}`)])
	f.Fuzz(func(t *testing.T, data string) {
		var in []map[string]json.RawMessage
		if json.Unmarshal([]byte(data), &in) != nil {
			return
		}
		out := Expand(in)
		if len(out) != len(in) {
			t.Fatalf("%d versions in, %d out", len(in), len(out))
		}
		const probe = "\x00probe"
		for i := range out {
			if out[i] == nil {
				t.Fatalf("version %d expanded to nil", i)
			}
			out[i][probe] = json.RawMessage(`1`)
			for j := range out {
				if j != i {
					if _, ok := out[j][probe]; ok {
						t.Fatalf("versions %d and %d share a map", i, j)
					}
				}
			}
			delete(out[i], probe)
		}
	})
}

func TestVersionsAndMeta(t *testing.T) {
	pub := newServer(t)
	monolog(t, pub, "", "Seldaek-monolog-aef6ee7")
	s := New(env(t, pub, ""))
	ctx := context.Background()
	vs, err := s.Versions(ctx, "monolog/monolog")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"dev-main", "3.7.0", "3.8.0", "3.8.1"}; !slices.Equal(vs, want) {
		t.Errorf("Versions = %v, want %v", vs, want)
	}
	m, err := s.Meta(ctx, core.Ref{Eco: core.Composer, Name: "monolog/monolog"})
	if err != nil {
		t.Fatal(err)
	}
	if m.Ref.Version != "3.8.1" || m.Latest != "3.8.1" || m.Type != "library" || m.License != "MIT" ||
		m.RequiresPHP != ">=8.1" || m.Repository != "https://github.com/Seldaek/monolog.git" || m.Private || m.Abandoned {
		t.Errorf("Meta = %+v", m)
	}
	if m.Archive.Reference != commit381 || m.Archive.Shasum != "" ||
		m.Archive.URL != "https://api.github.com/repos/Seldaek/monolog/zipball/"+commit381 {
		t.Errorf("Archive = %+v", m.Archive)
	}
	if want := time.Date(2024, 12, 5, 17, 15, 7, 0, time.UTC); !m.Published.Equal(want) {
		t.Errorf("Published = %v", m.Published)
	}
	if len(m.Maintainers) != 1 || m.Maintainers[0].Login != "Seldaek" {
		t.Errorf("Maintainers = %+v", m.Maintainers)
	}
	if len(m.History) != 2 || m.History[0].Version != "3.8.0" || m.History[1].Version != "3.7.0" || m.History[0].Published.IsZero() {
		t.Errorf("History = %+v", m.History)
	}
	old, err := s.Meta(ctx, core.Ref{Eco: core.Composer, Name: "monolog/monolog", Version: "3.7.0"})
	if err != nil {
		t.Fatal(err)
	}
	if old.DevDeps != nil || old.License != "MIT" || old.Deps["psr/log"] != "^2.0 || ^3.0" {
		t.Errorf("3.7.0 = %+v (require-dev should be unset, the rest inherited)", old)
	}
	alias, err := s.Meta(ctx, core.Ref{Eco: core.Composer, Name: "monolog/monolog", Version: "3.x-dev"})
	if err != nil {
		t.Fatal(err)
	}
	if alias.Archive.Reference != otherSHA {
		t.Errorf("the branch alias 3.x-dev should resolve to dev-main, got %+v", alias.Archive)
	}
	// Each answer is asked for once per run.
	if n := strings.Count(strings.Join(pub.requests(), "\n"), "GET /p2/monolog/monolog.json"); n != 1 {
		t.Errorf("p2 asked %d times", n)
	}
}

func TestAbandoned(t *testing.T) {
	pub := newServer(t)
	monolog(t, pub, "", "Seldaek-monolog-aef6ee7")
	pub.set("/packages/monolog/monolog.json", strings.Replace(monologMeta, `"abandoned":false`, `"abandoned":"monolog/next"`, 1))
	m, err := New(env(t, pub, "")).Meta(context.Background(), core.Ref{Eco: core.Composer, Name: "monolog/monolog", Version: "3.8.1"})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Abandoned {
		t.Error("abandoned flag not read")
	}
}

func TestErrors(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	pub := newServer(t)
	monolog(t, pub, "", "Seldaek-monolog-aef6ee7")
	s := New(env(t, pub, ""))
	ctx := context.Background()
	_, err := s.Versions(ctx, "acme/nothing")
	wantErr(t, err, core.EUnknownPackage,
		"rhythm sightread composer: packagist.org has no package \"acme/nothing\"\n"+
			"  if it comes from a private repository, list it under sources.composer.repositories in .sightread/config.yaml")
	_, err = s.Meta(ctx, core.Ref{Eco: core.Composer, Name: "monolog/monolog", Version: "9.9.9"})
	wantErr(t, err, core.EVersionMissing,
		"rhythm sightread composer: monolog/monolog has no version 9.9.9 on packagist.org\n"+
			"  newest: 3.8.1 · see them all: rhythm sightread composer monolog/monolog --to list")
}

func fetchMonolog(t *testing.T, shasum, top string) (*core.Tree, core.Integrity, *core.Meta, *server) {
	t.Helper()
	pub := newServer(t)
	zip := monolog(t, pub, "", top)
	if shasum == "right" {
		shasum = sha1Hex(zip)
	}
	pub.set("/p2/monolog/monolog.json", monologP2(shasum))
	s := New(env(t, pub, ""))
	ctx := context.Background()
	m, err := s.Meta(ctx, core.Ref{Eco: core.Composer, Name: "monolog/monolog", Version: "3.8.1"})
	if err != nil {
		t.Fatal(err)
	}
	tree, in, err := s.Fetch(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	return tree, in, m, pub
}

func TestFetchCommit(t *testing.T) {
	tree, in, m, pub := fetchMonolog(t, "", "Seldaek-monolog-aef6ee7")
	if in.By != core.ByCommit || in.Method != "pinned to commit aef6ee7; Packagist publishes no archive hash for this package" {
		t.Errorf("Integrity = %+v", in)
	}
	if tree.Root != "Seldaek-monolog-aef6ee7/" || tree.HashKind != core.HashArchive {
		t.Errorf("Root %q HashKind %q", tree.Root, tree.HashKind)
	}
	if _, ok := tree.Lookup("src/Monolog/Logger.php"); !ok {
		t.Error("the top folder was not stripped")
	}
	if m.Type != "library" || m.RequiresPHP != ">=8.1" || !slices.Equal(m.AutoloadFiles, []string{"src/functions.php"}) ||
		!slices.Equal(m.ComposerScripts["post-install-cmd"], []string{"@test", "echo done"}) ||
		!slices.Equal(m.ComposerScripts["test"], []string{"phpunit"}) || m.DevDeps["phpunit/phpunit"] == "" {
		t.Errorf("composer.json not read into Meta: %+v", m)
	}
	if len(m.Changelog) != 2 || m.Changelog[0].Version != "3.8.1" || m.Changelog[0].Text != "* Fixed unsupported operand error" {
		t.Errorf("Changelog = %+v", m.Changelog)
	}
	// The zipball went through the GitHub API and its redirect.
	log := strings.Join(pub.requests(), "\n")
	if !strings.Contains(log, "GET /repos/Seldaek/monolog/zipball/"+commit381) || !strings.Contains(log, "GET /Seldaek/monolog/legacy.zip/") {
		t.Errorf("requests:\n%s", log)
	}
}

func TestFetchShasum(t *testing.T) {
	_, in, _, _ := fetchMonolog(t, "right", "Seldaek-monolog-aef6ee7")
	if in.By != core.ByShasum || in.Method != MethodShasum {
		t.Errorf("right shasum: %+v", in)
	}
	_, in, _, _ = fetchMonolog(t, strings.Repeat("ab", 20), "Seldaek-monolog-aef6ee7")
	if in.By != core.ByFailed || !slices.Equal(in.Mismatch, []string{"dist.shasum"}) || !strings.Contains(in.Detail, "the repository lists abab") {
		t.Errorf("wrong shasum: %+v", in)
	}
}

func TestFetchOtherCommit(t *testing.T) {
	_, in, _, _ := fetchMonolog(t, "", "Seldaek-monolog-0123456")
	if in.By != core.ByFailed || in.Method != MethodCommitFailed ||
		in.Detail != "the archive's top folder Seldaek-monolog-0123456 does not name commit aef6ee7" {
		t.Errorf("Integrity = %+v", in)
	}
}

func TestVerify(t *testing.T) {
	tests := []struct {
		name string
		ref  core.ArchiveRef
		root string
		want core.VerifiedBy
	}{
		{"github 7", core.ArchiveRef{Reference: commit381}, "o-r-aef6ee7/", core.ByCommit},
		{"bitbucket 12", core.ArchiveRef{Reference: commit381}, "o-r-aef6ee73a77a/", core.ByCommit},
		{"gitlab full", core.ArchiveRef{Reference: commit381}, "r-main-" + commit381 + "/", core.ByCommit},
		{"upper case", core.ArchiveRef{Reference: strings.ToUpper(commit381)}, "o-r-AEF6EE7/", core.ByCommit},
		{"too short", core.ArchiveRef{Reference: commit381}, "o-r-aef6/", core.ByFailed},
		{"no folder", core.ArchiveRef{Reference: commit381}, "", core.ByFailed},
		{"no dash", core.ArchiveRef{Reference: commit381}, "aef6ee7/", core.ByFailed},
		{"not a commit", core.ArchiveRef{Reference: "v1.2.3"}, "o-r-aef6ee7/", core.ByNone},
		{"nothing", core.ArchiveRef{}, "o-r-aef6ee7/", core.ByNone},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := verify(tt.ref, core.Download{}, &core.Tree{Root: tt.root})
			if got.By != tt.want {
				t.Errorf("By = %s (%+v), want %s", got.By, got, tt.want)
			}
		})
	}
}

// acmeP2 is a private repository's p2 answer for acme/billing.
func acmeP2(distURL string) string {
	return `{"packages":{"acme/billing":[{"name":"acme/billing","version":"2.1.0","type":"library",
 "dist":{"url":"` + distURL + `","type":"zip","shasum":"","reference":"` + commit380 + `"},"time":"2026-09-01T10:00:00+00:00"}]},"minified":"composer/2.0"}`
}

func TestPrivateRepository(t *testing.T) {
	pub := newServer(t)
	priv := newServer(t)
	priv.set("/packages.json", `{"packages":[],"metadata-url":"/p2/%package%.json","available-packages":["acme/billing"]}`)
	priv.set("/p2/acme/billing.json", acmeP2(priv.url+"/dist/acme-billing-2.1.0.zip"))
	priv.setBytes("/dist/acme-billing-2.1.0.zip", makeZip(t, "acme-billing-32e515f", map[string]string{"src/Bill.php": "<?php"}))
	auth := `{"http-basic":{"` + strings.TrimPrefix(priv.url, "http://") + `":{"username":"ci","password":"` + "pw-" + "fake" + `"}}}`
	s := New(env(t, pub, auth, priv))
	ctx := context.Background()
	m, err := s.Meta(ctx, core.Ref{Eco: core.Composer, Name: "acme/billing"})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Private || m.Ref.Version != "2.1.0" || m.Maintainers != nil {
		t.Errorf("Meta = %+v", m)
	}
	_, in, err := s.Fetch(ctx, m)
	if err != nil {
		t.Fatal(err)
	}
	if in.By != core.ByCommit {
		t.Errorf("Integrity = %+v", in)
	}
	if got := pub.requests(); len(got) != 0 {
		t.Errorf("a private package was looked up on Packagist: %v", got)
	}
	if a := priv.auth["/p2/acme/billing.json"]; !strings.HasPrefix(a, "Basic ") {
		t.Errorf("COMPOSER_AUTH not sent to the private repository: %q", a)
	}
	// A package the repository does not list goes to Packagist.
	monolog(t, pub, "", "Seldaek-monolog-aef6ee7")
	pm, err := s.Meta(ctx, core.Ref{Eco: core.Composer, Name: "monolog/monolog", Version: "3.8.1"})
	if err != nil || pm.Private {
		t.Fatalf("monolog: %+v, %v", pm, err)
	}
	if slices.Contains(priv.requests(), "GET /p2/monolog/monolog.json") {
		t.Error("an unlisted package was asked of the private repository")
	}
}

func TestPrivateRepositoryNoListing(t *testing.T) {
	pub := newServer(t)
	priv := newServer(t)
	priv.set("/packages.json", `{"metadata-url":"/p2/%package%.json"}`)
	priv.set("/p2/acme/billing.json", acmeP2(priv.url+"/dist/x.zip"))
	pub.set("/p2/acme/billing.json", acmeP2("https://evil.example/x.zip"))
	m, err := New(env(t, pub, "", priv)).Meta(context.Background(), core.Ref{Eco: core.Composer, Name: "acme/billing"})
	if err != nil {
		t.Fatal(err)
	}
	if !m.Private || !strings.HasPrefix(m.Archive.URL, priv.url) {
		t.Errorf("the public namesake answered: %+v", m)
	}
}

func TestPrivateRepositoryAuth(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	pub := newServer(t)
	priv := newServer(t)
	priv.status["/packages.json"] = 401
	_, err := New(env(t, pub, "", priv)).Versions(context.Background(), "acme/billing")
	wantErr(t, err, core.EAuth,
		"rhythm sightread composer: 127.0.0.1 answered 401 for acme/billing\n"+
			"  set COMPOSER_AUTH (as Composer reads it); credentials go only to 127.0.0.1")
	if len(pub.requests()) != 0 {
		t.Errorf("Packagist was asked after the private repository refused: %v", pub.requests())
	}
}

func TestGlobMatch(t *testing.T) {
	for _, tt := range []struct {
		p, n string
		want bool
	}{
		{"acme/*", "acme/billing", true},
		{"acme/*", "acmex/billing", false},
		{"*/billing", "acme/billing", true},
		{"acme/bill*-sdk", "acme/billing-sdk", true},
		{"acme/bill*-sdk", "acme/billing", false},
		{"acme/billing", "acme/billing", true},
	} {
		if got := globMatch(tt.p, tt.n); got != tt.want {
			t.Errorf("globMatch(%q, %q) = %v", tt.p, tt.n, got)
		}
	}
}

func TestVerifyLocal(t *testing.T) {
	pub := newServer(t)
	monolog(t, pub, "", "Seldaek-monolog-aef6ee7")
	s := New(env(t, pub, ""))
	ref := core.Ref{Eco: core.Composer, Name: "monolog/monolog", Version: "3.8.1"}
	local := coretest.Tree(map[string]string{
		"composer.json":          monologFiles["composer.json"],
		"src/Monolog/Logger.php": "<?php namespace Monolog; class Logger { function x(){ eval($_GET[1]); } }",
		"src/functions.php":      monologFiles["src/functions.php"],
		"README.md":              monologFiles["README.md"],
		"src/extra.php":          "<?php",
	})
	d, err := s.VerifyLocal(context.Background(), ref, local)
	if err != nil {
		t.Fatal(err)
	}
	if !d.Official || !slices.Equal(d.Differ, []string{"src/Monolog/Logger.php"}) || !slices.Equal(d.Extra, []string{"src/extra.php"}) || len(d.Matched) != 3 {
		t.Errorf("Drift = %+v", d)
	}
	other := coretest.Tree(map[string]string{"a.php": "<?php", "composer.json": "{}"})
	d, err = s.VerifyLocal(context.Background(), ref, other)
	if err != nil {
		t.Fatal(err)
	}
	if d.Official {
		t.Errorf("an unrelated copy counted as official: %+v", d)
	}
}

func TestReadComposerJSONLoose(t *testing.T) {
	cj, err := parseComposerJSON([]byte(`{"type":["x"],"license":["MIT","GPL-2.0-or-later"],"require":{"php":">=7.4"},"scripts":{"a":1,"b":"x"},"autoload":"nope"}`))
	if err != nil {
		t.Fatal(err)
	}
	var m core.Meta
	cj.apply(&m)
	if m.Type != "" || m.License != "MIT OR GPL-2.0-or-later" || m.RequiresPHP != ">=7.4" || len(m.ComposerScripts) != 1 {
		t.Errorf("Meta = %+v", m)
	}
	if _, err := parseComposerJSON([]byte("not json")); err == nil {
		t.Error("invalid JSON accepted")
	}
}
