// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
)

// isolateHome points HOME at an empty folder so ~/.npmrc of the person
// running the tests is never read.
func isolateHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
}

// fixture copies testdata folders into one temp folder: dst path to
// testdata path.
func fixture(t *testing.T, parts map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for dst, src := range parts {
		from := copyTree(t, filepath.Join("testdata", filepath.FromSlash(src)))
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, dst)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(from, filepath.Join(dir, filepath.FromSlash(dst))); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// mergeInto copies the testdata folder src into dir.
func mergeInto(t *testing.T, dir, src string) {
	t.Helper()
	from := copyTree(t, filepath.Join("testdata", filepath.FromSlash(src)))
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if err := os.Rename(filepath.Join(from, e.Name()), filepath.Join(dir, e.Name())); err != nil {
			t.Fatal(err)
		}
	}
}

// refs lists the Installed entries as eco:name strings.
func refs(s *core.Site) []string {
	var out []string
	for _, in := range s.Installed {
		out = append(out, string(in.Ref.Eco)+":"+in.Ref.Name)
	}
	return out
}

// find returns the Installed entry eco:name, or nil.
func find(s *core.Site, eco core.Ecosystem, name string) *core.Installed {
	for i := range s.Installed {
		if s.Installed[i].Ref.Eco == eco && s.Installed[i].Ref.Name == name {
			return &s.Installed[i]
		}
	}
	return nil
}

// notCheckedReason returns the reason name is listed with, or "".
func notCheckedReason(s *core.Site, name string) core.NotCheckedReason {
	for _, nc := range s.NotChecked {
		if nc.Name == name {
			return nc.Reason
		}
	}
	return ""
}

func TestRegistered(t *testing.T) {
	if _, ok := core.GetInventory().(*Reader); !ok {
		t.Fatalf("inventory registered %T", core.GetInventory())
	}
}

func TestReadKinds(t *testing.T) {
	isolateHome(t)
	mixed := t.TempDir()
	mergeInto(t, mixed, "composer/laravel")
	mergeInto(t, mixed, "npm/v3")
	cases := []struct {
		name string
		root string
		ecos []core.Ecosystem
		kind string
		has  []string
	}{
		{"wordpress", filepath.Join("testdata", "wp", "site"), nil, KindWordPress, []string{"wp-plugin:akismet", "wp-theme:twentytwentyfour"}},
		{"wordpress below", fixture(t, map[string]string{"srv/www/site": "wp/site"}), nil, KindWordPress, []string{"wp-plugin:akismet"}},
		{"composer", filepath.Join("testdata", "composer", "laravel"), nil, KindComposer, []string{"composer:laravel/framework"}},
		{"npm", filepath.Join("testdata", "npm", "v3"), nil, KindNPM, []string{"npm:react"}},
		{"mixed", mixed, nil, KindMixed, []string{"composer:laravel/framework", "npm:react"}},
		{"mixed, composer only", mixed, []core.Ecosystem{core.Composer}, KindComposer, []string{"composer:laravel/framework"}},
		{"mixed, npm only", mixed, []core.Ecosystem{core.NPM}, KindNPM, []string{"npm:react"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, err := (&Reader{}).Read(context.Background(), core.InventoryRequest{Root: c.root, Ecosystems: c.ecos})
			if err != nil {
				t.Fatal(err)
			}
			if s.Kind != c.kind || s.Root != c.root {
				t.Errorf("kind %q root %q", s.Kind, s.Root)
			}
			got := refs(s)
			for _, h := range c.has {
				if !slices.Contains(got, h) {
					t.Errorf("missing %s in %q", h, got)
				}
			}
			for _, in := range s.Installed {
				if len(c.ecos) > 0 && !slices.Contains(c.ecos, in.Ref.Eco) {
					t.Errorf("%s is outside the ecosystems asked for", in.Ref)
				}
			}
		})
	}
}

func TestReadWordPressBelowRoot(t *testing.T) {
	root := fixture(t, map[string]string{"srv/www/site": "wp/site", "backup/old": "wp/site"})
	s, err := (&Reader{}).Read(context.Background(), core.InventoryRequest{Root: root, Ecosystems: []core.Ecosystem{core.WPPlugin}})
	if err != nil {
		t.Fatal(err)
	}
	ak := find(s, core.WPPlugin, "akismet")
	if ak == nil {
		t.Fatalf("installed = %q", refs(s))
	}
	// Both copies are 2 folders down; the first in name order is read.
	if ak.Path != "backup/old/wp-content/plugins/akismet" || !strings.HasPrefix(ak.Lockfile, "backup/old/wp-content/plugins/akismet/") {
		t.Errorf("path %q lockfile %q: want them relative to the root", ak.Path, ak.Lockfile)
	}
	want := "found 2 WordPress sites under " + root + ": read backup/old, not srv/www/site; name one with --path to read another"
	if !slices.Contains(s.Warnings, want) {
		t.Errorf("warnings = %q", s.Warnings)
	}
	if find(s, core.WPTheme, "twentytwentyfour") != nil {
		t.Error("a theme was read for wp-plugin only")
	}
	if notCheckedReason(s, "wordpress") != core.Core {
		t.Error("core is not listed for plugins")
	}
}

func TestReadNPMShapedForReview(t *testing.T) {
	isolateHome(t)
	root := filepath.Join("testdata", "npm", "v3")
	s, err := (&Reader{}).Read(context.Background(), core.InventoryRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if find(s, core.NPM, "xlsx") != nil || notCheckedReason(s, "xlsx") != core.VCS {
		t.Errorf("xlsx from cdn.sheetjs.com: installed %v, reason %q", find(s, core.NPM, "xlsx"), notCheckedReason(s, "xlsx"))
	}
	b := find(s, core.NPM, "@acme/billing")
	if b == nil || !b.Private || notCheckedReason(s, "@acme/billing") != "" {
		t.Errorf("@acme/billing = %+v, reason %q (run lists private packages)", b, notCheckedReason(s, "@acme/billing"))
	}
	if find(s, core.NPM, "js-tokens") != nil {
		t.Error("a transitive package was kept without Transitive")
	}
	all, err := (&Reader{}).Read(context.Background(), core.InventoryRequest{Root: root, Transitive: true})
	if err != nil {
		t.Fatal(err)
	}
	if find(all, core.NPM, "js-tokens") == nil || len(all.Installed) <= len(s.Installed) {
		t.Errorf("Transitive kept %q", refs(all))
	}
	for _, in := range s.Installed {
		if !in.Direct {
			t.Errorf("%s is not direct", in.Ref)
		}
	}
}

func TestReadComposerTransitive(t *testing.T) {
	root := filepath.Join("testdata", "composer", "laravel")
	direct, err := (&Reader{}).Read(context.Background(), core.InventoryRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	all, err := (&Reader{}).Read(context.Background(), core.InventoryRequest{Root: root, Transitive: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(direct.Installed) != 9 || len(all.Installed) != 111 {
		t.Errorf("direct %d, all %d; want 9 and 111", len(direct.Installed), len(all.Installed))
	}
}

func TestReadNamedLockfile(t *testing.T) {
	isolateHome(t)
	root := fixture(t, map[string]string{"web": "npm/v3"})
	s, err := (&Reader{}).Read(context.Background(), core.InventoryRequest{Root: root, Lockfiles: []string{"web/package-lock.json"}})
	if err != nil {
		t.Fatal(err)
	}
	r := find(s, core.NPM, "react")
	if r == nil || r.Lockfile != "web/package-lock.json" || r.Path != "web/node_modules/react" {
		t.Fatalf("react = %+v", r)
	}
	_, err = (&Reader{}).Read(context.Background(), core.InventoryRequest{Root: root, Lockfiles: []string{"web/notes.txt"}})
	if core.CodeOf(err) != core.EUnsupportedLock {
		t.Errorf("unknown lockfile name: %v", err)
	}
}

func TestReadTunerReportAsSource(t *testing.T) {
	report, err := filepath.Abs(filepath.Join("testdata", "tuner", "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := (&Reader{}).Read(context.Background(), core.InventoryRequest{
		Root: filepath.Join(t.TempDir(), "absent"), TunerReport: report, Ecosystems: []core.Ecosystem{core.WPPlugin}})
	if err != nil {
		t.Fatal(err)
	}
	if s.Kind != KindWordPress || find(s, core.WPPlugin, "woocommerce") == nil || find(s, core.WPTheme, "storefront") != nil {
		t.Errorf("site = %q", refs(s))
	}
}

func TestReadBunLockb(t *testing.T) {
	root := filepath.Join("testdata", "npm", "lockb")
	_, err := (&Reader{}).Read(context.Background(), core.InventoryRequest{Root: root, Ecosystems: []core.Ecosystem{core.NPM}})
	var ce *core.Error
	if !errors.As(err, &ce) || ce.Code != core.EUnsupportedLock || ce.What != "bun.lockb is Bun's binary lockfile, which Sightread can't read" {
		t.Fatalf("npm only: %v", err)
	}
	s, err := (&Reader{}).Read(context.Background(), core.InventoryRequest{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	if s.Kind != KindNPM || notCheckedReason(s, "bun.lockb") != core.UnsupportedLock {
		t.Errorf("all: %+v", s)
	}
}

func TestReadNothingFound(t *testing.T) {
	empty := t.TempDir()
	cases := []struct {
		name string
		root string
		ecos []core.Ecosystem
		code core.ErrorCode
		want string
	}{
		{"plugin", empty, []core.Ecosystem{core.WPPlugin}, core.ENothingInstalled,
			"no WordPress site under " + empty + " (looked 6 folders down for wp-includes/version.php and wp-content)\n" +
				`  name the site with --path /var/www/site, read it with --wp "wp --path=..." or give the version: --from <version>`},
		{"theme", empty, []core.Ecosystem{core.WPTheme}, core.ENothingInstalled, "no WordPress site under " + empty + " (looked 6 folders down"},
		{"npm", empty, []core.Ecosystem{core.NPM}, core.ENoLockfile,
			"no lockfile in " + empty + " (looked for npm-shrinkwrap.json, package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lock)\n" +
				"  run your package manager once to write one; Sightread compares versions a lockfile pins"},
		{"composer", empty, []core.Ecosystem{core.Composer}, core.ENoLockfile,
			"no lockfile in " + empty + " (looked for composer.lock)\n  run your package manager once to write one; Sightread compares versions a lockfile pins"},
		{"all", empty, nil, core.ENothingInstalled,
			"nothing installed found under " + empty + " (looked for a WordPress site up to 6 folders down, composer.lock and npm lockfiles)\n" +
				`  name the site or project folder, read a site with --wp "wp --path=..." or give a Tuner report with --from-tuner <report.json>`},
		{"missing folder", filepath.Join(empty, "nope"), []core.Ecosystem{core.WPPlugin}, core.ENothingInstalled,
			"no WordPress site under " + filepath.Join(empty, "nope") + " (no such folder)"},
		{"missing folder, npm", filepath.Join(empty, "nope"), []core.Ecosystem{core.NPM}, core.ENoLockfile,
			"no lockfile in " + filepath.Join(empty, "nope") + " (no such folder)"},
		{"composer only in an npm project", filepath.Join("testdata", "npm", "v3"), []core.Ecosystem{core.Composer}, core.ENoLockfile, "no lockfile in"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := (&Reader{}).Read(context.Background(), core.InventoryRequest{Root: c.root, Ecosystems: c.ecos})
			var ce *core.Error
			if !errors.As(err, &ce) {
				t.Fatalf("err = %v", err)
			}
			if ce.Code != c.code || ce.Exit != 2 || ce.Command != "" {
				t.Errorf("code %q exit %d command %q", ce.Code, ce.Exit, ce.Command)
			}
			got := ce.What + "\n  " + strings.Join(ce.Hint, "\n  ")
			if !strings.HasPrefix(got, c.want) {
				t.Errorf("got  %q\nwant %q", got, c.want)
			}
		})
	}
}

func TestReaderChanges(t *testing.T) {
	isolateHome(t)
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"a/package-lock.json": packageLock(map[string]string{"a": "^1"}, lockPkg{"node_modules/a", "1.0.0", reg("a", "1.0.0"), sri("a1")}),
		"b/package-lock.json": packageLock(map[string]string{"a": "^1"}, lockPkg{"node_modules/a", "1.0.1", reg("a", "1.0.1"), sri("a2")}),
	})
	cs, err := (&Reader{}).Changes(context.Background(), core.ChangesRequest{
		Before: filepath.Join(dir, "a", "package-lock.json"), After: filepath.Join(dir, "b", "package-lock.json")})
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.NotChecked) != 0 || cs.Base != "" || !slices.Equal(bumpList(cs.Bumps), []string{"a 1.0.0>1.0.1"}) {
		t.Fatalf("change set %+v", cs)
	}
	if _, err := (&Reader{}).Changes(context.Background(), core.ChangesRequest{Before: "x"}); core.CodeOf(err) != core.EBadFlag {
		t.Errorf("err = %v", err)
	}
}
