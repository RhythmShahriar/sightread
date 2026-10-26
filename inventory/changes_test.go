// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/inventory/gitref"
)

// lockPkg is one package-lock v3 entry: the node_modules path, version,
// resolved URL and integrity.
type lockPkg struct{ path, version, resolved, integrity string }

// reg is the public registry tarball URL of name at version.
func reg(name, version string) string {
	base := name
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		base = name[i+1:]
	}
	return "https://registry.npmjs.org/" + name + "/-/" + base + "-" + version + ".tgz"
}

// packageLock builds a package-lock.json v3 whose root depends on deps.
func packageLock(deps map[string]string, pkgs ...lockPkg) string {
	m := map[string]any{"": map[string]any{"name": "app", "version": "1.0.0", "dependencies": deps}}
	for _, p := range pkgs {
		e := map[string]any{"version": p.version, "resolved": p.resolved}
		if p.integrity != "" {
			e["integrity"] = p.integrity
		}
		m[p.path] = e
	}
	b, _ := json.MarshalIndent(map[string]any{"name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": true, "packages": m}, "", "  ")
	return string(b) + "\n"
}

// packageJSON is a root manifest with deps.
func packageJSON(deps map[string]string) string {
	b, _ := json.Marshal(map[string]any{"name": "app", "version": "1.0.0", "dependencies": deps})
	return string(b)
}

// sri is a fake integrity value for tests.
func sri(s string) string { return "sha512-" + s + strings.Repeat("A", 20) + "==" }

// needGit skips when git is missing.
func needGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed; the changes tests need it")
	}
}

// gitRun runs git in dir for test setup, away from the user's config.
func gitRun(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(gitref.Env(os.Environ()), "GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// gitRepo commits base, then writes work into the tree (uncommitted, as
// a pull request checkout would have it after the change). It returns
// the folder and the base commit.
func gitRepo(t *testing.T, base, work map[string]string) (string, string) {
	t.Helper()
	needGit(t)
	dir := t.TempDir()
	gitRun(t, dir, "init", "-q", "-b", "main")
	gitRun(t, dir, "config", "commit.gpgsign", "false")
	writeFiles(t, dir, base)
	writeFiles(t, dir, map[string]string{"README": "x\n"})
	gitRun(t, dir, "add", "-A")
	gitRun(t, dir, "commit", "-q", "-m", "base")
	commit := gitRun(t, dir, "rev-parse", "HEAD")
	writeFiles(t, dir, work)
	return dir, commit
}

// noNPMRC keeps the tests from reading the user's ~/.npmrc.
var noNPMRC = ChangesOptions{Options: Options{NPMRC: []string{}}}

// bumpList renders bumps as "name from>to" lines in order.
func bumpList(bs []core.Bump) []string {
	var out []string
	for _, b := range bs {
		from := "new"
		if b.From != nil {
			from = b.From.Ref.Version
		}
		out = append(out, b.To.Ref.Name+" "+from+">"+b.To.Ref.Version)
	}
	return out
}

func TestChangesPackageLock(t *testing.T) {
	deps := map[string]string{"left-pad": "^1.0.0", "chalk": "^5.0.0", "lodash": "^4.17.0", "gone": "^1.0.0"}
	before := packageLock(deps,
		lockPkg{"node_modules/left-pad", "1.0.0", reg("left-pad", "1.0.0"), sri("lp1")},
		lockPkg{"node_modules/chalk", "5.3.0", reg("chalk", "5.3.0"), sri("ch1")},
		lockPkg{"node_modules/lodash", "4.17.21", reg("lodash", "4.17.21"), sri("lo1")},
		lockPkg{"node_modules/gone", "1.0.0", reg("gone", "1.0.0"), sri("go1")},
	)
	delete(deps, "gone")
	after := packageLock(deps,
		lockPkg{"node_modules/left-pad", "1.3.0", reg("left-pad", "1.3.0"), sri("lp3")},
		lockPkg{"node_modules/chalk", "5.3.0", reg("chalk", "5.3.0"), sri("ch2")}, // same version, other bytes
		lockPkg{"node_modules/lodash", "4.17.21", reg("lodash", "4.17.21"), sri("lo1")},
		lockPkg{"node_modules/left-pad/node_modules/repeat", "2.0.0", reg("repeat", "2.0.0"), sri("re2")}, // added transitive
	)
	dir, base := gitRepo(t,
		map[string]string{"package-lock.json": before, "package.json": packageJSON(deps)},
		map[string]string{"package-lock.json": after})
	cs, err := ReadChanges(context.Background(), core.ChangesRequest{Repo: dir, Base: base}, noNPMRC)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"chalk 5.3.0>5.3.0", "left-pad 1.0.0>1.3.0", "repeat new>2.0.0"}
	got := bumpList(cs.Bumps)
	slices.Sort(got)
	if !slices.Equal(got, want) {
		t.Fatalf("bumps = %q, want %q", got, want)
	}
	for _, b := range cs.Bumps {
		if b.To.Lockfile != "package-lock.json" || b.To.LockLine == 0 {
			t.Errorf("%s: lockfile %q line %d", b.To.Ref, b.To.Lockfile, b.To.LockLine)
		}
		if b.To.Ref.Name == "repeat" && b.To.Direct {
			t.Error("the added transitive package is direct")
		}
		if b.To.Ref.Name == "chalk" && b.From.Integrity == b.To.Integrity {
			t.Error("chalk's integrity change is lost")
		}
	}
	if cs.Base != base || len(cs.NotChecked) != 0 {
		t.Errorf("base %q, not checked %+v", cs.Base, cs.NotChecked)
	}
}

// composerLock builds a composer.lock with one package per entry: name,
// version and dist reference.
func composerLock(pkgs ...[3]string) string {
	var list []map[string]any
	for _, p := range pkgs {
		list = append(list, map[string]any{
			"name": p[0], "version": p[1],
			"dist":             map[string]any{"type": "zip", "url": "https://api.github.com/repos/" + p[0] + "/zipball/" + p[2], "reference": p[2], "shasum": ""},
			"notification-url": "https://packagist.org/downloads/",
		})
	}
	b, _ := json.MarshalIndent(map[string]any{"content-hash": "x", "packages": list, "packages-dev": []any{}}, "", "    ")
	return string(b) + "\n"
}

func TestChangesComposerRetag(t *testing.T) {
	manifest := `{"require": {"monolog/monolog": "^3.0", "psr/log": "^3.0"}}`
	dir, base := gitRepo(t,
		map[string]string{"composer.lock": composerLock([3]string{"monolog/monolog", "3.7.0", "f4393b6"}, [3]string{"psr/log", "3.0.2", "aaaa"}), "composer.json": manifest},
		map[string]string{"composer.lock": composerLock([3]string{"monolog/monolog", "3.7.0", "e1c0ae9"}, [3]string{"psr/log", "3.0.2", "aaaa"})})
	cs, err := ReadChanges(context.Background(), core.ChangesRequest{Repo: dir, Base: base}, noNPMRC)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs.Bumps) != 1 {
		t.Fatalf("bumps = %q", bumpList(cs.Bumps))
	}
	b := cs.Bumps[0]
	if b.From == nil || b.From.Reference != "f4393b6" || b.To.Reference != "e1c0ae9" || b.To.Ref.Version != "3.7.0" || !b.To.Direct {
		t.Errorf("retag bump = %+v from %+v", b.To, b.From)
	}
}

func TestChangesGitHubBaseRef(t *testing.T) {
	before := packageLock(map[string]string{"a": "^1"}, lockPkg{"node_modules/a", "1.0.0", reg("a", "1.0.0"), sri("a1")})
	after := packageLock(map[string]string{"a": "^1"}, lockPkg{"node_modules/a", "1.1.0", reg("a", "1.1.0"), sri("a2")})
	dir, base := gitRepo(t, map[string]string{"web/package-lock.json": before}, map[string]string{"web/package-lock.json": after})
	gitRun(t, dir, "update-ref", "refs/remotes/origin/main", base)
	opt := noNPMRC
	opt.Env = func(k string) string {
		if k == "GITHUB_BASE_REF" {
			return "main"
		}
		return ""
	}
	cs, err := ReadChanges(context.Background(), core.ChangesRequest{Repo: dir}, opt)
	if err != nil {
		t.Fatal(err)
	}
	if cs.Base != "origin/main" || !slices.Equal(bumpList(cs.Bumps), []string{"a 1.0.0>1.1.0"}) {
		t.Fatalf("base %q bumps %q", cs.Base, bumpList(cs.Bumps))
	}
	if cs.Bumps[0].To.Lockfile != "web/package-lock.json" {
		t.Errorf("lockfile = %q", cs.Bumps[0].To.Lockfile)
	}
}

func TestChangesMergeBase(t *testing.T) {
	before := packageLock(map[string]string{"a": "^1"}, lockPkg{"node_modules/a", "1.0.0", reg("a", "1.0.0"), sri("a1")})
	after := packageLock(map[string]string{"a": "^1"}, lockPkg{"node_modules/a", "1.1.0", reg("a", "1.1.0"), sri("a2")})
	dir, base := gitRepo(t, map[string]string{"package-lock.json": before}, map[string]string{"package-lock.json": after})
	opt := noNPMRC
	opt.Env = func(string) string { return "" }
	_, err := ReadChanges(context.Background(), core.ChangesRequest{Repo: dir}, opt)
	var ce *core.Error
	if !errors.As(err, &ce) || ce.Exit != 2 || ce.What != "found no base to compare with: HEAD and origin/HEAD share no commit, or origin/HEAD is not set" {
		t.Fatalf("no origin/HEAD: %v", err)
	}
	gitRun(t, dir, "update-ref", "refs/remotes/origin/main", base)
	gitRun(t, dir, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
	cs, err := ReadChanges(context.Background(), core.ChangesRequest{Repo: dir}, opt)
	if err != nil || cs.Base != base || len(cs.Bumps) != 1 {
		t.Fatalf("cs = %+v, %v", cs, err)
	}
}

func TestChangesRefusesAnOptionRef(t *testing.T) {
	dir, _ := gitRepo(t, map[string]string{"package-lock.json": packageLock(nil)}, nil)
	_, err := ReadChanges(context.Background(), core.ChangesRequest{Repo: dir, Base: "--output=x"}, noNPMRC)
	if core.CodeOf(err) != core.EBadFlag || !strings.Contains(err.Error(), `--base: "--output=x" starts with -, so git would read it as an option`) {
		t.Fatalf("err = %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(dir, "x")); statErr == nil {
		t.Fatal("git wrote the file the ref named")
	}
}

func TestChangesUnknownBase(t *testing.T) {
	dir, _ := gitRepo(t, map[string]string{"package-lock.json": packageLock(nil)}, nil)
	_, err := ReadChanges(context.Background(), core.ChangesRequest{Repo: dir, Base: "origin/nope"}, noNPMRC)
	var ce *core.Error
	if !errors.As(err, &ce) || ce.What != "origin/nope is not a commit in this repository" ||
		ce.Hint[0] != "fetch it first (git fetch origin), or give --before <old lock> --after <new lock> instead" {
		t.Fatalf("err = %v", err)
	}
}

func TestChangesLockfileNewAtHead(t *testing.T) {
	after := packageLock(map[string]string{"a": "^1"}, lockPkg{"node_modules/a", "1.0.0", reg("a", "1.0.0"), sri("a1")})
	dir, base := gitRepo(t, nil, map[string]string{"package-lock.json": after})
	cs, err := ReadChanges(context.Background(), core.ChangesRequest{Repo: dir, Base: base}, noNPMRC)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(bumpList(cs.Bumps), []string{"a new>1.0.0"}) {
		t.Errorf("bumps = %q", bumpList(cs.Bumps))
	}
	want := "package-lock.json is not at " + base + ", so every package in it counts as added"
	if !slices.Contains(cs.Warnings, want) {
		t.Errorf("warnings = %q", cs.Warnings)
	}
}

func TestChangesNoGit(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"package-lock.json": packageLock(nil)})
	t.Setenv("PATH", t.TempDir())
	_, err := ReadChanges(context.Background(), core.ChangesRequest{Repo: dir, Base: "origin/main"}, noNPMRC)
	var ce *core.Error
	if !errors.As(err, &ce) || ce.Exit != 2 || ce.Code != "" {
		t.Fatalf("err = %#v", err)
	}
	want := "git is needed to read package-lock.json at origin/main and wasn't found\n  install git, or give --before <old lock> --after <new lock> instead"
	if got := ce.What + "\n  " + ce.Hint[0]; got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

func TestChangesNotARepo(t *testing.T) {
	needGit(t)
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"package-lock.json": packageLock(nil)})
	_, err := ReadChanges(context.Background(), core.ChangesRequest{Repo: dir, Base: "HEAD"}, noNPMRC)
	var ce *core.Error
	if !errors.As(err, &ce) || ce.What != dir+" is not in a git repository, so there is no base to compare with" {
		t.Fatalf("err = %v", err)
	}
}

func TestChangesBeforeAfterWithoutGit(t *testing.T) {
	dir := t.TempDir()
	deps := map[string]string{"a": "^1"}
	writeFiles(t, dir, map[string]string{
		"old/package-lock.json": packageLock(deps, lockPkg{"node_modules/a", "1.0.0", reg("a", "1.0.0"), sri("a1")}),
		"new/package-lock.json": packageLock(deps, lockPkg{"node_modules/a", "1.2.0", reg("a", "1.2.0"), sri("a2")},
			lockPkg{"node_modules/b", "1.0.0", "git+https://github.com/x/b.git#abc", ""}),
		"new/package.json": packageJSON(map[string]string{"a": "^1", "b": "github:x/b"}),
	})
	t.Setenv("PATH", t.TempDir())
	cs, err := ReadChanges(context.Background(), core.ChangesRequest{
		Before: filepath.Join(dir, "old", "package-lock.json"), After: filepath.Join(dir, "new", "package-lock.json")}, noNPMRC)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(bumpList(cs.Bumps), []string{"a 1.0.0>1.2.0"}) || cs.Base != "" {
		t.Fatalf("bumps = %q", bumpList(cs.Bumps))
	}
	if len(cs.NotChecked) != 1 || cs.NotChecked[0].Name != "b" || cs.NotChecked[0].Reason != core.VCS {
		t.Errorf("not checked = %+v", cs.NotChecked)
	}
	if !cs.Bumps[0].To.Direct || cs.Bumps[0].To.Constraint != "^1" {
		t.Errorf("manifest next to --after not read: %+v", cs.Bumps[0].To)
	}
}

func TestChangesBeforeAfterErrors(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"package-lock.json": packageLock(nil), "composer.lock": composerLock(), "notes.txt": "x"})
	p := func(n string) string { return filepath.Join(dir, n) }
	for _, c := range []struct {
		req  core.ChangesRequest
		want string
	}{
		{core.ChangesRequest{Before: p("package-lock.json")}, "--before and --after go together: the old and the new lockfile"},
		{core.ChangesRequest{Before: p("composer.lock"), After: p("package-lock.json")}, "--before composer.lock and --after package-lock.json are different kinds of lockfile"},
		{core.ChangesRequest{Before: p("notes.txt"), After: p("notes.txt")}, "notes.txt is not a lockfile Sightread reads"},
		{core.ChangesRequest{Before: p("gone/package-lock.json"), After: p("package-lock.json")}, "--before " + p("gone/package-lock.json") + ": "},
	} {
		_, err := ReadChanges(context.Background(), c.req, noNPMRC)
		var ce *core.Error
		if !errors.As(err, &ce) || ce.Exit != 2 || !strings.HasPrefix(ce.What, c.want) {
			t.Errorf("%+v: err = %v, want %q", c.req, err, c.want)
		}
	}
}

func TestChangesSourceMove(t *testing.T) {
	deps := map[string]string{"xlsx": "*", "fresh": "*"}
	before := packageLock(deps, lockPkg{"node_modules/xlsx", "0.18.5", reg("xlsx", "0.18.5"), sri("x1")})
	after := packageLock(deps,
		lockPkg{"node_modules/xlsx", "0.20.3", "https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz", sri("x2")},
		lockPkg{"node_modules/fresh", "1.0.0", "https://cdn.example.test/fresh-1.0.0.tgz", ""})
	cs, err := changesFromBytes(t, before, after)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(bumpList(cs.Bumps), []string{"xlsx 0.18.5>0.20.3"}) || cs.Bumps[0].To.ResolvedKind != core.ResolvedTarball {
		t.Fatalf("bumps = %q", bumpList(cs.Bumps))
	}
	if len(cs.NotChecked) != 1 || cs.NotChecked[0].Name != "fresh" || cs.NotChecked[0].Reason != core.VCS {
		t.Errorf("not checked = %+v", cs.NotChecked)
	}
}

// changesFromBytes runs --before/--after over two package-lock bodies.
func changesFromBytes(t *testing.T, before, after string) (*ChangeSet, error) {
	t.Helper()
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"a/package-lock.json": before, "b/package-lock.json": after})
	return ReadChanges(context.Background(), core.ChangesRequest{
		Before: filepath.Join(dir, "a", "package-lock.json"), After: filepath.Join(dir, "b", "package-lock.json")}, noNPMRC)
}

func TestChangesLockfiles(t *testing.T) {
	needGit(t)
	ctx := context.Background()
	t.Run("none", func(t *testing.T) {
		dir := t.TempDir()
		_, err := ReadChanges(ctx, core.ChangesRequest{Repo: dir, Base: "HEAD"}, noNPMRC)
		want := "no lockfile in " + dir + " (looked for composer.lock, npm-shrinkwrap.json, package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lock)\n  run your package manager once to write one; Sightread compares versions a lockfile pins"
		var ce *core.Error
		if !errors.As(err, &ce) || ce.Code != core.ENoLockfile || ce.What+"\n  "+ce.Hint[0] != want {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("bun.lockb found", func(t *testing.T) {
		dir := t.TempDir()
		writeFiles(t, dir, map[string]string{"bun.lockb": "\x00bun"})
		cs, err := ReadChanges(ctx, core.ChangesRequest{Repo: dir, Base: "HEAD"}, noNPMRC)
		if err != nil {
			t.Fatal(err)
		}
		if len(cs.NotChecked) != 1 || cs.NotChecked[0].Reason != core.UnsupportedLock ||
			cs.NotChecked[0].Text != "bun.lockb is Bun's binary lockfile, which Sightread can't read" ||
			cs.NotChecked[0].Hint != "run bun install --save-text-lockfile once to write bun.lock" {
			t.Errorf("not checked = %+v", cs.NotChecked)
		}
	})
	t.Run("bun.lockb named", func(t *testing.T) {
		_, err := ReadChanges(ctx, core.ChangesRequest{Repo: t.TempDir(), Base: "HEAD", Lockfiles: []string{"bun.lockb"}}, noNPMRC)
		var ce *core.Error
		if !errors.As(err, &ce) || ce.Code != core.EUnsupportedLock || ce.Command != "" {
			t.Fatalf("err = %#v", err)
		}
	})
	t.Run("named outside", func(t *testing.T) {
		_, err := ReadChanges(ctx, core.ChangesRequest{Repo: t.TempDir(), Base: "HEAD", Lockfiles: []string{"../package-lock.json"}}, noNPMRC)
		if core.CodeOf(err) != core.EBadFlag || !strings.Contains(err.Error(), "--lockfile ../package-lock.json: not inside the repository folder") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("walk", func(t *testing.T) {
		dir := t.TempDir()
		writeFiles(t, dir, map[string]string{
			"composer.lock": "{}", "web/yarn.lock": "", "web/package-lock.json": "{}", "node_modules/x/package-lock.json": "{}",
			"a/b/c/d/e/f/g/package-lock.json": "{}", "vendor/x/composer.lock": "{}",
		})
		got, err := changeLockfiles(ctx, dir, nil, &ChangeSet{})
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"composer.lock", "web/package-lock.json"}; !slices.Equal(got, want) {
			t.Errorf("lockfiles = %q, want %q", got, want)
		}
	})
	t.Run("named in a folder", func(t *testing.T) {
		after := packageLock(map[string]string{"a": "^1"}, lockPkg{"node_modules/a", "1.0.0", reg("a", "1.0.0"), sri("a1")})
		dir, base := gitRepo(t, map[string]string{"web/package-lock.json": after, "package-lock.json": packageLock(nil)},
			map[string]string{"web/package-lock.json": strings.ReplaceAll(after, "1.0.0", "1.0.1"), "package-lock.json": after})
		cs, err := ReadChanges(ctx, core.ChangesRequest{Repo: dir, Base: base, Lockfiles: []string{filepath.Join(dir, "web", "package-lock.json")}}, noNPMRC)
		if err != nil || !slices.Equal(bumpList(cs.Bumps), []string{"a 1.0.0>1.0.1"}) {
			t.Fatalf("bumps = %v, %v", cs, err)
		}
	})
}

func TestChangesBadLockAtBase(t *testing.T) {
	dir, base := gitRepo(t, map[string]string{"package-lock.json": "{not json"}, map[string]string{"package-lock.json": packageLock(nil)})
	_, err := ReadChanges(context.Background(), core.ChangesRequest{Repo: dir, Base: base}, noNPMRC)
	if core.CodeOf(err) != core.EUnsupportedLock || !strings.Contains(err.Error(), "package-lock.json can't be read: ") {
		t.Fatalf("err = %v", err)
	}
}

func TestLockBumpsPairing(t *testing.T) {
	in := func(name, version, kind string) core.Installed {
		return core.Installed{Ref: core.Ref{Eco: core.NPM, Name: name, Version: version}, ResolvedKind: kind}
	}
	old := []core.Installed{in("a", "1.0.0", "registry"), in("a", "2.0.0", "registry"), in("g", "1.0.0", "git"), in("Cmp", "1.0.0", "")}
	cur := []core.Installed{in("a", "2.0.0", "registry"), in("a", "1.5.0", "registry"), in("g", "1.1.0", "git"), in("a", "0.9.0", "registry")}
	bumps, nc := lockBumps(old, cur)
	if got, want := bumpList(bumps), []string{"a 1.0.0>1.5.0", "a 1.0.0>0.9.0"}; !slices.Equal(got, want) {
		t.Errorf("bumps = %q, want %q", got, want)
	}
	if len(nc) != 1 || nc[0].Name != "g" || nc[0].Version != "1.1.0" || nc[0].Text != "git, path or tarball dependency" {
		t.Errorf("not checked = %+v", nc)
	}
	cOld := []core.Installed{{Ref: core.Ref{Eco: core.Composer, Name: "Acme/Log", Version: "1.0.0"}}}
	cNew := []core.Installed{{Ref: core.Ref{Eco: core.Composer, Name: "acme/log", Version: "1.1.0"}}}
	if b, _ := lockBumps(cOld, cNew); len(b) != 1 || b[0].From == nil {
		t.Errorf("composer names are not matched without case: %q", bumpList(b))
	}
	if b, nc := lockBumps(cur, cur); len(b) != 0 || len(nc) != 0 {
		t.Errorf("no change gave %q %+v", bumpList(b), nc)
	}
}
