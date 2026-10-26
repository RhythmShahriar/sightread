// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package gitref

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
)

// needGit skips a test when git is not installed.
func needGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed; the git ref tests need it")
	}
}

// git runs git in dir for a test's setup, isolated from the user's
// config. It returns the trimmed output.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(Env(os.Environ()), "GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.test", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.test")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// repo makes a repository with two commits of a.txt (old, then new)
// and web/b.txt only in the second. It returns the folder and the
// first commit.
func repo(t *testing.T) (dir, first string) {
	t.Helper()
	needGit(t)
	dir = t.TempDir()
	git(t, dir, "init", "-q", "-b", "main")
	git(t, dir, "config", "commit.gpgsign", "false")
	write(t, dir, "a.txt", "old\n")
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "one")
	first = git(t, dir, "rev-parse", "HEAD")
	write(t, dir, "a.txt", "new\n")
	write(t, dir, "web/b.txt", "b\n")
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "two")
	return dir, first
}

func write(t *testing.T, dir, name, data string) {
	t.Helper()
	p := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestRegistered(t *testing.T) {
	if core.GetGitShow() == nil {
		t.Fatal("gitref did not register with core.SetGitShow")
	}
}

func TestValidRef(t *testing.T) {
	for _, ok := range []string{"main", "origin/main", "HEAD~1", "HEAD^", "v1.2.3", "release/2026-10", "a1b2c3d4", "feature_x@2"} {
		if err := ValidRef(ok); err != nil {
			t.Errorf("ValidRef(%q) = %v", ok, err)
		}
	}
	for ref, want := range map[string]string{
		"--output=x":             `"--output=x" starts with -, so git would read it as an option`,
		"-p":                     "starts with -",
		"":                       "the ref is empty",
		"main:secret":            "is not a git ref",
		"a b":                    "is not a git ref",
		"@{u}":                   "is not a git ref",
		"main..evil":             "names a range",
		strings.Repeat("a", 201): "is not a git ref",
		"x\x1b[31m":              "is not a git ref",
	} {
		err := ValidRef(ref)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ValidRef(%q) = %v, want %q", ref, err, want)
		}
		if err != nil && strings.ContainsRune(err.Error(), 0x1b) {
			t.Errorf("control byte in %q", err)
		}
	}
}

func TestValidPath(t *testing.T) {
	for _, ok := range []string{"package-lock.json", "web/yarn.lock", "./composer.lock"} {
		if err := ValidPath(ok); err != nil {
			t.Errorf("ValidPath(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"", "../x", "/etc/passwd", "a/../../b", "a\x00b", "a\nb", strings.Repeat("a", 1025)} {
		if err := ValidPath(bad); err == nil {
			t.Errorf("ValidPath(%q) = nil", bad)
		}
	}
}

func TestArgvAndEnv(t *testing.T) {
	got := Argv("git", "/r", "show", "--no-textconv", "HEAD:./a")
	want := []string{"git", "-C", "/r", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.DevNull, "show", "--no-textconv", "HEAD:./a"}
	if !slices.Equal(got, want) {
		t.Errorf("argv = %q\nwant   %q", got, want)
	}
	env := Env([]string{"PATH=/bin", "GIT_DIR=/elsewhere", "GIT_CONFIG_PARAMETERS='core.fsmonitor=x'", "LC_ALL=de_DE", "HOME=/h"})
	wantEnv := []string{"PATH=/bin", "HOME=/h", "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_NOSYSTEM=1", "GIT_OPTIONAL_LOCKS=0", "LC_ALL=C"}
	if !slices.Equal(env, wantEnv) {
		t.Errorf("env = %q\nwant  %q", env, wantEnv)
	}
}

func TestShow(t *testing.T) {
	dir, first := repo(t)
	ctx := context.Background()
	b, err := Show(ctx, dir, first, "a.txt")
	if err != nil || string(b) != "old\n" {
		t.Fatalf("Show(first) = %q, %v", b, err)
	}
	if b, err = Show(ctx, dir, "HEAD", "a.txt"); err != nil || string(b) != "new\n" {
		t.Fatalf("Show(HEAD) = %q, %v", b, err)
	}
	// The path is relative to the folder given, even inside the tree.
	if b, err = Show(ctx, filepath.Join(dir, "web"), "HEAD", "b.txt"); err != nil || string(b) != "b\n" {
		t.Fatalf("Show(web) = %q, %v", b, err)
	}
	_, err = Show(ctx, dir, first, "web/b.txt")
	if !errors.Is(err, ErrNotAtRef) || !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing at ref: %v", err)
	}
	if _, err = Show(ctx, dir, "nope", "a.txt"); err == nil || errors.Is(err, ErrNotAtRef) {
		t.Errorf("unknown ref: %v", err)
	}
	if _, err = Show(ctx, dir, "--output=x", "a.txt"); err == nil || !strings.Contains(err.Error(), "starts with -") {
		t.Errorf("option ref: %v", err)
	}
	if _, err = Show(ctx, dir, "HEAD", "../a.txt"); err == nil {
		t.Error("a path outside the repository was read")
	}
}

func TestShowIgnoresGitDirFromTheEnvironment(t *testing.T) {
	dir, _ := repo(t)
	t.Setenv("GIT_DIR", filepath.Join(t.TempDir(), "elsewhere"))
	if b, err := Show(context.Background(), dir, "HEAD", "a.txt"); err != nil || string(b) != "new\n" {
		t.Fatalf("Show = %q, %v", b, err)
	}
}

func TestCommit(t *testing.T) {
	dir, first := repo(t)
	ctx := context.Background()
	if h, err := Commit(ctx, dir, first[:10]); err != nil || h != first {
		t.Errorf("Commit = %q, %v", h, err)
	}
	if _, err := Commit(ctx, dir, "origin/nope"); !errors.Is(err, ErrUnknownRef) {
		t.Errorf("unknown: %v", err)
	}
	if _, err := Commit(ctx, t.TempDir(), "HEAD"); !errors.Is(err, ErrNotRepo) {
		t.Errorf("not a repo: %v", err)
	}
}

func TestResolveBase(t *testing.T) {
	dir, first := repo(t)
	ctx := context.Background()
	env := func(v string) func(string) string {
		return func(k string) string {
			if k == "GITHUB_BASE_REF" {
				return v
			}
			return ""
		}
	}
	if b, err := ResolveBase(ctx, dir, env("main")); err != nil || b != "origin/main" {
		t.Errorf("GITHUB_BASE_REF: %q, %v", b, err)
	}
	if _, err := ResolveBase(ctx, dir, env("main:x")); err == nil {
		t.Error("a bad GITHUB_BASE_REF was accepted")
	}
	if _, err := ResolveBase(ctx, dir, env("")); !errors.Is(err, ErrNoBase) {
		t.Errorf("no origin/HEAD: %v", err)
	}
	git(t, dir, "update-ref", "refs/remotes/origin/main", first)
	git(t, dir, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
	if b, err := ResolveBase(ctx, dir, env("")); err != nil || b != first {
		t.Errorf("merge base = %q, %v; want %s", b, err, first)
	}
	if _, err := ResolveBase(ctx, t.TempDir(), env("")); !errors.Is(err, ErrNotRepo) {
		t.Errorf("not a repo: %v", err)
	}
}

func TestNoGit(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if _, err := Show(context.Background(), t.TempDir(), "HEAD", "a.txt"); !errors.Is(err, ErrNoGit) {
		t.Errorf("err = %v", err)
	}
}

func TestCanceled(t *testing.T) {
	dir, _ := repo(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Show(ctx, dir, "HEAD", "a.txt"); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
}

func FuzzValidRef(f *testing.F) {
	for _, s := range []string{"main", "--output=x", "a:b", "HEAD~1", "a..b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, ref string) {
		if ValidRef(ref) != nil {
			return
		}
		if strings.HasPrefix(ref, "-") || strings.ContainsAny(ref, ": \t\n{}") || strings.Contains(ref, "..") || len(ref) > 200 {
			t.Fatalf("accepted %q", ref)
		}
	})
}
