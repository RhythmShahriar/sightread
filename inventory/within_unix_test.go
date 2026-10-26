// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build unix

package inventory

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
)

// outsideSecret writes a file outside the project that a hostile link
// could point at and returns its path.
func outsideSecret(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), ".npmrc")
	tok := "npm_" + strings.Repeat("Q7", 18)
	if err := os.WriteFile(p, []byte("//registry.npmjs.org/:_authToken="+tok+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWithin(t *testing.T) {
	root := t.TempDir()
	writeFiles(t, root, map[string]string{"real.lock": "x", "sub/a": "y"})
	if err := os.Symlink("real.lock", filepath.Join(root, "inside.lock")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideSecret(t), filepath.Join(root, "out.lock")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "sub"), filepath.Join(root, "subdir")); err != nil {
		t.Fatal(err)
	}
	for _, ok := range []string{"real.lock", "inside.lock", "subdir/a"} {
		if _, err := readAllWithin(root, filepath.Join(root, filepath.FromSlash(ok)), 1<<10); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	if _, err := readAllWithin(root, filepath.Join(root, "out.lock"), 1<<10); !errors.Is(err, errOutsideRoot) {
		t.Errorf("out.lock: err = %v, want errOutsideRoot", err)
	}
	if _, err := readAllWithin(root, filepath.Join(root, "gone.lock"), 1<<10); !os.IsNotExist(err) {
		t.Errorf("gone.lock: err = %v, want not exist", err)
	}
}

func TestReadNPMRefusesLinkOutside(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(outsideSecret(t), filepath.Join(dir, "yarn.lock")); err != nil {
		t.Fatal(err)
	}
	_, err := ReadNPM(dir, Options{NPMRC: []string{}})
	if !errors.Is(err, errOutsideRoot) || strings.Contains(err.Error(), "authToken") {
		t.Fatalf("err = %v", err)
	}
}

func TestReadNPMSkipsManifestOutside(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{"package-lock.json": packageLock(nil)})
	if err := os.Symlink(outsideSecret(t), filepath.Join(dir, "package.json")); err != nil {
		t.Fatal(err)
	}
	p, err := ReadNPM(dir, Options{NPMRC: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(p.Warnings, "\n"), "skipped package.json: it is a link that leads outside the project folder") {
		t.Errorf("warnings = %q", p.Warnings)
	}
}

func TestReadComposerRefusesLinkOutside(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(outsideSecret(t), filepath.Join(dir, ComposerLock)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadComposer(dir, Options{}); !errors.Is(err, errOutsideRoot) {
		t.Fatalf("err = %v", err)
	}
}

func TestChangesRefusesLockLinkOutside(t *testing.T) {
	deps := map[string]string{"a": "^1"}
	dir, _ := gitRepo(t, map[string]string{"yarn.lock": "", "package.json": packageJSON(deps)}, nil)
	target := outsideSecret(t)
	if err := os.Remove(filepath.Join(dir, "yarn.lock")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "yarn.lock")); err != nil {
		t.Fatal(err)
	}
	_, err := ReadChanges(context.Background(), core.ChangesRequest{Repo: dir, Base: "HEAD", Lockfiles: []string{"yarn.lock"}}, noNPMRC)
	var ce *core.Error
	if !errors.As(err, &ce) || ce.What != "can't read yarn.lock: it is a link that leads outside the project folder" {
		t.Fatalf("err = %v", err)
	}
}
