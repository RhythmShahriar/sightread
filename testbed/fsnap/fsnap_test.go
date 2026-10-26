// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package fsnap

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func write(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestDiffFindsEveryKindOfChange(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "keep.txt"), "same")
	write(t, filepath.Join(root, "edit.txt"), "before")
	write(t, filepath.Join(root, "gone.txt"), "x")
	write(t, filepath.Join(root, "work", "cache.bin"), "a")

	before, err := Take(root, "work")
	if err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(root, "edit.txt"), "after!")
	write(t, filepath.Join(root, "new", "file.txt"), "y")
	write(t, filepath.Join(root, "work", "cache.bin"), "changed but skipped")
	if err := os.Remove(filepath.Join(root, "gone.txt")); err != nil {
		t.Fatal(err)
	}
	after, err := Take(root, "work")
	if err != nil {
		t.Fatal(err)
	}

	got := Diff(before, after)
	want := []Change{
		{"edit.txt", "changed"},
		{"gone.txt", "removed"},
		{"new", "added"},
		{"new/file.txt", "added"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Diff = %v, want %v", got, want)
	}
	if before.Digest() == after.Digest() {
		t.Error("Digest did not change with the tree")
	}
}

func TestUnchangedTreeIsIdentical(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, "a", "b.php"), "<?php echo 1;")
	if runtime.GOOS != "windows" {
		if err := os.Symlink("a/b.php", filepath.Join(root, "link")); err != nil {
			t.Fatal(err)
		}
	}
	s1, err := Take(root)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := Take(root)
	if err != nil {
		t.Fatal(err)
	}
	if d := Diff(s1, s2); len(d) != 0 {
		t.Errorf("an untouched tree changed: %v", d)
	}
	if s1.Digest() != s2.Digest() {
		t.Error("Digest differs for the same tree")
	}
}

func TestMissingRootIsEmpty(t *testing.T) {
	s, err := Take(filepath.Join(t.TempDir(), "nope"))
	if err != nil || len(s) != 0 {
		t.Fatalf("Take(missing) = %v, %v; want empty, nil", s, err)
	}
}
