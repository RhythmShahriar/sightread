// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package large

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/RhythmShahriar/sightread/testbed/fsnap"
)

func TestGenerateSmallSpec(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "p01")
	spec := Spec{Files: 100, FileBytes: 2048, Changed: 10, Added: 3}
	if err := Generate(dir, spec); err != nil {
		t.Fatal(err)
	}
	old, err := fsnap.Take(filepath.Join(dir, "old"))
	if err != nil {
		t.Fatal(err)
	}
	newer, err := fsnap.Take(filepath.Join(dir, "new"))
	if err != nil {
		t.Fatal(err)
	}
	var added, changed int
	for _, c := range fsnap.Diff(old, newer) {
		if filepath.Ext(c.Path) != ".php" {
			continue
		}
		switch c.What {
		case "added":
			added++
		case "changed":
			changed++
		case "removed":
			t.Errorf("the new version removed %s", c.Path)
		}
	}
	// The main file changes its Version header too.
	if added != spec.Added || changed != spec.Changed+1 {
		t.Errorf("added %d changed %d, want %d and %d", added, changed, spec.Added, spec.Changed+1)
	}
	var files int
	var size int64
	for _, e := range old {
		if e.Kind == "file" {
			files++
			size += e.Size
		}
	}
	if files != spec.Files+1 || size < int64(spec.Files*spec.FileBytes) {
		t.Errorf("old has %d files of %d bytes, want %d files of at least %d", files, size, spec.Files+1, spec.Files*spec.FileBytes)
	}

	// A second call with the same spec keeps the tree.
	if err := os.WriteFile(filepath.Join(dir, "old", "touch"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Generate(dir, spec); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "old", "touch")); err != nil {
		t.Error("the same spec rebuilt the tree")
	}
	// A different spec rebuilds it.
	if err := Generate(dir, Spec{Files: 50, FileBytes: 1024}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "old", "touch")); err == nil {
		t.Error("a new spec kept the old tree")
	}
}

func TestFileIsDeterministic(t *testing.T) {
	a, b := File(7, 4096, false), File(7, 4096, false)
	if !bytes.Equal(a, b) {
		t.Fatal("File is not deterministic")
	}
	if bytes.Equal(a, File(8, 4096, false)) {
		t.Error("two files are identical")
	}
	if e := File(7, 4096, true); !bytes.HasPrefix(e, a) || len(e) <= len(a) {
		t.Error("an edited file does not extend the old one")
	}
	if len(a) < 4096 || len(a) > 4096+400 {
		t.Errorf("size %d, want about 4096", len(a))
	}
}

func TestDefaultIsPRDSized(t *testing.T) {
	total := Default.Files * Default.FileBytes
	if Default.Files < 4000 || total < 40<<20-1<<20 {
		t.Errorf("Default is %d files, %d bytes; PRD 17 wants thousands of files and tens of MB", Default.Files, total)
	}
}
