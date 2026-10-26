// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/archive"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// zipManifest zips the folder the way a release would and returns the
// manifest hash of the zip's entries, computed apart from LocalTree.
func zipManifest(t *testing.T, dir string) [32]byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		w, err := zw.Create("sample/" + filepath.ToSlash(rel))
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		_, err = w.Write(b)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var files []core.File
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(rc)
		_ = rc.Close()
		files = append(files, core.File{Path: strings.TrimPrefix(f.Name, "sample/"), SHA256: sha256.Sum256(b)})
	}
	return core.ManifestHash(files)
}

func TestLocalTreeMatchesZip(t *testing.T) {
	dir := copyTree(t, "testdata/local/sample")
	blobs := coretest.MemBlobs()
	tree, err := LocalTree(context.Background(), dir, blobs, core.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if tree.HashKind != core.HashManifest || tree.SHA256 != zipManifest(t, dir) {
		t.Errorf("tree hash %x (%s) differs from the zip's manifest hash", tree.SHA256[:4], tree.HashKind)
	}
	if len(tree.Issues) != 0 {
		t.Errorf("issues = %+v", tree.Issues)
	}
	want := map[string]core.FileKind{
		"assets/js/app.js": core.KindJS, "composer.json": core.KindJSON, "includes/loader.php": core.KindPHP,
		"readme.txt": core.KindText, "sample.php": core.KindPHP,
	}
	if len(tree.Files) != len(want) {
		t.Fatalf("files = %+v", tree.Files)
	}
	var total int64
	for i, f := range tree.Files {
		if i > 0 && tree.Files[i-1].Path >= f.Path {
			t.Errorf("files not sorted at %s", f.Path)
		}
		if want[f.Path] != f.Kind {
			t.Errorf("%s kind = %s, want %s", f.Path, f.Kind, want[f.Path])
		}
		if !f.Mode.IsRegular() || !blobs.Has(f.SHA256) {
			t.Errorf("%s: mode %v, stored %v", f.Path, f.Mode, blobs.Has(f.SHA256))
		}
		total += f.Size
	}
	if tree.Bytes != total || tree.Root != filepath.Base(dir)+"/" || tree.Blobs != blobs {
		t.Errorf("tree = bytes %d (files %d), root %q", tree.Bytes, total, tree.Root)
	}
	if got := coretest.Read(tree, "includes/loader.php"); got != "<?php\nfunction sample_load() {}\n" {
		t.Errorf("loader.php = %q", got)
	}
	// Negative: one changed byte changes the hash.
	writeFiles(t, dir, map[string]string{"readme.txt": "=== Sample ===\nStable tag: 1.0.1\n"})
	tree2, err := LocalTree(context.Background(), dir, blobs, core.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if tree2.SHA256 == tree.SHA256 {
		t.Error("a changed file kept the same manifest hash")
	}
}

func TestLocalTreeLinkNotFollowed(t *testing.T) {
	dir := copyTree(t, "testdata/local/sample")
	outside := t.TempDir()
	writeFiles(t, outside, map[string]string{"secret.php": "<?php // outside the package"})
	if err := os.Symlink(outside, filepath.Join(dir, "linked-dir")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("creating links needs a privilege on Windows:", err)
		}
		t.Fatal(err)
	}
	if err := os.Symlink("sample.php", filepath.Join(dir, "alias.php")); err != nil {
		t.Fatal(err)
	}
	tree, err := LocalTree(context.Background(), dir, coretest.MemBlobs(), core.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range tree.Files {
		if strings.Contains(f.Path, "secret") {
			t.Errorf("followed a link into %s", f.Path)
		}
	}
	for p, target := range map[string]string{"linked-dir": outside, "alias.php": "sample.php"} {
		f, ok := tree.Lookup(p)
		if !ok || f.Mode&fs.ModeSymlink == 0 || f.Link != target || coretest.Read(tree, p) != target {
			t.Errorf("%s = %+v, want a link to %q", p, f, target)
		}
	}
}

func TestLocalTreeLimits(t *testing.T) {
	dir := copyTree(t, "testdata/local/sample")
	writeFiles(t, dir, map[string]string{"big.bin": strings.Repeat("x", 100)})
	lim := core.DefaultLimits()
	lim.EntryStored = 99
	tree, err := LocalTree(context.Background(), dir, coretest.MemBlobs(), lim)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := tree.Lookup("big.bin"); ok || len(tree.Issues) != 1 || tree.Issues[0].Kind != core.IssueLimit || tree.Issues[0].Path != "big.bin" {
		t.Errorf("over EntryStored: issues %+v", tree.Issues)
	}
	if len(tree.Files) != 5 {
		t.Errorf("files = %d, want the 5 others", len(tree.Files))
	}

	lim = core.DefaultLimits()
	lim.Entries = 2
	tree, err = LocalTree(context.Background(), dir, coretest.MemBlobs(), lim)
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Files) != 2 || len(tree.Issues) != 1 || tree.Issues[0].Kind != core.IssueLimit {
		t.Errorf("over Entries: %d files, issues %+v", len(tree.Files), tree.Issues)
	}

	lim = core.DefaultLimits()
	lim.Uncompressed = 150
	tree, err = LocalTree(context.Background(), dir, coretest.MemBlobs(), lim)
	if err != nil {
		t.Fatal(err)
	}
	if tree.Bytes > 150 || len(tree.Issues) != 1 || tree.Issues[0].Kind != core.IssueLimit {
		t.Errorf("over Uncompressed: %d bytes, issues %+v", tree.Bytes, tree.Issues)
	}
}

func TestLocalTreeUnreadable(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("file modes don't stop this user from reading")
	}
	dir := copyTree(t, "testdata/local/sample")
	if err := os.Chmod(filepath.Join(dir, "readme.txt"), 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "includes"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dir, "includes"), 0o755) })
	tree, err := LocalTree(context.Background(), dir, coretest.MemBlobs(), core.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, is := range tree.Issues {
		got[is.Path] = is.Detail
	}
	if got["readme.txt"] != "couldn't read: permission denied" || got["includes"] != "couldn't read the folder: permission denied" {
		t.Errorf("issues = %+v", tree.Issues)
	}
	if len(tree.Files) != 3 {
		t.Errorf("files = %+v, want the 3 readable ones", tree.Files)
	}
}

// Negative: not a folder, a missing folder and a canceled context are
// errors, not trees.
func TestLocalTreeErrors(t *testing.T) {
	dir := copyTree(t, "testdata/local/sample")
	for _, p := range []string{filepath.Join(dir, "sample.php"), filepath.Join(dir, "missing")} {
		if _, err := LocalTree(context.Background(), p, coretest.MemBlobs(), core.DefaultLimits()); err == nil {
			t.Errorf("LocalTree(%s) gave no error", p)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := LocalTree(ctx, dir, coretest.MemBlobs(), core.DefaultLimits()); err == nil {
		t.Error("a canceled context gave no error")
	}
}

func TestLocalPathProblem(t *testing.T) {
	for _, p := range []string{"a.php", "dir/b c.js", "ünï/cödé.php", strings.Repeat("a", 1024)} {
		if bad := localPathProblem(p); bad != "" {
			t.Errorf("%q: %s", p, bad)
		}
	}
	for _, p := range []string{"a\x1b.php", "b\n.php", "c\x7f", strings.Repeat("a", 1025)} {
		if localPathProblem(p) == "" {
			t.Errorf("%q accepted", p)
		}
	}
}

func TestFileKindOf(t *testing.T) {
	long := []byte(strings.Repeat("a", 1200))
	for _, c := range []struct {
		p    string
		head []byte
		want core.FileKind
	}{
		{"a.php", nil, core.KindPHP}, {"B.PHP", nil, core.KindPHP}, {"a.js", []byte("x\n"), core.KindJS},
		{"a.min.js", nil, core.KindMinified}, {"bundle.js", long, core.KindMinified}, {"a.json", nil, core.KindJSON},
		{"i.png", nil, core.KindAsset}, {"f.woff2", nil, core.KindAsset}, {"x.zip", nil, core.KindArchive},
		{"blob", []byte("a\x00b"), core.KindBinary}, {"readme.txt", []byte("hello"), core.KindText}, {"LICENSE", nil, core.KindText},
		// The archive rule: every PHP extension, and a file of an unknown
		// type is binary (checked for hidden code) even when it reads as
		// text.
		{"a.php8", nil, core.KindPHP}, {"a.phps", nil, core.KindPHP}, {"shell.module", []byte("<?php system($x);"), core.KindBinary},
	} {
		if got := FileKindOf(c.p, c.head); got != c.want {
			t.Errorf("FileKindOf(%q) = %s, want %s", c.p, got, c.want)
		}
		// An installed copy and the archive entry of the same name agree
		// unless the head shows a minified script.
		if got, arc := FileKindOf(c.p, c.head), archive.KindOf(c.p); got != arc && got != core.KindMinified {
			t.Errorf("%q: installed %s, archive %s", c.p, got, arc)
		}
	}
}
