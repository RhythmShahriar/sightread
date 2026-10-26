// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package diff

import (
	"context"
	"crypto/sha256"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// archiveLink is a link as an archive records it: the target text and
// no blob.
func archiveLink(path, target string) core.File {
	return core.File{Path: path, Mode: fs.ModeSymlink | 0o777, Link: target, Kind: core.KindBinary}
}

// localLink is a link as an installed folder records it: the target
// text stored as its contents.
func localLink(t *testing.T, blobs core.BlobStore, path, target string) core.File {
	t.Helper()
	sum, n, err := blobs.Put(context.Background(), strings.NewReader(target), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return core.File{Path: path, Size: n, SHA256: sum, Mode: fs.ModeSymlink | 0o777, Link: target, Kind: core.KindText}
}

// tree is a tree of files over a fresh blob store.
func tree(blobs core.BlobStore, files ...core.File) *core.Tree {
	return &core.Tree{Files: files, Blobs: blobs}
}

// Negative: a link to the same target is unchanged whether an archive
// or an installed folder recorded it, in a diff and in drift.
func TestLinkSameTarget(t *testing.T) {
	blobs := coretest.MemBlobs()
	arc := tree(blobs, archiveLink("lib", "vendor/lib"))
	local := tree(blobs, localLink(t, blobs, "lib", "vendor/lib"))
	d, err := Differ{}.Diff(context.Background(), arc, local)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Changes) != 0 {
		t.Errorf("changes %q", summary(d))
	}
	if dr := (Differ{}).Drift(context.Background(), local, arc); len(dr.Differ) != 0 || len(dr.Matched) != 1 {
		t.Errorf("drift %+v", dr)
	}
}

// Positive: a link moved to another target is modified and its hunk
// shows both targets. Two archive links with different targets are
// never paired as a rename (both have the zero hash).
func TestLinkRetargeted(t *testing.T) {
	blobs := coretest.MemBlobs()
	old := tree(blobs, archiveLink("lib", "vendor/lib"), archiveLink("a", "x"))
	new := tree(blobs, localLink(t, blobs, "lib", "/etc/passwd"), archiveLink("b", "y"))
	d, err := Differ{}.Diff(context.Background(), old, new)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"removed a->", "added ->b", "modified lib->lib"}
	if got := summary(d); !reflect.DeepEqual(got, want) {
		t.Errorf("changes %q, want %q", got, want)
	}
	h, err := Differ{}.Hunks(context.Background(), d, "lib", 3)
	if err != nil {
		t.Fatal(err)
	}
	if joined := strings.Join(h[0].Lines, "\n"); !strings.Contains(joined, "vendor/lib") || !strings.Contains(joined, "/etc/passwd") {
		t.Errorf("hunk %q", h[0].Lines)
	}
	if identity(&old.Files[0]) != sha256.Sum256([]byte("vendor/lib")) {
		t.Error("an archive link's identity is not its target's hash")
	}
}
