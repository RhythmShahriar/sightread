// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// TestPruneIndexes: an index older than the age goes and its blobs are
// no longer referenced; a fresh one stays and names its blobs; a file
// that isn't an index is left alone.
func TestPruneIndexes(t *testing.T) {
	cache := t.TempDir()
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	oldTree := coretest.Tree(map[string]string{"old.php": "<?php // old\n"})
	newTree := coretest.Tree(map[string]string{"new.php": "<?php // new\n"})
	oldRef := core.Ref{Eco: core.WPPlugin, Name: "a", Version: "1.0.0"}
	newRef := core.Ref{Eco: core.WPPlugin, Name: "a", Version: "1.1.0"}
	in := core.Integrity{By: core.ByChecksums}
	if err := saveIndex(cache, oldRef, oldTree, in, now.Add(-40*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := saveIndex(cache, newRef, newTree, in, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	stray := filepath.Join(cache, "archives", "notes.json")
	if err := os.WriteFile(stray, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	removed, refs, err := PruneIndexes(cache, 30*24*time.Hour, now)
	if err != nil || removed != 1 {
		t.Fatalf("removed %d (%v)", removed, err)
	}
	if !refs[newTree.Files[0].SHA256] || refs[oldTree.Files[0].SHA256] || len(refs) != 1 {
		t.Errorf("referenced %v", refs)
	}
	if _, err := os.Stat(indexPath(cache, oldRef)); !os.IsNotExist(err) {
		t.Errorf("the old index is still there (%v)", err)
	}
	if _, err := os.Stat(stray); err != nil {
		t.Errorf("a file that isn't an index was removed: %v", err)
	}
	if removed, refs, err := PruneIndexes(t.TempDir(), time.Hour, now); err != nil || removed != 0 || len(refs) != 0 {
		t.Errorf("empty cache: %d %v %v", removed, refs, err)
	}
	blobs := coretest.MemBlobs()
	if _, ok := CachedTree(cache, newRef, blobs); ok {
		t.Errorf("a tree whose blobs are gone came back from the cache")
	}
}
