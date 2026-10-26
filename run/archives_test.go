// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/blob"
	"github.com/RhythmShahriar/sightread/core"
)

// TestLoadIndexTamperedBlob (e06): a cached blob changed on disk makes
// the index unusable, so the run fetches the archive again instead of
// failing on the read; the bad blob is gone. An untouched cache is
// reused.
func TestLoadIndexTamperedBlob(t *testing.T) {
	cache := t.TempDir()
	store, err := blob.OpenDisk(filepath.Join(cache, "blobs"))
	if err != nil {
		t.Fatal(err)
	}
	sum, n, err := store.Put(context.Background(), bytes.NewReader([]byte("<?php echo 1;\n")), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	tree := &core.Tree{Root: "p/", HashKind: core.HashManifest, Files: []core.File{{Path: "p.php", Size: n, Mode: 0o644, SHA256: sum}}}
	tree.SHA256 = core.ManifestHash(tree.Files)
	ref := core.Ref{Eco: core.WPPlugin, Name: "p", Version: "1.0.0"}
	in := core.Integrity{By: core.ByChecksums, Method: "checksums"}
	if err := saveIndex(cache, ref, tree, in, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := loadIndex(cache, ref, store); !ok {
		t.Fatal("a sound cache was not reused")
	}
	p, _ := store.Path(sum)
	_ = os.Chmod(p, 0o600)
	if err := os.WriteFile(p, []byte("<?php echo 2;\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := loadIndex(cache, ref, store); ok {
		t.Fatal("a tampered blob was reused")
	}
	if store.Has(sum) {
		t.Error("the tampered blob is still in the store")
	}
}
