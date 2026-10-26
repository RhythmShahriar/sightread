// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build unix

package inventory

import (
	"context"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// A FIFO in an installed folder is an issue and never opened.
func TestLocalTreeFIFO(t *testing.T) {
	dir := copyTree(t, "testdata/local/sample")
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe.php"), 0o644); err != nil {
		t.Skip("no FIFOs here:", err)
	}
	done := make(chan *core.Tree, 1)
	go func() {
		tree, err := LocalTree(context.Background(), dir, coretest.MemBlobs(), core.DefaultLimits())
		if err != nil {
			t.Error(err)
		}
		done <- tree
	}()
	select {
	case tree := <-done:
		if tree == nil || len(tree.Issues) != 1 || tree.Issues[0].Detail != "it is a FIFO, not a regular file; not read" {
			t.Errorf("tree = %+v", tree)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("LocalTree blocked on a FIFO")
	}
}
