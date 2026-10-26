// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run

import (
	"encoding/hex"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// TestSideHash: a manifest hash of no files, or of a tree an archive
// limit cut short, is left out; an archive hash of the bytes stays.
func TestSideHash(t *testing.T) {
	full := coretest.Tree(map[string]string{"a.php": "<?php\n"})
	full.HashKind = core.HashManifest
	if got := sideHash(full); got != hex.EncodeToString(full.SHA256[:]) || got == "" {
		t.Errorf("complete tree %q", got)
	}
	empty := &core.Tree{HashKind: core.HashManifest, SHA256: core.ManifestHash(nil)}
	if got := sideHash(empty); got != "" {
		t.Errorf("empty manifest %q", got)
	}
	cut := coretest.Tree(map[string]string{"a.php": "<?php\n"})
	cut.HashKind = core.HashManifest
	cut.Issues = []core.ArchiveIssue{{Kind: core.IssueLimit, Detail: "too many files"}}
	if got := sideHash(cut); got != "" {
		t.Errorf("limited manifest %q", got)
	}
	cut.HashKind = core.HashArchive
	if got := sideHash(cut); got != hex.EncodeToString(cut.SHA256[:]) {
		t.Errorf("archive hash dropped: %q", got)
	}
}
