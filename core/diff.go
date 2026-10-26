// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import "context"

// ChangeKind is how a file changed between two trees.
type ChangeKind uint8

// The change kinds.
const (
	Added ChangeKind = iota + 1
	Removed
	Modified
	Renamed
	ModeChanged
)

// String returns the lower-case name of k.
func (k ChangeKind) String() string {
	switch k {
	case Added:
		return "added"
	case Removed:
		return "removed"
	case Modified:
		return "modified"
	case Renamed:
		return "renamed"
	case ModeChanged:
		return "mode-changed"
	}
	return "unknown"
}

// FileChange is one changed file. Old is nil for an added file and New
// for a removed one.
type FileChange struct {
	Kind       ChangeKind
	Old, New   *File
	Similarity float32 // for Renamed
	EOLOnly    bool    // only line endings changed; stays quiet
}

// DiffStats are the numbers of the Diff line.
type DiffStats struct {
	FilesChanged, FilesAdded, FilesRemoved int
	LinesAdded, LinesRemoved               int
	BytesFrom, BytesTo                     int64
}

// Hunk is one unified-diff hunk. Lines start with "+", "-" or " " and
// are raw package text: writers sanitise them.
type Hunk struct {
	Path               string
	OldStart, OldLines int
	NewStart, NewLines int
	Lines              []string
}

// Diff is the file-level comparison of two trees.
type Diff struct {
	Old, New *Tree
	Changes  []FileChange
	Stats    DiffStats
}

// Differ compares trees (package diff).
type Differ interface {
	Diff(ctx context.Context, old, new *Tree) (*Diff, error)
	// Hunks returns the hunks of one changed path with context lines.
	Hunks(ctx context.Context, d *Diff, path string, contextLines int) ([]Hunk, error)
	// Drift compares an installed copy with the official tree of the
	// same version. It is the one implementation LocalVerifier uses.
	Drift(ctx context.Context, local, official *Tree) Drift
}
