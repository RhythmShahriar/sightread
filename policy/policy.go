// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package policy

import (
	"io"
	"os"
	"time"
)

// Store loads and edits the Sightread files of a project.
type Store struct {
	// Stderr gets the warning lines, such as an expired ignore entry.
	Stderr io.Writer
	// Now is the clock that expires ignore and allow entries.
	Now func() time.Time
}

// New returns a Store that warns on os.Stderr and uses the real clock.
func New() *Store { return &Store{Stderr: os.Stderr, Now: time.Now} }

func (s *Store) now() time.Time {
	if s.Now == nil {
		return time.Now()
	}
	return s.Now()
}

func (s *Store) stderr() io.Writer {
	if s.Stderr == nil {
		return io.Discard
	}
	return s.Stderr
}
