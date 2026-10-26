// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package watch

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/RhythmShahriar/sightread/run"
)

// StateName is the file in the watch folder that records what earlier
// runs counted.
const StateName = "state.json"

// stateSchema names the state file format.
const stateSchema = "sightread-watch/v1"

// forget is how long a counted finding stays in the state after the last
// run that saw it. A version no site is offered any more drops out, so
// the file doesn't grow for ever.
const forget = 90 * 24 * time.Hour

// maxState bounds the state file read back.
const maxState = 32 << 20

// state is state.json.
type state struct {
	Schema   string    `json:"schema"`
	Report   string    `json:"report,omitempty"` // the last report's file name
	Finished time.Time `json:"finished"`
	// SignalPack is the sightread-signals version of the last run; a run
	// with a newer one re-reviews the installed versions.
	SignalPack string `json:"signal_pack,omitempty"`
	// Seen maps the key of every counted finding (site, package, version,
	// sha256 and signal ID) to the last run that saw it: a finding is
	// notified once, whether it came with an update or a rereview.
	Seen map[string]time.Time `json:"seen"`
	// InstalledChecked is when owners and closures were last asked; they
	// are asked again after InstalledEvery.
	InstalledChecked time.Time `json:"installed_checked"`
	// Owners maps site and package to who could publish it last time.
	Owners map[string][]string `json:"owners"`
	// Closed holds the site, package and version of every closure that
	// was notified.
	Closed map[string]bool `json:"closed"`
}

func newState() *state {
	return &state{Schema: stateSchema, Seen: map[string]time.Time{}, Owners: map[string][]string{}, Closed: map[string]bool{}}
}

// errCorrupt marks a state file that exists but can't be read.
var errCorrupt = errors.New("state file is not a watch state")

// loadState reads the state file. A missing file is a fresh state; an
// unreadable one is errCorrupt with a fresh state, so a damaged file
// costs some repeated notifications, never the watch.
func loadState(dir string) (*state, error) {
	st := newState()
	f, err := os.Open(filepath.Join(dir, StateName)) //nolint:gosec // the watch's own folder
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return st, err
	}
	defer func() { _ = f.Close() }()
	var got state
	if err := json.NewDecoder(io.LimitReader(f, maxState)).Decode(&got); err != nil || got.Schema != stateSchema {
		return st, errCorrupt
	}
	if got.Seen == nil {
		got.Seen = map[string]time.Time{}
	}
	if got.Owners == nil {
		got.Owners = map[string][]string{}
	}
	if got.Closed == nil {
		got.Closed = map[string]bool{}
	}
	return &got, nil
}

// save writes the state through a temp file and a rename, dropping
// findings no run has seen for a while.
func (st *state) save(dir string, now time.Time) error {
	for k, t := range st.Seen {
		if now.Sub(t) > forget {
			delete(st.Seen, k)
		}
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := run.WriteFile(filepath.Join(dir, StateName), append(b, '\n')); err != nil {
		return fmt.Errorf("%s: %w", StateName, err)
	}
	return nil
}

// setAside renames a corrupt state file so the next run starts clean and
// the bad file is still there to look at.
func setAside(dir string) {
	p := filepath.Join(dir, StateName)
	_ = os.Rename(p, p+".bad")
}
