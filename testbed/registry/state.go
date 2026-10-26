// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Scenario states. The state selects whether the candidate version is
// published: in StateBad the registry offers the candidate (the bad
// update for a bad scenario, the benign update for a good one); in
// StateGood only the installed version exists, so the update is "already
// the latest". Toggling writes the file and needs no restart.
const (
	StateGood = "good"
	StateBad  = "bad"
)

// state returns the state of scenario id. The default, with no file, is
// StateBad so a freshly started registry serves the full scenario.
func readState(stateDir, id string) string {
	b, err := os.ReadFile(filepath.Join(stateDir, id)) //nolint:gosec // our own state folder
	if err != nil {
		return StateBad
	}
	if strings.TrimSpace(string(b)) == StateGood {
		return StateGood
	}
	return StateBad
}

// WriteState sets the state of scenario id under stateDir.
func WriteState(stateDir, id, state string) error {
	if state != StateGood && state != StateBad {
		return fmt.Errorf("state %q: want %q or %q", state, StateGood, StateBad)
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil { //nolint:gosec // testbed state dir
		return err
	}
	return os.WriteFile(filepath.Join(stateDir, id), []byte(state+"\n"), 0o644) //nolint:gosec // not a secret
}
