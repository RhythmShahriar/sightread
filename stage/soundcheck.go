// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package stage

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"strings"
	"time"

	"github.com/RhythmShahriar/sightread/internal/proc"
)

// soundcheckTimeout bounds one rhythm-soundcheck run: a snapshot of a
// large site takes minutes, never hours.
const soundcheckTimeout = time.Hour

// comparison is the part of rhythm-soundcheck compare --json stage reads.
type comparison struct {
	Schema  string `json:"schema"`
	Kind    string `json:"kind"`
	Summary struct {
		Broke   int    `json:"broke"`
		New     int    `json:"new"`
		Changed int    `json:"changed"`
		Verdict string `json:"verdict"`
	} `json:"summary"`
	After struct {
		Dir string `json:"dir"`
	} `json:"after"`
	Interrupted bool `json:"interrupted"`
}

// unsafeSnapshot matches what a snapshot name can't hold: it becomes a
// folder under .soundcheck/snapshots.
var unsafeSnapshot = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// snapshotName is sightread-<name>-<from>, made folder-safe.
func snapshotName(name, from string) string {
	if from == "" {
		from = "new"
	}
	n := unsafeSnapshot.ReplaceAllString("sightread-"+strings.TrimPrefix(name, "@")+"-"+from, "-")
	return strings.Trim(n, "-.")
}

// snapshot records the staging site before the update (PRD 15 step 4).
func (s *stager) snapshot(ctx context.Context, name string) error {
	argv := append([]string{s.soundcheck, "snapshot", s.p.Staging, "--name", name}, s.p.Args...)
	res, err := proc.Run(ctx, proc.Spec{Argv: argv, Purpose: proc.PurposeSoundcheck, Timeout: soundcheckTimeout, Log: s.p.Log})
	if err != nil || res.Code != 0 {
		return s.ranBadly("rhythm-soundcheck snapshot", res.Code, res.Stderr, err)
	}
	return nil
}

// compare checks the staging site against the snapshot (step 6).
func (s *stager) compare(ctx context.Context, name string) (*comparison, error) {
	argv := []string{s.soundcheck, "compare", s.p.Staging, "--snapshot", name, "--json"}
	res, err := proc.Run(ctx, proc.Spec{Argv: argv, Purpose: proc.PurposeSoundcheck, Timeout: soundcheckTimeout, Log: s.p.Log})
	if err != nil {
		return nil, s.ranBadly("rhythm-soundcheck compare", -1, res.Stderr, err)
	}
	var c comparison
	jsonErr := json.Unmarshal(bytes.TrimSpace(res.Stdout), &c)
	// Exit 1 is Soundcheck's own gate on what it found; the comparison
	// is still complete.
	if res.Code > 1 || jsonErr != nil || c.Kind != "comparison" || c.Interrupted {
		return nil, s.ranBadly("rhythm-soundcheck compare", res.Code, res.Stderr, jsonErr)
	}
	return &c, nil
}

// trips reports whether the comparison has changes at the --soundcheck-
// fail-on class: broke counts BROKE, new adds NEW, changed adds CHANGED.
func (c *comparison) trips(class string) bool {
	switch class {
	case "changed":
		return c.Summary.Broke+c.Summary.New+c.Summary.Changed > 0
	case "new":
		return c.Summary.Broke+c.Summary.New > 0
	}
	return c.Summary.Broke > 0
}
