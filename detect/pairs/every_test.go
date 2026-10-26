// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package pairs_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
	"github.com/RhythmShahriar/sightread/detect/pairs"

	// The detectors, their explain text and data packs, plus the real
	// analyzer and differ once those lanes land.
	_ "github.com/RhythmShahriar/sightread/analyze"
	_ "github.com/RhythmShahriar/sightread/data"
	_ "github.com/RhythmShahriar/sightread/detect"
	_ "github.com/RhythmShahriar/sightread/detect/code"
	_ "github.com/RhythmShahriar/sightread/detect/meta"
	_ "github.com/RhythmShahriar/sightread/diff"
)

var root = filepath.Join("testdata", "pairs")

func load(t *testing.T) []*pairs.Case {
	t.Helper()
	cases, err := pairs.Load(root)
	if err != nil {
		t.Fatal(err)
	}
	return cases
}

// TestEverySignalHasFixtures holds every signal a detector emits to at
// least 3 positive and 3 negative cases with one lookalike. A catalogue
// signal no detector emits yet is logged; it fails once the build is
// meant to be whole (SIGHTREAD_REQUIRE_LINKED=1).
func TestEverySignalHasFixtures(t *testing.T) {
	cases := load(t)
	emitted := pairs.Emitted()
	for id := range emitted {
		if s, ok := core.Signal(id); !ok || s.Emitter != core.EmitDetect {
			t.Errorf("a detector declares %q, which is not a detect signal of the catalogue", id)
		}
	}
	var built, missing []string
	for _, id := range pairs.DetectSignals() {
		if emitted[id] {
			built = append(built, id)
		} else {
			missing = append(missing, id)
		}
	}
	for _, s := range pairs.Shortfalls(built, pairs.Counts(cases)) {
		t.Error(s)
	}
	for _, c := range cases {
		if s, _ := core.Signal(c.Signal); s.Emitter != core.EmitDetect {
			t.Errorf("%s: %s is emitted by %s, not by a detector", c, c.Signal, s.Emitter)
		}
	}
	if len(missing) > 0 {
		msg := "no detector emits " + strings.Join(missing, ", ")
		if pairs.RequireLinked() {
			t.Errorf("%s (%s=1)", msg, coretest.RequireLinkedEnv)
		} else {
			t.Log(msg)
		}
	}
}

// TestPairs runs every case against the registered detectors.
func TestPairs(t *testing.T) {
	for _, c := range load(t) {
		t.Run(c.String(), func(t *testing.T) { pairs.Run(t, c) })
	}
}
