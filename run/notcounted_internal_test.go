// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run

import (
	"testing"

	"github.com/RhythmShahriar/sightread/core"
)

// TestNotCountedNote: the note says how many findings were set aside and
// why. It warns when one is critical or high.
func TestNotCountedNote(t *testing.T) {
	for _, c := range []struct {
		s    core.Summary
		want string
	}{
		{core.Summary{}, ""},
		{core.Summary{Baselined: 7, NotCountedSevere: 5},
			"7 findings were not counted (7 in the --baseline report); 5 of them critical or high, so check them before you update"},
		{core.Summary{Ignored: 1, NotCountedSevere: 1}, "1 finding was not counted (1 ignored by config); it is critical or high, so check it before you update"},
		{core.Summary{Baselined: 1, Ignored: 2},
			"3 findings were not counted (1 in the --baseline report and 2 ignored by config); the verdicts leave them out"},
	} {
		if got := notCountedNote(c.s); got != c.want {
			t.Errorf("%+v:\n got %q\nwant %q", c.s, got, c.want)
		}
	}
}
