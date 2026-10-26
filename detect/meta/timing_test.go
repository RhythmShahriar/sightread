// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package meta

import (
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/core"
)

func TestParseMinAge(t *testing.T) {
	for in, want := range map[string]time.Duration{
		"": 72 * time.Hour, "72h": 72 * time.Hour, "7d": 7 * 24 * time.Hour, "2w": 14 * 24 * time.Hour,
		"90m": 90 * time.Minute, " 3d ": 3 * 24 * time.Hour, "0d": 0,
	} {
		if got, ok := ParseMinAge(in); !ok || got != want {
			t.Errorf("ParseMinAge(%q) = %v %v, want %v", in, got, ok, want)
		}
	}
	for _, bad := range []string{"3 days", "-1d", "d", "1.5d", "-5h", "soon"} {
		if _, ok := ParseMinAge(bad); ok {
			t.Errorf("ParseMinAge(%q) accepted it", bad)
		}
	}
}

func TestFreshWording(t *testing.T) {
	s := subject(core.NPM)
	s.Now = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	s.New.Published = time.Date(2026, 10, 26, 7, 0, 0, 0, time.UTC)
	f := only(t, run(t, timingDetector{}, s), SigFreshRelease)
	if want := "published 5 hours ago (2026-10-26 07:00 UTC); the minimum age is 72h"; f.Evidence.String() != want {
		t.Errorf("evidence = %q, want %q", f.Evidence, want)
	}
	s.Config.MinAge = "7d"
	s.New.Published = s.Now.Add(-50 * time.Hour)
	f = only(t, run(t, timingDetector{}, s), SigFreshRelease)
	if want := "published 2 days ago (2026-10-24 10:00 UTC); the minimum age is 7d"; f.Evidence.String() != want {
		t.Errorf("evidence = %q, want %q", f.Evidence, want)
	}
	s.New.Published = s.Now.Add(time.Hour)
	f = only(t, run(t, timingDetector{}, s), SigFreshRelease)
	if want := "published with a date in the future (2026-10-26 13:00 UTC); the minimum age is 7d"; f.Evidence.String() != want {
		t.Errorf("evidence = %q, want %q", f.Evidence, want)
	}
}

func TestDormantWording(t *testing.T) {
	s := subject(core.NPM)
	s.New.Published = time.Date(2026, 10, 6, 0, 0, 0, 0, time.UTC)
	s.New.History = []core.Release{{Version: "1.0.0", Published: time.Date(2025, 9, 1, 0, 0, 0, 0, time.UTC)}}
	f := only(t, run(t, timingDetector{}, s), SigDormantRelease)
	if want := "2.0.0 came 400 days after 1.0.0 (2025-09-01), the release before it"; f.Evidence.String() != want {
		t.Errorf("evidence = %q, want %q", f.Evidence, want)
	}
	// Exactly a year is not dormant.
	s.New.History[0].Published = s.New.Published.Add(-365 * 24 * time.Hour)
	for _, f := range run(t, timingDetector{}, s) {
		if f.ID == SigDormantRelease {
			t.Errorf("365 days fired: %q", f.Evidence)
		}
	}
}
