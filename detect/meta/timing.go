// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package meta

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/RhythmShahriar/sightread/core"
)

// The signals of the release timing detector.
const (
	SigFreshRelease   = "fresh-release"
	SigDormantRelease = "dormant-release"
)

// defaultMinAge is --min-age when neither the flag nor min_age is set
// (PRD 7): most malicious releases are pulled within three days.
const defaultMinAge = 72 * time.Hour

// dormantAfter is the silence after which a release is dormant-release.
const dormantAfter = 365 * 24 * time.Hour

func init() { core.RegisterDetector(timingDetector{}) }

// timingDetector reports a candidate published very recently or one
// that ends a year or more of silence (PRD 12.1).
type timingDetector struct{}

func (timingDetector) Info() core.DetectorInfo {
	return core.DetectorInfo{Name: "meta-timing", Signals: []string{SigFreshRelease, SigDormantRelease}}
}

func (timingDetector) Detect(_ context.Context, s *core.Subject, emit func(core.Finding)) {
	out := newEmitter(s, emit)
	if s.New == nil || s.New.Published.IsZero() {
		return
	}
	if f, ok := freshFinding(s); ok {
		out.send(f)
	}
	if f, ok := dormantFinding(s); ok {
		out.send(f)
	}
}

// ParseMinAge reads a min_age or --min-age value: a Go duration such as
// 72h or 90m, or a whole number of days or weeks (7d, 2w). Empty is the
// default, 72h.
func ParseMinAge(v string) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return defaultMinAge, true
	}
	for suffix, unit := range map[string]time.Duration{"d": 24 * time.Hour, "w": 7 * 24 * time.Hour} {
		if n, ok := strings.CutSuffix(v, suffix); ok {
			i, err := strconv.Atoi(n)
			if err != nil || i < 0 {
				return 0, false
			}
			return time.Duration(i) * unit, true
		}
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		return 0, false
	}
	return d, true
}

// minAge is the quarantine the config sets and its text, the default
// when the value is missing or can't be read (policy refuses a bad one
// before any detector runs).
func minAge(cfg *core.Config) (time.Duration, string) {
	if cfg != nil {
		if d, ok := ParseMinAge(cfg.MinAge); ok && strings.TrimSpace(cfg.MinAge) != "" {
			return d, strings.TrimSpace(cfg.MinAge)
		}
	}
	return defaultMinAge, "72h"
}

// freshFinding fires when the candidate is younger than the minimum age:
// "published 5 hours ago (2026-10-26 07:00 UTC); the minimum age is 72h".
func freshFinding(s *core.Subject) (core.Finding, bool) {
	if s.Now.IsZero() {
		return core.Finding{}, false
	}
	limit, text := minAge(s.Config)
	age := s.Now.Sub(s.New.Published)
	if age >= limit {
		return core.Finding{}, false
	}
	when := "published " + ago(max(age, 0))
	if age < 0 {
		when = "published with a date in the future"
	}
	return newFinding(SigFreshRelease, when+" ("+s.New.Published.UTC().Format("2006-01-02 15:04")+" UTC); the minimum age is "+text), true
}

// previousRelease is the newest known release published before the
// candidate: from History, or the installed version when History is
// empty.
func previousRelease(s *core.Subject) (core.Release, bool) {
	var best core.Release
	found := false
	for _, r := range s.New.History {
		if r.Published.IsZero() || !r.Published.Before(s.New.Published) || r.Version == s.New.Ref.Version {
			continue
		}
		if !found || r.Published.After(best.Published) {
			best, found = r, true
		}
	}
	if !found && len(s.New.History) == 0 && s.Old != nil && !s.Old.Published.IsZero() && s.Old.Published.Before(s.New.Published) {
		best, found = core.Release{Version: s.Old.Ref.Version, Published: s.Old.Published}, true
	}
	return best, found
}

// dormantFinding fires when the release before the candidate came more
// than a year earlier: "2.0.0 came 400 days after 1.0.0 (2025-09-21),
// the release before it".
func dormantFinding(s *core.Subject) (core.Finding, bool) {
	prev, ok := previousRelease(s)
	if !ok {
		return core.Finding{}, false
	}
	gap := s.New.Published.Sub(prev.Published)
	if gap <= dormantAfter {
		return core.Finding{}, false
	}
	days := int(gap / (24 * time.Hour))
	return newFinding(SigDormantRelease, s.New.Ref.Version+" came "+plural(days, "day", "days")+" after "+
		prev.Version+" ("+prev.Published.UTC().Format("2006-01-02")+"), the release before it"), true
}
