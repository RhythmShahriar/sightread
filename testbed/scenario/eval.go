// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package scenario

import "sort"

// Status is the outcome category of a scenario, the scoreboard's rows.
type Status string

// The statuses.
const (
	// StatusCaught: a bad scenario reported every expected signal at or
	// above its rank, with nothing forbidden.
	StatusCaught Status = "caught"
	// StatusFoundOther: a bad scenario was flagged but not with the
	// expected signal set.
	StatusFoundOther Status = "found-as-something-else"
	// StatusMissed: a bad scenario came back clean.
	StatusMissed Status = "missed"
	// StatusClean: a good scenario reported no finding at or above its
	// gate (beyond the ones it is allowed).
	StatusClean Status = "clean"
	// StatusFalseAlarm: a good scenario reported a finding at or above its
	// gate that it is not allowed.
	StatusFalseAlarm Status = "false-alarm"
	// StatusPending: a scenario whose detector or stage is not merged yet.
	StatusPending Status = "pending"
)

// Outcome is the result of evaluating one scenario against a review.
type Outcome struct {
	Scenario    Scenario
	Status      Status
	Present     []string // expected signals that were found
	Missing     []string // expected signals that were not found at rank
	FalseAlarms []string // good: counted findings at or above the gate
	Forbidden   []string // forbidden signals that appeared
	VerdictOK   bool
	GotVerdict  string
}

// severityRank orders the five severities; an unknown value sorts below
// info so a typo never silently satisfies a minimum.
func severityRank(s string) int {
	switch s {
	case "info":
		return 0
	case "low":
		return 1
	case "medium":
		return 2
	case "high":
		return 3
	case "critical":
		return 4
	}
	return -1
}

// Evaluate judges a review against a scenario. A pending scenario is
// reported as pending without being scored.
func Evaluate(s Scenario, r *Report) Outcome {
	o := Outcome{Scenario: s, GotVerdict: r.OverallVerdict()}
	o.VerdictOK = s.Expect.Verdict == "" || s.Expect.Verdict == o.GotVerdict

	// Highest severity seen per counted signal id.
	best := map[string]int{}
	for _, f := range r.CountedFindings() {
		if rank := severityRank(f.Severity); rank > best[f.ID] || !inMap(best, f.ID) {
			best[f.ID] = rank
		}
	}

	for _, id := range s.Forbid {
		if _, ok := best[id]; ok {
			o.Forbidden = append(o.Forbidden, id)
		}
	}

	if s.Pending != "" {
		o.Status = StatusPending
		return o
	}

	switch s.Kind {
	case KindGood:
		allowed := map[string]bool{}
		for _, e := range s.Expect.Signals {
			allowed[e.ID] = true
		}
		gate := severityRank(s.EffectiveFailOn())
		for id, rank := range best {
			if !allowed[id] && gate >= 0 && rank >= gate {
				o.FalseAlarms = append(o.FalseAlarms, id)
			}
		}
		sort.Strings(o.FalseAlarms)
		if len(o.FalseAlarms) == 0 && len(o.Forbidden) == 0 {
			o.Status = StatusClean
		} else {
			o.Status = StatusFalseAlarm
		}
	default: // bad
		for _, e := range s.Expect.Signals {
			min := severityRank(e.MinSeverity)
			if min < 0 {
				min = 0
			}
			if rank, ok := best[e.ID]; ok && rank >= min {
				o.Present = append(o.Present, e.ID)
			} else {
				o.Missing = append(o.Missing, e.ID)
			}
		}
		sort.Strings(o.Present)
		sort.Strings(o.Missing)
		switch {
		case len(o.Missing) == 0 && len(o.Forbidden) == 0:
			o.Status = StatusCaught
		case len(best) > 0 || r.OverallVerdict() != "ROUTINE":
			o.Status = StatusFoundOther
		default:
			o.Status = StatusMissed
		}
	}
	return o
}

// inMap reports whether k is a key of m.
func inMap(m map[string]int, k string) bool {
	_, ok := m[k]
	return ok
}

// NotCheckedOK reports whether the review lists every reason the
// scenario expects under Not checked.
func (r *Report) NotCheckedOK(reasons []string) bool {
	have := map[string]bool{}
	for _, nc := range r.Data.NotChecked {
		have[nc.Reason] = true
	}
	for _, want := range reasons {
		if !have[want] {
			return false
		}
	}
	return true
}
