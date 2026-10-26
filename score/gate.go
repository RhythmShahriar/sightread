// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package score

import (
	"fmt"
	"slices"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

// Summarise counts the report for its header (every count, zero
// included) and decides whether it is complete: not when an update is
// UNVERIFIED, a package or the run recorded an error, anything is Not
// checked for a reason that is not informational (core and mu-plugin
// are listed but never make a run partial) or the run stopped early. It also adds the Notes lines Score
// left for the report's updates. Severity counts are of counted
// findings only; allowed, ignored and baselined findings have their own
// counts and below-confidence ones are in none.
func (s *Scorer) Summarise(r *core.Report) {
	sum := core.Summary{Updates: len(r.Updates), NotChecked: core.CountNotChecked(r.NotChecked)}
	errs := len(r.Errors)
	for i := range r.Updates {
		u := &r.Updates[i]
		switch u.Verdict {
		case core.Hold:
			sum.Hold++
		case core.Review:
			sum.Review++
		case core.Routine:
			sum.Routine++
		case core.Allowed:
			sum.Allowed++
		case core.Unverified:
			sum.Unverified++
		}
		if u.FromCache {
			sum.FromCache++
		}
		errs += len(u.Errors)
		for _, f := range u.Findings {
			switch {
			case f.Allowed != nil:
				sum.AllowedFindings++
				continue
			case f.Ignored:
				sum.Ignored++
				continue
			case f.Baselined:
				sum.Baselined++
				continue
			case f.BelowConfidence:
				continue
			}
			if f.Demoted != "" {
				sum.Demoted++
			}
			switch f.Severity {
			case cli.SeverityCritical:
				sum.Critical++
			case cli.SeverityHigh:
				sum.High++
			case cli.SeverityMedium:
				sum.Medium++
			case cli.SeverityLow:
				sum.Low++
			case cli.SeverityInfo:
				sum.Info++
			}
		}
		for _, n := range s.takeNotes(u) {
			if !slices.Contains(r.Notes, n) {
				r.Notes = append(r.Notes, n)
			}
		}
	}
	r.Summary = sum
	r.Complete = sum.Unverified == 0 && sum.NotChecked == 0 && errs == 0 && r.StoppedBy == ""
}

// Gate returns the exit code of PRD section 10 and the reason the footer
// prints. Exit 1 when a counted finding is at or above o.FailOn, or at
// or above o.FailOnNew (a baseline has already set aside the findings
// that are not new). Else, with o.FailOn set, exit 3 when the run is
// partial: an UNVERIFIED update without o.AllowUnverified, or a package
// not checked (informational reasons aside), a fetch error or a stopped run without o.AllowPartial.
// Findings win over gaps, so a run with both exits 1. The reason is one
// or two lines: what happened, then how to accept it.
func (s *Scorer) Gate(r *core.Report, o core.GateOptions) (int, string) {
	var atFail, atNew int
	for _, u := range r.Updates {
		for _, f := range u.Findings {
			if !f.Counted() {
				continue
			}
			if o.FailOn.Fails(f.Severity) {
				atFail++
			}
			if o.FailOnNew.Fails(f.Severity) {
				atNew++
			}
		}
	}
	switch {
	case atFail > 0:
		return cli.ExitFindings, fmt.Sprintf("%s at or above --fail-on %s", plural(atFail, "finding", "findings"), o.FailOn)
	case atNew > 0:
		return cli.ExitFindings, fmt.Sprintf("%s at or above --fail-on-new %s", plural(atNew, "new finding", "new findings"), o.FailOnNew)
	case o.FailOn == cli.SeverityNone:
		return cli.ExitOK, ""
	}

	var what, flags []string
	unverified, notChecked, failed := 0, core.CountNotChecked(r.NotChecked), len(r.Errors)
	for _, u := range r.Updates {
		if u.Verdict == core.Unverified {
			unverified++
		}
		for _, e := range u.Errors {
			// An integrity error is the update's UNVERIFIED verdict or its
			// integrity-mismatch finding, not a fetch failure.
			if e.Code != core.EUnverifiable && e.Code != core.EIntegrityMismatch {
				failed++
			}
		}
	}
	if unverified > 0 && !o.AllowUnverified {
		what = append(what, plural(unverified, "update couldn't be verified", "updates couldn't be verified"))
		flags = append(flags, "--allow-unverified")
	}
	if !o.AllowPartial {
		partial := false
		if notChecked > 0 {
			what = append(what, plural(notChecked, "package wasn't checked", "packages weren't checked"))
			partial = true
		}
		if failed > 0 {
			what = append(what, plural(failed, "package couldn't be fetched", "packages couldn't be fetched"))
			partial = true
		}
		switch r.StoppedBy {
		case "":
		case "interrupted":
			what, partial = append(what, "the run was interrupted"), true
		case "deadline":
			what, partial = append(what, "the run hit its --deadline"), true
		default:
			what, partial = append(what, "the run stopped early"), true
		}
		if partial {
			flags = append(flags, "--allow-partial")
		}
	}
	if len(what) == 0 {
		return cli.ExitOK, ""
	}
	accept := "to accept them"
	if len(flags) == 1 && flags[0] == "--allow-partial" && notChecked == 0 && failed == 0 {
		accept = "to accept a partial run"
	}
	return cli.ExitUnavailable, fmt.Sprintf("%s, so --fail-on %s can't pass it\nadd %s %s",
		join(what), o.FailOn, join(flags), accept)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// join lists items as "a, b and c", with no comma before the "and".
func join(items []string) string {
	if len(items) <= 1 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}
