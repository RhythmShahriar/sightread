// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package release

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Finding is one finding of a reviewed release.
type Finding struct {
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title,omitempty"`
}

// Review is the result of one pair of the corpus.
type Review struct {
	Entry    Entry     `json:"entry"`
	Verdict  string    `json:"verdict"` // HOLD, REVIEW, ROUTINE, UNVERIFIED or ERROR
	Findings []Finding `json:"findings,omitempty"`
	Error    string    `json:"error,omitempty"`
	Seconds  float64   `json:"seconds"`
}

// Timing is one PRD 17 real-network case.
type Timing struct {
	Case   string  `json:"case"`
	Target string  `json:"target"`
	Limit  float64 `json:"limit_seconds"`
	// Seconds is the measured time; negative when the case did not run.
	Seconds float64 `json:"seconds"`
	Note    string  `json:"note,omitempty"`
}

// Met reports whether the case ran within its limit.
func (t Timing) Met() bool { return t.Seconds >= 0 && t.Seconds < t.Limit }

// Run is one owner run of the corpus.
type Run struct {
	Fetched time.Time `json:"fetched"`
	Ran     time.Time `json:"ran"`
	Version string    `json:"version"`
	Machine string    `json:"machine"`
	Reviews []Review  `json:"reviews"`
	Timings []Timing  `json:"timings"`
}

// Counts tallies the verdicts.
type Counts struct {
	Hold, Review, Routine, Other, Errors, Total int
}

// Count tallies a run's verdicts. Total counts the pairs that were
// reviewed (errors left out).
func (r Run) Count() Counts {
	var c Counts
	for _, rv := range r.Reviews {
		switch rv.Verdict {
		case "HOLD":
			c.Hold++
		case "REVIEW":
			c.Review++
		case "ROUTINE":
			c.Routine++
		case "ERROR", "":
			c.Errors++
			continue
		default:
			c.Other++
		}
		c.Total++
	}
	return c
}

// TargetMet applies PRD 19: on real benign updates, zero HOLD and at
// most 1 in 10 REVIEW.
func (c Counts) TargetMet() bool {
	return c.Total > 0 && c.Hold == 0 && c.Review*10 <= c.Total
}

// RenderSection writes the real-release section of docs/benchmark.md
// (without the corpus markers; benchdoc.SpliceCorpus adds them).
func RenderSection(r Run) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	c := r.Count()

	w("## Real releases (owner-run)\n\n")
	fetched := "Not fetched yet"
	if !r.Fetched.IsZero() {
		fetched = "Fetched " + r.Fetched.UTC().Format("2006-01-02") + " by the owner"
	}
	w("%s with `make -C testbed corpus` from downloads.wordpress.org and registry.npmjs.org, each archive checked against the SHA-256 pinned in `testbed/corpus/corpus.lock`; reviewed %s with %s on %s. These are real releases of popular packages, assumed benign, so every HOLD or REVIEW below is a false alarm until the owner judges otherwise. It needs network, so it is never part of the testbed or CI.\n\n",
		fetched, r.Ran.UTC().Format("2006-01-02"), orDash(r.Version), orDash(r.Machine))

	res := "met"
	if !c.TargetMet() {
		res = "**not met**"
	}
	w("| HOLD | REVIEW | ROUTINE | Other | Could not review | Target: 0 HOLD, at most 1 in 10 REVIEW |\n|---|---|---|---|---|---|\n")
	w("| %d | %d | %d | %d | %d | %s (%s) |\n\n", c.Hold, c.Review, c.Routine, c.Other, c.Errors, res, rate(c))

	w("### Findings for the owner to judge\n\n")
	var flagged []Review
	for _, rv := range r.Reviews {
		if rv.Verdict == "HOLD" || rv.Verdict == "REVIEW" {
			flagged = append(flagged, rv)
		}
	}
	sort.SliceStable(flagged, func(i, j int) bool { return flagged[i].Verdict < flagged[j].Verdict })
	switch {
	case c.Total == 0:
		w("Nothing was reviewed.\n\n")
	case len(flagged) == 0:
		w("None: every reviewed pair came back ROUTINE.\n\n")
	default:
		w("| Package | Update | Verdict | Findings |\n|---|---|---|---|\n")
		for _, rv := range flagged {
			w("| %s | %s to %s | %s | %s |\n", rv.Entry.Ref(), rv.Entry.From, rv.Entry.To, rv.Verdict, cell(findings(rv.Findings)))
		}
		w("\n")
	}

	var failed []Review
	for _, rv := range r.Reviews {
		if rv.Verdict == "ERROR" || rv.Verdict == "" {
			failed = append(failed, rv)
		}
	}
	if len(failed) > 0 {
		w("### Could not review\n\n")
		for _, rv := range failed {
			w("- %s %s to %s: %s\n", rv.Entry.Ref(), rv.Entry.From, rv.Entry.To, orDash(rv.Error))
		}
		w("\n")
	}

	w("### Real-network speed (PRD 17)\n\n")
	if len(r.Timings) == 0 {
		w("Not measured in this run.\n")
		return b.String()
	}
	w("| Case | Target | Measured | Result |\n|---|---|---|---|\n")
	for _, t := range r.Timings {
		measured, result := "not run", "not run"
		if t.Seconds >= 0 {
			measured = fmt.Sprintf("%.1f s", t.Seconds)
			result = "met"
			if !t.Met() {
				result = "**not met**"
			}
		}
		if t.Note != "" {
			result += " (" + t.Note + ")"
		}
		w("| %s | %s | %s | %s |\n", t.Case, t.Target, measured, cell(result))
	}
	return b.String()
}

// rate is the REVIEW and HOLD share as "3 of 97 (3.1%)".
func rate(c Counts) string {
	if c.Total == 0 {
		return "nothing reviewed"
	}
	n := c.Hold + c.Review
	return fmt.Sprintf("%d of %d flagged, %.1f%%", n, c.Total, 100*float64(n)/float64(c.Total))
}

// findings lists ids with their severity.
func findings(fs []Finding) string {
	if len(fs) == 0 {
		return "-"
	}
	parts := make([]string, 0, len(fs))
	for _, f := range fs {
		parts = append(parts, f.ID+" ("+f.Severity+")")
	}
	return strings.Join(parts, ", ")
}

// cell keeps text inside a Markdown table cell.
func cell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", `\|`), "\n", " ")
}

// orDash returns s or a dash.
func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
