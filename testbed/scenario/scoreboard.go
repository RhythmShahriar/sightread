// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package scenario

import (
	"fmt"
	"strings"
)

// Tally counts outcomes by status.
type Tally struct {
	Caught, FoundOther, Missed, Clean, FalseAlarm, Pending, NoReport int
}

// TallyOf counts a set of outcomes.
func TallyOf(outcomes []Outcome) Tally {
	var t Tally
	for _, o := range outcomes {
		switch o.Status {
		case StatusCaught:
			t.Caught++
		case StatusFoundOther:
			t.FoundOther++
		case StatusMissed:
			t.Missed++
		case StatusClean:
			t.Clean++
		case StatusFalseAlarm:
			t.FalseAlarm++
		case StatusPending:
			t.Pending++
		case StatusNoReport:
			t.NoReport++
		}
	}
	return t
}

// Pass reports whether the 1.0 detection targets are met: every
// non-pending bad scenario caught, no good scenario a false alarm and
// every run wrote a report.
func (t Tally) Pass() bool {
	return t.FoundOther == 0 && t.Missed == 0 && t.FalseAlarm == 0 && t.NoReport == 0
}

// Scoreboard renders the detection scoreboard as Markdown. The benchmark
// prepends the generated-file header and the honest framing and appends
// the safety counters, speed and the compared tools.
func Scoreboard(outcomes []Outcome) string {
	t := TallyOf(outcomes)
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }

	w("## Scoreboard\n\n")
	w("Caught %d, found as something else %d, missed %d, false alarms %d, no report %d, pending %d.\n\n",
		t.Caught, t.FoundOther, t.Missed, t.FalseAlarm, t.NoReport, t.Pending)

	w("### Bad scenarios\n\n")
	w("| Scenario | Title | Result | Signals |\n")
	w("|---|---|---|---|\n")
	for _, o := range outcomes {
		if o.Scenario.Kind != KindBad {
			continue
		}
		w("| %s | %s | %s | %s |\n", o.Scenario.ID, o.Scenario.Title, result(o), signals(o))
	}

	w("\n### Good scenarios\n\n")
	w("| Scenario | Title | Result | False alarms |\n")
	w("|---|---|---|---|\n")
	for _, o := range outcomes {
		if o.Scenario.Kind != KindGood {
			continue
		}
		w("| %s | %s | %s | %s |\n", o.Scenario.ID, o.Scenario.Title, result(o), joinOrDash(o.FalseAlarms))
	}

	if t.NoReport > 0 {
		w("\n### No report (shown apart: neither caught nor clean)\n\n")
		w("The run crashed, timed out or stopped with a usage error before writing its report; the problems table says why.\n\n")
		for _, o := range outcomes {
			if o.Status == StatusNoReport {
				w("- %s %s\n", o.Scenario.ID, o.Scenario.Title)
			}
		}
	}

	if t.Pending > 0 {
		w("\n### Pending (shown apart, not counted)\n\n")
		for _, o := range outcomes {
			if o.Status == StatusPending {
				w("- %s %s: %s\n", o.Scenario.ID, o.Scenario.Title, o.Scenario.Pending)
			}
		}
	}
	return b.String()
}

// result is the human label for an outcome's status.
func result(o Outcome) string {
	switch o.Status {
	case StatusCaught:
		return "caught"
	case StatusFoundOther:
		return "found as something else"
	case StatusMissed:
		return "MISSED"
	case StatusClean:
		return "clean"
	case StatusFalseAlarm:
		return "FALSE ALARM"
	case StatusPending:
		return "pending"
	case StatusNoReport:
		return "NO REPORT"
	}
	return string(o.Status)
}

// signals lists a bad outcome's present and missing signals.
func signals(o Outcome) string {
	parts := make([]string, 0, len(o.Present)+len(o.Missing)+len(o.Forbidden))
	parts = append(parts, o.Present...)
	for _, m := range o.Missing {
		parts = append(parts, "missing:"+m)
	}
	for _, f := range o.Forbidden {
		parts = append(parts, "forbidden:"+f)
	}
	return joinOrDash(parts)
}

// joinOrDash joins ss with commas, or a dash when empty.
func joinOrDash(ss []string) string {
	if len(ss) == 0 {
		return "-"
	}
	return strings.Join(ss, ", ")
}
