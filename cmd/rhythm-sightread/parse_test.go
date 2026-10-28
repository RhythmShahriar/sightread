// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"
)

// TestFlagErrors: a bad flag is named as typed, with one hint and where
// the flags are listed. No help page follows.
func TestFlagErrors(t *testing.T) {
	world(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"demo", "--md"}, "rhythm-sightread demo: unknown flag --md\n  the demo writes other formats as files: -o demo.md\n  rhythm-sightread help demo lists every flag\n"},
		{[]string{"report", "r.json", "--jsonl"}, "rhythm-sightread report: unknown flag --jsonl\n  report writes .md, .html, .sarif and .json; the JSONL stream comes only from a review (--jsonl)\n  rhythm-sightread help report lists every flag\n"},
		{[]string{"doctor", "--jsn"}, "rhythm-sightread doctor: unknown flag --jsn\n  did you mean --json?\n  rhythm-sightread help doctor lists every flag\n"},
		{[]string{"all", "--retries"}, "rhythm-sightread all: --retries needs a value\n  rhythm-sightread help all lists every flag\n"},
		{[]string{"changes", "-sarf"}, "rhythm-sightread changes: unknown flag -sarf\n  did you mean --sarif?\n  rhythm-sightread help changes lists every flag\n"},
	} {
		code, out, errOut := execute(t, c.args...)
		if code != cli.ExitUsage || out != "" || errOut != c.want {
			t.Errorf("%q: exit %d stdout %q stderr\n%q\nwant\n%q", c.args, code, out, errOut, c.want)
		}
	}
}

// TestTypedAs keeps the dashes and drops a value.
func TestTypedAs(t *testing.T) {
	for _, c := range []struct {
		args       []string
		name, want string
	}{
		{[]string{"--md"}, "md", "--md"},
		{[]string{"-q"}, "q", "-q"},
		{[]string{"--to=1.0"}, "to", "--to"},
		{[]string{"--", "--x"}, "x", "-x"}, // after -- nothing is a flag
		{nil, "q", "-q"},
	} {
		if got := typedAs(c.args, c.name); got != c.want {
			t.Errorf("typedAs(%q, %q) = %q, want %q", c.args, c.name, got, c.want)
		}
	}
}
