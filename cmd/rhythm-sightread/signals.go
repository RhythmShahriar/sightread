// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

// signalsCommand is `signals`: the catalogue of PRD 12.1 as a table or
// as the kind signals document.
var signalsCommand = &simpleCommand{
	name: "signals", args: "[--json]", summary: "list every signal with its default severity",
	long: "Lists every signal Sightread can raise, in catalogue order, with its default severity, confidence, the " +
		"ecosystems it applies to and the title reports use. Config signals.severity changes a severity for one " +
		"project. Read one in full with {prog} explain <id>.",
	examples: []string{"signals", "signals --json"},
	flags: func(fs *flag.FlagSet, _ *simpleFlags) runFunc {
		asJSON := fs.Bool("json", false, "print the signals document as JSON (rhythm-sightread/v1, kind signals)")
		return func(_ context.Context, pos []string, stdout, _ io.Writer) error {
			if len(pos) > 0 {
				return cli.Usagef("signals takes no arguments, got %q", pos[0])
			}
			if *asJSON {
				return writeDocument(stdout, core.KindSignals, "", core.SignalsData{Signals: core.Catalog})
			}
			return writeSignals(stdout, core.Catalog)
		}
	},
}

// writeSignals prints the signals table: ID, SEVERITY, CONFIDENCE,
// ECOSYSTEMS and NAME, with a mark on the IDs that can never be ignored.
func writeSignals(w io.Writer, signals []core.SignalInfo) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSEVERITY\tCONFIDENCE\tECOSYSTEMS\tNAME")
	for _, s := range signals {
		ecos := make([]string, len(s.Ecosystems))
		for i, e := range s.Ecosystems {
			ecos[i] = string(e)
		}
		name := s.Title
		if s.Unignorable {
			name += " (can't be ignored)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", s.ID, s.Severity, s.Confidence, strings.Join(ecos, ","), name)
	}
	return tw.Flush()
}
