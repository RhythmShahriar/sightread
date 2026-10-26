// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Command signalsdoc writes docs/signals.md, the signal reference, from
// the catalogue and the explain text. Run it from the module's folder
// after changing either:
//
//	go run ./detect/cmd/signalsdoc
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/RhythmShahriar/sightread/detect"
)

func main() {
	out := flag.String("o", detect.SignalsDocPath, "the file to write")
	flag.Parse()
	if err := os.WriteFile(*out, detect.SignalsDoc(), 0o644); err != nil { //nolint:gosec // a doc in the repository, read by everyone
		fmt.Fprintln(os.Stderr, "signalsdoc:", err)
		os.Exit(1)
	}
}
