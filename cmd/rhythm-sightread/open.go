// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"runtime"
	"time"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/internal/proc"
)

// openTimeout bounds the OS opener, which normally hands the file to the
// browser and returns at once.
const openTimeout = 30 * time.Second

// openReport opens the first HTML report with the OS opener for --open.
// When there is none, or it fails, it says where the report is instead:
// the report is written either way.
func openReport(ctx context.Context, p *plan, stderr io.Writer) {
	path := ""
	for _, f := range p.files {
		if f.format == core.FormatHTML {
			path = f.path
			break
		}
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	argv := opener(runtime.GOOS, path)
	if _, err := proc.LookPath(argv[0]); err == nil {
		res, err := proc.Run(ctx, proc.Spec{Argv: argv, Purpose: proc.PurposeOpen, Timeout: openTimeout, Log: p.req.Log})
		if err == nil && res.Code == 0 {
			return
		}
	}
	fmt.Fprintf(stderr, "open %s in a browser\n", path)
}

// opener is the argv that opens path in the default browser on goos.
func opener(goos, path string) []string {
	switch goos {
	case "darwin":
		return []string{"open", path}
	case "windows":
		return []string{"rundll32", "url.dll,FileProtocolHandler", path}
	}
	return []string{"xdg-open", path}
}
