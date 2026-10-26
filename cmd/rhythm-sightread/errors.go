// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"errors"
	"fmt"
	"io"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/secrets"
	"github.com/RhythmShahriar/sightread/core"
)

// finish prints a *core.Error the way PRD section 10 shows it, "<program>
// <command>: <what happened>" then the indented fix; it returns its exit
// code for cli.Main. kit's own printing would put the program name in
// front a second time. With -v the cause follows on its own line, masked
// like every other -v output. Other errors go back to cli.Main as they
// are.
func finish(stderr io.Writer, err error, verbose bool) error {
	var e *core.Error
	if !errors.As(err, &e) {
		return err
	}
	fmt.Fprintln(stderr, e.Error())
	if verbose && e.Err != nil {
		fmt.Fprintf(stderr, "  cause: %s\n", secrets.Redact(e.Err.Error()))
	}
	return &cli.ExitError{Code: e.ExitCode()}
}
