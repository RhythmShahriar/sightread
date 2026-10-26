// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package proc is the only package that starts programs. Sightread never
// runs fetched code: the programs it starts are git (to read a lockfile
// at a ref), the user's own wp command, rhythm-soundcheck and
// rhythm-roadie, the --apply command on a staging copy, a watch run of
// itself and the OS opener for --open. Run takes an argv, never a shell
// line, caps what it reads back and stops the child's whole process tree
// when the context ends. Interrupt, KillOnExit and KillTree are the
// process helpers that differ between Unix and Windows.
package proc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/secrets"
)

// Interrupt sets cmd.Cancel to ask the child to stop: an interrupt on
// Unix, so it can clean up (close its browser, finish writing files),
// and a kill on Windows, which can't send an interrupt to another
// process. A child that ignores the interrupt is still killed after
// cmd.WaitDelay.
func Interrupt(cmd *exec.Cmd) {
	cmd.Cancel = func() error { return stop(cmd) }
}

// Purposes of Spec.Purpose: why Sightread starts a program. -v prints
// it, so a user sees every program a run started and why.
const (
	PurposeGit        = "git"
	PurposeWPCLI      = "wp-cli"
	PurposeApply      = "apply"
	PurposeSoundcheck = "soundcheck"
	PurposeRoadie     = "roadie"
	PurposeWatchChild = "watch-child"
	PurposeOpen       = "open"
)

var purposes = map[string]bool{PurposeGit: true, PurposeWPCLI: true, PurposeApply: true,
	PurposeSoundcheck: true, PurposeRoadie: true, PurposeWatchChild: true, PurposeOpen: true}

// DefaultMaxOutput is the most bytes Run keeps from stdout and from
// stderr when Spec.MaxOutput is 0.
const DefaultMaxOutput = 16 << 20

// waitDelay is how long a child gets to stop after the interrupt before
// it is killed.
const waitDelay = 5 * time.Second

// ErrOutputTooLarge is returned when a child writes more than
// Spec.MaxOutput to stdout or stderr. The child is stopped.
var ErrOutputTooLarge = errors.New("program output over the limit")

// Spec is one program to run.
type Spec struct {
	Argv      []string // program and arguments; never passed to a shell
	Dir       string
	Env       []string // nil inherits this process's environment
	Stdin     io.Reader
	MaxOutput int64         // per stream; 0 means DefaultMaxOutput
	Timeout   time.Duration // 0 means only the context bounds it
	Purpose   string        // one of the Purpose* constants
	// Log, when set, receives one line before the program starts:
	// "run <purpose>: <argv>", with secrets in the argv masked (-v).
	Log io.Writer
}

// Result is what a finished program left.
type Result struct {
	Stdout, Stderr []byte
	Code           int // exit code; -1 when it was killed
}

// Run starts s.Argv and waits for it. The error is nil when the program
// ran to its end, whatever its exit code (see Result.Code); it is set
// when the program could not start, the context or Timeout ended it or
// it wrote more than MaxOutput.
func Run(ctx context.Context, s Spec) (Result, error) {
	if len(s.Argv) == 0 || s.Argv[0] == "" {
		return Result{Code: -1}, errors.New("proc: empty argv")
	}
	if !purposes[s.Purpose] {
		return Result{Code: -1}, fmt.Errorf("proc: unknown purpose %q", s.Purpose)
	}
	if s.Log != nil {
		fmt.Fprintf(s.Log, "run %s: %s\n", s.Purpose, secrets.Redact(strings.Join(s.Argv, " ")))
	}
	if s.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.Timeout)
		defer cancel()
	}
	limit := s.MaxOutput
	if limit <= 0 {
		limit = DefaultMaxOutput
	}
	ctx, over := context.WithCancelCause(ctx)
	defer over(nil)
	stdout := &capped{limit: limit, over: over}
	stderr := &capped{limit: limit, over: over}

	cmd := exec.CommandContext(ctx, s.Argv[0], s.Argv[1:]...) //nolint:gosec // argv from Sightread's own callers, never a shell
	cmd.Dir, cmd.Env, cmd.Stdin = s.Dir, s.Env, s.Stdin
	cmd.Stdout, cmd.Stderr = stdout, stderr
	cmd.WaitDelay = waitDelay
	ownGroup(cmd)
	Interrupt(cmd)
	if err := cmd.Start(); err != nil {
		return Result{Code: -1}, fmt.Errorf("proc: start %s: %w", s.Argv[0], err)
	}
	err := cmd.Wait()
	res := Result{Stdout: stdout.buf.Bytes(), Stderr: stderr.buf.Bytes(), Code: cmd.ProcessState.ExitCode()}
	if ctx.Err() != nil {
		// The child is gone; anything it started may not be.
		stopGroup(cmd)
		if cause := context.Cause(ctx); errors.Is(cause, ErrOutputTooLarge) {
			return res, fmt.Errorf("proc: %s: %w", s.Argv[0], ErrOutputTooLarge)
		}
		return res, fmt.Errorf("proc: %s stopped: %w", s.Argv[0], context.Cause(ctx))
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		return res, fmt.Errorf("proc: %s: %w", s.Argv[0], err)
	}
	return res, nil
}

// capped keeps up to limit bytes and cancels the run on the first byte
// past it.
type capped struct {
	buf   bytes.Buffer
	limit int64
	over  context.CancelCauseFunc
}

func (c *capped) Write(p []byte) (int, error) {
	room := c.limit - int64(c.buf.Len())
	if int64(len(p)) > room {
		c.buf.Write(p[:max(room, 0)])
		c.over(ErrOutputTooLarge)
		return 0, ErrOutputTooLarge
	}
	return c.buf.Write(p)
}

// LookPath finds a program on PATH, for doctor and the --soundcheck
// checks. It never runs it.
func LookPath(name string) (string, error) { return exec.LookPath(name) }
