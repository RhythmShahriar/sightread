// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import (
	"errors"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"
)

// ErrorCode names one case of the error table in PRD section 10.
type ErrorCode string

// The error codes of PRD section 10 (E21 was added by the lead for a
// remote --wp prefix under --soundcheck).
const (
	ENothingInstalled   ErrorCode = "E1"  // nothing installed found
	EUnknownPackage     ErrorCode = "E2"  // slug or name unknown on the source
	EVersionMissing     ErrorCode = "E3"  // version not published
	ENoLockfile         ErrorCode = "E4"  // no lockfile
	EUnverifiable       ErrorCode = "E5"  // integrity could not be checked
	EIntegrityMismatch  ErrorCode = "E6"  // integrity mismatch (reported as a finding)
	ENetwork            ErrorCode = "E7"  // network down, or offline with an empty cache
	EUnsupportedLock    ErrorCode = "E8"  // unsupported lockfile
	ERateLimited        ErrorCode = "E9"  // rate limited
	EAuth               ErrorCode = "E10" // private package needs auth
	ETooLarge           ErrorCode = "E11" // too big or a bomb
	EBadConfig          ErrorCode = "E12" // bad config or allow entry
	EBadFlag            ErrorCode = "E13" // bad flag value
	EProduction         ErrorCode = "E14" // --soundcheck on production
	ESoundcheckMissing  ErrorCode = "E15" // Soundcheck or Roadie missing, or verify failed
	EGitHubLimit        ErrorCode = "E16" // GitHub anonymous limit
	ESoundcheckOnHold   ErrorCode = "E17" // --soundcheck on a HOLD
	EAllowUnverified    ErrorCode = "E18" // allow on an unverified or mismatched version
	EDowngrade          ErrorCode = "E19" // downgrade without --allow-downgrade
	EUnknownCommand     ErrorCode = "E20" // unknown command (kit text)
	ERemoteWPSoundcheck ErrorCode = "E21" // --soundcheck with a remote --wp prefix
)

// Error is a Sightread error as the user sees it: one line saying what
// happened, then indented lines with the fix.
type Error struct {
	Code    ErrorCode
	Exit    int    // cli.ExitUsage, cli.ExitUnavailable, cli.ExitFindings
	Command string // "plugin"; empty for tool-wide
	What    string // first line after "<program> <command>: "
	Hint    []string
	Err     error // cause, printed only with -v
}

// Error returns "<program> <command>: <What>" and one line per hint
// indented by two spaces. <program> is kit cli.Name(), so it reads
// "rhythm sightread" through the router.
func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString(cli.Name())
	if e.Command != "" {
		b.WriteString(" ")
		b.WriteString(e.Command)
	}
	b.WriteString(": ")
	b.WriteString(e.What)
	for _, h := range e.Hint {
		b.WriteString("\n  ")
		b.WriteString(h)
	}
	return b.String()
}

// Unwrap returns the cause.
func (e *Error) Unwrap() error { return e.Err }

// ExitCode returns e.Exit, or cli.ExitUnavailable when it was left zero,
// so an Error never passes as success.
func (e *Error) ExitCode() int {
	if e.Exit == 0 {
		return cli.ExitUnavailable
	}
	return e.Exit
}

// CodeOf returns the code of the first *Error in err's chain, or "".
func CodeOf(err error) ErrorCode {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
