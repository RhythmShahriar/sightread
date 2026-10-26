// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"errors"

	"github.com/RhythmShahriar/rhythm/kit/cli"
)

// GateOptions decide the exit code of a review (PRD section 10).
type GateOptions struct {
	FailOn          cli.Severity
	AllowPartial    bool
	AllowUnverified bool
	FailOnNew       cli.Severity // watch: new findings at or above this
}

// Scorer applies severity overrides, context rules, ignore, allow and
// baseline to an update, sets its verdict, counts the report and gates
// it (package score).
type Scorer interface {
	Score(ctx context.Context, u *Update, cfg *Config, allow AllowSet, baseline map[string]bool)
	Summarise(r *Report)
	Gate(r *Report, o GateOptions) (exit int, reason string)
}

// AllowSet answers whether a version was reviewed.
type AllowSet interface {
	// Match returns the entry for this exact version and hash, whether
	// it counts (an entry only in the working tree of `changes` doesn't
	// without --trust-pr-allow) and an entry for the same version with
	// another hash (approved-version-changed).
	Match(eco Ecosystem, name, version, sha256 string) (match *AllowEntry, counted bool, conflict *AllowEntry)
}

// ErrAlreadyAllowed is the cause of the error AddAllow returns for an
// entry the file already has, so allow --from can skip it and go on.
var ErrAlreadyAllowed = errors.New("already allowed")

// Policy loads and edits config, allow and baseline files (package
// policy).
type Policy interface {
	// LoadConfig finds the config from start upwards, or reads explicit,
	// or returns an empty one when none is true. It returns the config's
	// path, "" when there is none.
	LoadConfig(start string, explicit string, none bool) (*Config, string, error)
	// LoadAllow reads the allow files; baseRef, when set, reads them at
	// that git ref too (changes).
	LoadAllow(cfg *Config, configPath string, baseRef string) (AllowSet, error)
	// AddAllow appends e; an error wrapping ErrAlreadyAllowed means the
	// same package, version and hash is already there.
	AddAllow(path string, e AllowEntry) error
	RemoveAllow(path string, r Ref) error
	ImportAllow(path, from string) (int, error)
	// LoadBaseline returns the fingerprints of a saved report.
	LoadBaseline(path string) (map[string]bool, error)
}
