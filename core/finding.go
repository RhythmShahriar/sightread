// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path"
	"strings"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
)

// AllowMatch is the allow entry that covers a finding.
type AllowMatch struct {
	By     string `json:"by"`
	Reason string `json:"reason"`
	Date   string `json:"date"`
	Until  string `json:"until"`
	Source string `json:"source"` // the allowed.yaml it came from
	// InThisChange marks an entry that exists only in the working tree
	// of `changes`: shown, not counted, unless --trust-pr-allow.
	InThisChange bool `json:"-"`
}

// Finding is one signal on one update.
type Finding struct {
	ID          string
	Title       string
	Severity    cli.Severity
	Confidence  Confidence
	File        string // path inside the package, or the project's lockfile (InLockfile)
	Line        int
	EndLine     int
	Evidence    Snippet
	Domains     []string
	RaisedBy    []string // context rules that raised it
	Demoted     string   // why it was lowered, e.g. "vendored path"
	Advice      string
	Fingerprint string
	Allowed     *AllowMatch
	// Func is the function or method the evidence is in, from the
	// feature's Evidence.Func ("" at the top level or for metadata), for
	// the same-function context rule.
	Func string

	Baselined       bool
	Ignored         bool
	BelowConfidence bool
}

// FindingsVerdict is the verdict u's counted findings give on their
// own, leaving out whether its bytes were verified: HOLD for a critical
// one, REVIEW for high or medium, ALLOWED when every finding is allowed
// and ROUTINE otherwise. An UNVERIFIED update reviewed with
// --allow-unverified shows it as "would be HOLD".
func (u *Update) FindingsVerdict() Verdict {
	worst, allowed := cli.SeverityNone, 0
	for _, f := range u.Findings {
		if f.Allowed != nil {
			allowed++
		}
		if f.Counted() {
			worst = max(worst, f.Severity)
		}
	}
	switch {
	case worst == cli.SeverityCritical:
		return Hold
	case worst >= cli.SeverityMedium:
		return Review
	case worst == cli.SeverityNone && allowed > 0:
		return Allowed
	}
	return Routine
}

// SetAside is whether --baseline or a config ignore took f out of the
// count. An allowed finding is not set aside: it was reviewed.
func (f *Finding) SetAside() bool {
	return f.Allowed == nil && (f.Baselined || f.Ignored)
}

// Severe reports whether f is critical or high.
func (f *Finding) Severe() bool { return f.Severity >= cli.SeverityHigh }

// SetAsideSevere counts u's findings, shown or hidden, that --baseline
// or a config ignore took out of the count while they are critical or
// high. Such an update is never offered as safe to install.
func (u *Update) SetAsideSevere() int {
	n := 0
	for _, fs := range [][]Finding{u.Findings, u.Hidden} {
		for i := range fs {
			if fs[i].SetAside() && fs[i].Severe() {
				n++
			}
		}
	}
	return n
}

// Counted reports whether f counts for the verdict and the gate.
func (f *Finding) Counted() bool {
	return f.Allowed == nil && !f.Ignored && !f.Baselined && !f.BelowConfidence
}

// lockfileSignals are the signals that point at the project's lockfile
// (the entry of the package) rather than at a file in the package.
var lockfileSignals = map[string]bool{"dependency-new": true, "version-republished": true, "lockfile-source-change": true}

// lockfileNames are the lockfiles inventory reads.
var lockfileNames = map[string]bool{"composer.lock": true, "npm-shrinkwrap.json": true, "package-lock.json": true,
	"pnpm-lock.yaml": true, "yarn.lock": true, "bun.lock": true}

// InLockfile reports whether f points at the project's lockfile, which
// is outside the package: no archive holds it, so there is no package
// diff to show for it.
func (f *Finding) InLockfile() bool {
	return lockfileSignals[f.ID] && lockfileNames[path.Base(f.File)]
}

// Subject is everything detectors look at for one update.
type Subject struct {
	Update                     Ref   // name and candidate version
	Old, New                   *Meta // Old nil for an added package
	OldTree, NewTree           *Tree
	OldIntegrity, NewIntegrity Integrity
	OldLock, NewLock           *Installed // lock entries when known
	Diff                       *Diff
	OldFeatures, NewFeatures   *FeatureSet
	Drift                      *Drift // installed copy vs official installed version
	Config                     *Config
	Now                        time.Time
}

// DetectorInfo names a detector and the signals it may emit.
type DetectorInfo struct {
	Name    string
	Signals []string
}

// Detector turns a Subject into findings. It reads only the Subject:
// no network, no files, no clock.
type Detector interface {
	Info() DetectorInfo
	Detect(ctx context.Context, s *Subject, emit func(Finding))
}

// ConfigChecker is a Detector that reads files the config names (the
// --signals rule folders). run calls CheckConfig once before any
// download, so a missing folder or a bad file stops the run with its
// error (E12) instead of switching rules off without a word.
type ConfigChecker interface {
	CheckConfig(c *Config) error
}

// Explain is a signal's explain text (PRD 6.5).
type Explain struct {
	Why, HowToReview, FalseAlarms, Incidents, Advice, More string
}

// Fingerprint identifies a finding across runs, for --baseline and SARIF
// partialFingerprints: the first 16 hex of SHA-256 over
// "ecosystem|name|to.version|id|file|evidence" (PRD 9.2). file is made
// slash separated and relative and the evidence has its whitespace
// collapsed, so neither the machine nor reformatting changes it.
func Fingerprint(eco Ecosystem, name, toVersion, id, file string, evidence Snippet) string {
	file = strings.ReplaceAll(file, `\`, "/")
	if file != "" {
		file = strings.TrimLeft(path.Clean(file), "/")
	}
	ev := strings.Join(strings.Fields(evidence.String()), " ")
	sum := sha256.Sum256([]byte(strings.Join([]string{string(eco), name, toVersion, id, file, ev}, "|")))
	return hex.EncodeToString(sum[:8])
}
