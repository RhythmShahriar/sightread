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
	File        string // path inside the package
	Line        int
	EndLine     int
	Evidence    Snippet
	Domains     []string
	RaisedBy    []string // context rules that raised it
	Demoted     string   // why it was lowered, e.g. "vendored path"
	Advice      string
	Fingerprint string
	Allowed     *AllowMatch

	Baselined       bool
	Ignored         bool
	BelowConfidence bool
}

// Counted reports whether f counts for the verdict and the gate.
func (f *Finding) Counted() bool {
	return f.Allowed == nil && !f.Ignored && !f.Baselined && !f.BelowConfidence
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
