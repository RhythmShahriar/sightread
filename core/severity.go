// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

// Severities are kit cli.Severity values (cli.SeverityCritical and the
// rest), so --fail-on parses and compares the same way in every tool.

// Confidence says how exact the pattern behind a finding is.
type Confidence string

// The confidences, from most to least exact.
const (
	Confirmed Confidence = "confirmed" // an exact pattern
	Likely    Confidence = "likely"    // a heuristic
)

// ParseConfidence reads a --min-confidence or min_confidence value.
func ParseConfidence(s string) (Confidence, bool) {
	switch Confidence(s) {
	case Confirmed, Likely:
		return Confidence(s), true
	}
	return "", false
}
