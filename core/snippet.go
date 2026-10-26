// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import (
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/RhythmShahriar/rhythm/kit/secrets"
	"github.com/RhythmShahriar/rhythm/kit/term"
)

// SnippetMax is the most bytes a snippet holds, the "…" included.
const SnippetMax = 300

const ellipsis = "…"

// Snippet is package text that is safe to put in a finding: secrets
// masked, control and bidi characters escaped, at most SnippetMax bytes.
// Its field is unexported so NewSnippet is the only way to make one
// (SR-10): no writer ever sees raw package text through a Finding.
type Snippet struct{ s string }

// NewSnippet masks secrets with kit secrets.Redact, writes each bidi
// control (U+202A-U+202E, U+2066-U+2069) as a visible \u202e escape,
// makes the rest safe for a terminal with kit term.Sanitize and cuts it
// to SnippetMax bytes on a rune boundary, ending in "…" when cut.
// Masking runs first so a secret is never split by an escape or the cut
// and left half visible. The escape keeps the evidence of a Trojan
// Source finding: Sanitize alone drops the very character it reports.
func NewSnippet(raw string) Snippet {
	s := term.Sanitize(escapeBidi(secrets.Redact(raw)))
	if len(s) <= SnippetMax {
		return Snippet{s}
	}
	cut := SnippetMax - len(ellipsis)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return Snippet{s[:cut] + ellipsis}
}

// IsBidi reports whether r is a bidirectional embedding, override or
// isolate, the characters of Trojan Source.
func IsBidi(r rune) bool { return r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069 }

// escapeBidi writes each bidi control in s as \u followed by its four
// hex digits.
func escapeBidi(s string) string {
	if !strings.ContainsFunc(s, IsBidi) {
		return s
	}
	var b strings.Builder
	for _, r := range s {
		if IsBidi(r) {
			fmt.Fprintf(&b, `\u%04x`, r)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// String returns the safe text.
func (s Snippet) String() string { return s.s }

// MarshalJSON writes the safe text as a JSON string.
func (s Snippet) MarshalJSON() ([]byte, error) { return json.Marshal(s.s) }

// UnmarshalJSON reads a saved report's evidence back through NewSnippet,
// so text from a report file is treated as untrusted too.
func (s *Snippet) UnmarshalJSON(b []byte) error {
	var raw string
	if err := json.Unmarshal(b, &raw); err != nil {
		return err
	}
	*s = NewSnippet(raw)
	return nil
}
