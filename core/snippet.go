// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import (
	"encoding/json"
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

// NewSnippet masks secrets with kit secrets.Redact, makes the text safe
// for a terminal with kit term.Sanitize and cuts it to SnippetMax bytes
// on a rune boundary, ending in "…" when cut. Masking runs first so a
// secret is never split by the cut and left half visible.
func NewSnippet(raw string) Snippet {
	s := term.Sanitize(secrets.Redact(raw))
	if len(s) <= SnippetMax {
		return Snippet{s}
	}
	cut := SnippetMax - len(ellipsis)
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return Snippet{s[:cut] + ellipsis}
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
