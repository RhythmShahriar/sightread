// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package report

import (
	"fmt"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
)

// notePrefix starts a hunk line that is Sightread's own note rather than
// package text (package diff's NotePrefix): `\ No newline at end of
// file`, `\ binary file changed (...)`, `\ line endings changed only`.
const notePrefix = `\ `

// noteLine reports whether a hunk line is a note.
func noteLine(l string) bool { return strings.HasPrefix(l, notePrefix) }

// notesOnly reports a hunk that holds notes only (a binary file or a
// change of line endings): it has no line numbers to show.
func notesOnly(h core.Hunk) bool {
	if len(h.Lines) == 0 {
		return false
	}
	for _, l := range h.Lines {
		if !noteLine(l) {
			return false
		}
	}
	return true
}

// hunkHead is the header line of h without the path: "" for a hunk of
// notes only, "@@ tokens @@" for one that numbers tokens of a minified
// file, else the unified "@@ -a,b +c,d @@".
func hunkHead(h core.Hunk) string {
	switch {
	case notesOnly(h):
		return ""
	case h.Tokens:
		return "@@ tokens @@"
	}
	return fmt.Sprintf("@@ -%d,%d +%d,%d @@", h.OldStart, h.OldLines, h.NewStart, h.NewLines)
}

// hunkTitle is hunkHead with the path, or the path alone for a hunk of
// notes only.
func hunkTitle(h core.Hunk, path string) string {
	if head := hunkHead(h); head != "" {
		return head + " " + path
	}
	return path
}
