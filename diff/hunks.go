// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package diff

import (
	"bytes"
	"context"
	"fmt"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
)

// NoNewline is the line that follows a hunk line whose unit is the last
// of its file and has no newline, as git writes it. Applying a hunk drops
// the newline of the line before it.
const NoNewline = `\ No newline at end of file`

// NotePrefix starts a hunk line that is a note from Sightread rather
// than package text: NoNewline and the binary file line.
const NotePrefix = `\ `

// hunkWork bounds the effort of one file's line diff; see script.
const hunkWork = 64 << 20

// Hunks returns the hunks of the change at path (its new path, or the
// old one for a removed file) with contextLines of context. They are
// computed from the blobs on demand, so a report only pays for the
// files it shows.
//
// A change with nothing to read gives no hunks: a rename by hash, a mode
// change or a change of line endings only. A binary file gives one hunk
// with the note `\ binary file changed (<old size> to <new size>)`. A
// minified file (or any line over 64 KiB) is compared in tokens cut at
// punctuation; those hunks are for reading, since the tokens are not
// lines.
func (Differ) Hunks(ctx context.Context, d *core.Diff, path string, contextLines int) ([]core.Hunk, error) {
	if d == nil {
		return nil, fmt.Errorf("hunks of %s: no diff", path)
	}
	c, ok := findChange(d, path)
	if !ok {
		return nil, fmt.Errorf("hunks of %s: the path did not change", path)
	}
	if c.EOLOnly || c.Kind == core.ModeChanged || c.Kind == core.Renamed && c.Old.SHA256 == c.New.SHA256 {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	old, err := readSide(d.Old, c.Old)
	if err != nil {
		return nil, fmt.Errorf("hunks of %s: %w", path, err)
	}
	new, err := readSide(d.New, c.New)
	if err != nil {
		return nil, fmt.Errorf("hunks of %s: %w", path, err)
	}
	if binaryChange(c, old, new) {
		return []core.Hunk{{
			Path:  path,
			Lines: []string{NotePrefix + "binary file changed (" + size(int64(len(old))) + " to " + size(int64(len(new))) + ")"},
		}}, nil
	}
	tokens := c.Old != nil && c.Old.Kind == core.KindMinified || c.New != nil && c.New.Kind == core.KindMinified
	return LineHunks(path, old, new, contextLines, tokens), nil
}

// findChange finds the change whose new path, or old path when it has no
// new one, is path.
func findChange(d *core.Diff, path string) (core.FileChange, bool) {
	for _, c := range d.Changes {
		if c.New != nil && c.New.Path == path {
			return c, true
		}
	}
	for _, c := range d.Changes {
		if c.New == nil && c.Old != nil && c.Old.Path == path {
			return c, true
		}
	}
	return core.FileChange{}, false
}

// readSide reads f from t, or nothing when f is nil (an added or
// removed file).
func readSide(t *core.Tree, f *core.File) ([]byte, error) {
	if f == nil {
		return nil, nil
	}
	return readBlob(t, f)
}

// binaryChange reports whether either side is binary: by kind, or by a
// NUL byte in the first 8,000 bytes as git decides.
func binaryChange(c core.FileChange, old, new []byte) bool {
	for _, f := range []*core.File{c.Old, c.New} {
		if f != nil && !textKind(f.Kind) {
			return true
		}
	}
	return hasNUL(old) || hasNUL(new)
}

// hasNUL reports a NUL byte in the first 8,000 bytes of b.
func hasNUL(b []byte) bool { return bytes.IndexByte(b[:min(len(b), 8000)], 0) >= 0 }

// LineHunks diffs old and new as text and returns unified hunks with
// contextLines of context, at least 0. With tokens set, or for lines over
// 64 KiB, the units compared are tokens cut at punctuation. Applying the
// hunks of line units to old gives new.
func LineHunks(path string, old, new []byte, contextLines int, tokens bool) []core.Hunk {
	contextLines = max(contextLines, 0)
	ou, nu := units(old, tokens), units(new, tokens)
	a, b := intern(ou, nu)
	edits := script(a, b, hunkWork+16*(len(a)+len(b)))
	return buildHunks(path, ou, nu, edits, contextLines, tokens)
}

// buildHunks groups the edits into hunks, joining changes whose equal
// stretch between them is at most twice the context.
func buildHunks(path string, ou, nu []string, edits []edit, ctxLines int, tokens bool) []core.Hunk {
	var hunks []core.Hunk
	for i := 0; i < len(edits); {
		if edits[i].kind == opEqual {
			i++
			continue
		}
		// Changes i..j-1 form one hunk; equal runs inside are short.
		j := i
		for j < len(edits) {
			if edits[j].kind == opEqual {
				if j+1 >= len(edits) || edits[j].n > 2*ctxLines {
					break
				}
			}
			j++
		}
		first, last := edits[i], edits[j-1]
		aStart := max(first.a-ctxLines, 0)
		bStart := first.b - (first.a - aStart)
		aEnd := min(last.a+lenA(last)+ctxLines, len(ou))
		bEnd := last.b + lenB(last) + (aEnd - (last.a + lenA(last)))
		h := core.Hunk{Path: path}
		w := hunkWriter{h: &h, ou: ou, nu: nu, tokens: tokens}
		for k := aStart; k < first.a; k++ {
			w.line(' ', ou[k], k == len(ou)-1)
		}
		for _, e := range edits[i:j] {
			for k := 0; k < e.n; k++ {
				switch e.kind {
				case opEqual:
					w.line(' ', ou[e.a+k], e.a+k == len(ou)-1)
				case opDelete:
					w.line('-', ou[e.a+k], e.a+k == len(ou)-1)
				case opInsert:
					w.line('+', nu[e.b+k], e.b+k == len(nu)-1)
				}
			}
		}
		for k := last.a + lenA(last); k < aEnd; k++ {
			w.line(' ', ou[k], k == len(ou)-1)
		}
		h.OldLines, h.NewLines = aEnd-aStart, bEnd-bStart
		h.OldStart, h.NewStart = start(aStart, h.OldLines), start(bStart, h.NewLines)
		hunks = append(hunks, h)
		i = j
	}
	return hunks
}

// lenA is how many old units e covers.
func lenA(e edit) int {
	if e.kind == opInsert {
		return 0
	}
	return e.n
}

// lenB is how many new units e covers.
func lenB(e edit) int {
	if e.kind == opDelete {
		return 0
	}
	return e.n
}

// start is the 1-based line a hunk side starts at; an empty side names
// the line before it, as unified diffs do.
func start(i, n int) int {
	if n == 0 {
		return i
	}
	return i + 1
}

// hunkWriter appends the lines of one hunk.
type hunkWriter struct {
	h      *core.Hunk
	ou, nu []string
	tokens bool
}

// line appends unit u with its mark, without its newline. The last unit
// of a file without a newline gets NoNewline after it.
func (w hunkWriter) line(mark byte, u string, last bool) {
	text := strings.TrimSuffix(u, "\n")
	w.h.Lines = append(w.h.Lines, string(mark)+text)
	if last && !w.tokens && len(text) == len(u) {
		w.h.Lines = append(w.h.Lines, NoNewline)
	}
}

// size writes n bytes for the binary file note.
func size(n int64) string {
	switch {
	case n < 1<<10:
		if n == 1 {
			return "1 byte"
		}
		return fmt.Sprintf("%d bytes", n)
	case n < 1<<20:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	}
}
