// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package report

import (
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
)

// A hunk of notes only has no header; a token hunk says so instead of
// numbers; a line hunk keeps its unified header.
func TestHunkHead(t *testing.T) {
	for _, c := range []struct {
		h    core.Hunk
		want string
	}{
		{core.Hunk{Path: "logo.png", Lines: []string{`\ binary file changed (2 KiB to 3 MiB)`}}, "logo.png"},
		{core.Hunk{Path: "a.php", Lines: []string{`\ line endings changed only`}}, "a.php"},
		{core.Hunk{Path: "app.min.js", OldStart: 2499, OldLines: 5, NewStart: 2499, NewLines: 5, Tokens: true, Lines: []string{"+x;"}}, "@@ tokens @@ app.min.js"},
		{core.Hunk{Path: "a.php", OldStart: 3, OldLines: 2, NewStart: 3, NewLines: 3, Lines: []string{" a", "+b", `\ No newline at end of file`}}, "@@ -3,2 +3,3 @@ a.php"},
	} {
		if got := hunkTitle(c.h, c.h.Path); got != c.want {
			t.Errorf("hunkTitle = %q, want %q", got, c.want)
		}
	}
}

// Notes in the HTML have their own class and take no line number, so
// the numbers after them stay right.
func TestHTMLHunkNotes(t *testing.T) {
	h := htmlHunkOf(core.Hunk{Path: "a.php", OldStart: 1, OldLines: 1, NewStart: 1, NewLines: 1,
		Lines: []string{"-a", `\ No newline at end of file`, "+b"}}, nil)
	if len(h.Lines) != 4 || h.Lines[2].Class != "note" || h.Lines[2].Old != "" || h.Lines[2].New != "" || h.Lines[3].New != "1" {
		t.Errorf("lines %+v", h.Lines)
	}
	h = htmlHunkOf(core.Hunk{Path: "a.png", Lines: []string{`\ binary file changed (1 KiB to 2 KiB)`}}, nil)
	if len(h.Lines) != 1 || h.Lines[0].Class != "note" || strings.HasPrefix(h.Lines[0].Text, `\`) {
		t.Errorf("binary %+v", h.Lines)
	}
}

// A finding's line is never matched against token numbers: every hunk
// of the file is taken instead.
func TestCoversTokens(t *testing.T) {
	f := &core.Finding{File: "app.min.js", Line: 1}
	h := core.Hunk{Path: "app.min.js", NewStart: 1, NewLines: 3, Tokens: true}
	if covers(h, f) {
		t.Error("a token hunk covers line 1")
	}
	if got := flagged(&core.Update{Hunks: []core.Hunk{h}}, []*core.Finding{f}); len(got) != 1 {
		t.Errorf("flagged %+v", got)
	}
}
