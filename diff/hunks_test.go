// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package diff

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// apply applies unified hunks to old the way patch does and fails on a
// context or removed line that doesn't match.
func apply(old string, hunks []core.Hunk) (string, error) {
	lines := strings.SplitAfter(old, "\n")
	if lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	var out []byte
	pos := 0
	for _, h := range hunks {
		at := h.OldStart - 1
		if h.OldLines == 0 {
			at = h.OldStart
		}
		if at < pos || at > len(lines) {
			return "", fmt.Errorf("hunk at %d after %d of %d lines", h.OldStart, pos, len(lines))
		}
		for _, l := range lines[pos:at] {
			out = append(out, l...)
		}
		pos = at
		prev := byte(0)
		for _, l := range h.Lines {
			if l == NoNewline {
				if prev == ' ' || prev == '+' {
					out = out[:len(out)-1]
				}
				continue
			}
			prev = l[0]
			switch l[0] {
			case ' ', '-':
				if pos >= len(lines) || strings.TrimSuffix(lines[pos], "\n") != l[1:] {
					return "", fmt.Errorf("line %d is not %q", pos+1, l)
				}
				pos++
				if l[0] == ' ' {
					out = append(out, l[1:]+"\n"...)
				}
			case '+':
				out = append(out, l[1:]+"\n"...)
			default:
				return "", fmt.Errorf("bad hunk line %q", l)
			}
		}
	}
	for _, l := range lines[pos:] {
		out = append(out, l...)
	}
	return string(out), nil
}

// hunks diffs old and new as one file f.txt and returns its hunks.
func hunks(t testing.TB, path, old, new string, ctxLines int) []core.Hunk {
	t.Helper()
	ot, nt := coretest.Tree(map[string]string{path: old}), coretest.Tree(map[string]string{path: new})
	d, err := Differ{}.Diff(context.Background(), ot, nt)
	if err != nil {
		t.Fatal(err)
	}
	h, err := Differ{}.Hunks(context.Background(), d, path, ctxLines)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestHunkShape(t *testing.T) {
	old := "a\nb\nc\nd\ne\nf\ng\nh\ni\nj\n"
	got := hunks(t, "f.txt", old, strings.Replace(old, "e\n", "E\n", 1), 3)
	want := []core.Hunk{{
		Path: "f.txt", OldStart: 2, OldLines: 7, NewStart: 2, NewLines: 7,
		Lines: []string{" b", " c", " d", "-e", "+E", " f", " g", " h"},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("hunks = %+v\nwant %+v", got, want)
	}
}

func TestHunksJoinAndSplit(t *testing.T) {
	old := numbered("l", 40)
	near := strings.Replace(strings.Replace(old, "l 10\n", "x\n", 1), "l 15\n", "y\n", 1)
	if h := hunks(t, "f.txt", old, near, 3); len(h) != 1 {
		t.Errorf("changes 5 lines apart: %d hunks, want 1", len(h))
	}
	far := strings.Replace(strings.Replace(old, "l 10\n", "x\n", 1), "l 30\n", "y\n", 1)
	if h := hunks(t, "f.txt", old, far, 3); len(h) != 2 {
		t.Errorf("changes 20 lines apart: %d hunks, want 2", len(h))
	}
	if h := hunks(t, "f.txt", old, far, 0); len(h) != 2 || len(h[0].Lines) != 2 {
		t.Errorf("no context: %+v", h)
	}
}

func TestHunksAddedAndRemoved(t *testing.T) {
	ot := coretest.Tree(map[string]string{"gone.txt": "a\nb\n"})
	nt := coretest.Tree(map[string]string{"new.txt": "x\n"})
	d, err := Differ{}.Diff(context.Background(), ot, nt)
	if err != nil {
		t.Fatal(err)
	}
	h, err := Differ{}.Hunks(context.Background(), d, "new.txt", 3)
	if err != nil || len(h) != 1 || h[0].OldStart != 0 || h[0].NewStart != 1 || !reflect.DeepEqual(h[0].Lines, []string{"+x"}) {
		t.Errorf("added: %+v, %v", h, err)
	}
	h, err = Differ{}.Hunks(context.Background(), d, "gone.txt", 3)
	if err != nil || len(h) != 1 || h[0].NewStart != 0 || !reflect.DeepEqual(h[0].Lines, []string{"-a", "-b"}) {
		t.Errorf("removed: %+v, %v", h, err)
	}
	if _, err := (Differ{}).Hunks(context.Background(), d, "other.txt", 3); err == nil {
		t.Error("a path that did not change gave no error")
	}
	if _, err := (Differ{}).Hunks(context.Background(), nil, "new.txt", 3); err == nil {
		t.Error("a nil diff gave no error")
	}
}

func TestHunksNoNewline(t *testing.T) {
	got := hunks(t, "f.txt", "a\nb", "a\nc", 1)
	want := []string{" a", "-b", NoNewline, "+c", NoNewline}
	if len(got) != 1 || !reflect.DeepEqual(got[0].Lines, want) {
		t.Errorf("hunks = %+v, want lines %q", got, want)
	}
	got = hunks(t, "f.txt", "a\nb", "a\nb\n", 1)
	if out, err := apply("a\nb", got); err != nil || out != "a\nb\n" {
		t.Errorf("adding the last newline: %q, %v (%+v)", out, err, got)
	}
}

func TestHunksQuietChanges(t *testing.T) {
	if h := hunks(t, "f.php", "<?php\nx();\n", "<?php\r\nx();\r\n", 3); h != nil {
		t.Errorf("line endings only: %+v, want no hunks", h)
	}
	ot := coretest.Tree(map[string]string{"a.php": "<?php\n"})
	nt := coretest.Tree(map[string]string{"b.php": "<?php\n"})
	d, _ := Differ{}.Diff(context.Background(), ot, nt)
	if h, err := (Differ{}).Hunks(context.Background(), d, "b.php", 3); err != nil || h != nil {
		t.Errorf("rename by hash: %+v, %v; want no hunks", h, err)
	}
}

func TestHunksBinary(t *testing.T) {
	old := "\x00" + strings.Repeat("a", 2047)
	new := "\x00" + strings.Repeat("b", 3*1024*1024)
	h := hunks(t, "logo.bin", old, new, 3)
	want := []core.Hunk{{Path: "logo.bin", Lines: []string{`\ binary file changed (2.0 KiB to 3.0 MiB)`}}}
	if !reflect.DeepEqual(h, want) {
		t.Errorf("hunks = %+v, want %+v", h, want)
	}
	// An asset is binary by kind even without a NUL byte.
	h = hunks(t, "logo.png", "PNG1", "PNG22", 3)
	if len(h) != 1 || h[0].Lines[0] != `\ binary file changed (4 bytes to 5 bytes)` {
		t.Errorf("asset: %+v", h)
	}
	// A text file is not.
	if h := hunks(t, "a.txt", "one\n", "two\n", 3); len(h) != 1 || h[0].Lines[0] != "-one" {
		t.Errorf("text: %+v", h)
	}
}

func TestSize(t *testing.T) {
	for n, want := range map[int64]string{0: "0 bytes", 1: "1 byte", 1023: "1023 bytes", 1536: "1.5 KiB", 5 << 20: "5.0 MiB"} {
		if got := size(n); got != want {
			t.Errorf("size(%d) = %q, want %q", n, got, want)
		}
	}
}

// bundle is a minified script of n statements on one line.
func bundle(n int, change func(i int) string) string {
	var b strings.Builder
	b.WriteString("!function(){")
	for i := range n {
		s := fmt.Sprintf("var a%d=f(%d);", i, i)
		if change != nil {
			if c := change(i); c != "" {
				s = c
			}
		}
		b.WriteString(s)
	}
	b.WriteString("}();")
	return b.String()
}

func TestHunksMinifiedTokens(t *testing.T) {
	old := bundle(5000, nil)
	new := bundle(5000, func(i int) string {
		if i == 2500 {
			return `fetch("https://example.test/x");`
		}
		return ""
	})
	h := hunks(t, "dist/app.min.js", old, new, 2)
	if len(h) != 1 {
		t.Fatalf("%d hunks, want 1", len(h))
	}
	want := []string{" var a2498=f(2498);", " var a2499=f(2499);", "-var a2500=f(2500);", `+fetch("https://example.test/x");`, " var a2501=f(2501);", " var a2502=f(2502);"}
	if !reflect.DeepEqual(h[0].Lines, want) {
		t.Errorf("lines = %q, want %q", h[0].Lines, want)
	}
}

func TestHunksLongLineTokens(t *testing.T) {
	// A text file with one line over 64 KiB is cut into tokens too.
	long := strings.Repeat("x=1;", maxLine/4+10)
	old := "<?php\n$a = '" + long + "';\nend();\n"
	new := "<?php\n$a = '" + strings.Replace(long, "x=1;", "x=2;", 1) + "';\nend();\n"
	h := hunks(t, "big.php", old, new, 1)
	if len(h) != 1 {
		t.Fatalf("%d hunks, want 1", len(h))
	}
	for _, l := range h[0].Lines {
		if len(l) > maxToken+1 {
			t.Errorf("hunk line of %d bytes, want tokens", len(l))
		}
	}
	// A long line without punctuation is cut every maxToken bytes.
	if u := units([]byte(strings.Repeat("a", 3*maxToken+5)), true); len(u) != 4 || len(u[0]) != maxToken {
		t.Errorf("units of a long word: %d", len(u))
	}
}

func TestScriptRepeatedLines(t *testing.T) {
	// Lines that occur over maxChain times give no anchor, so the region
	// falls back to Myers.
	old := strings.Repeat("}\n", 200) + "a\n" + strings.Repeat("}\n", 200)
	new := strings.Repeat("}\n", 150) + "b\n" + strings.Repeat("}\n", 251)
	h := hunks(t, "f.txt", old, new, 3)
	if got, err := apply(old, h); err != nil || got != new {
		t.Fatalf("apply: %v", err)
	}
}

func TestScriptWorkBound(t *testing.T) {
	// With no work left every region is a plain replacement, still a
	// correct script.
	a, b := intern(units([]byte("a\nb\nc\nd\n"), false), units([]byte("a\nx\nc\nd\ny\n"), false))
	for _, work := range []int{0, 1, 1 << 20} {
		edits := script(a, b, work)
		var na, nb int
		for _, e := range edits {
			na += lenA(e)
			nb += lenB(e)
		}
		if na != len(a) || nb != len(b) {
			t.Errorf("work %d: script covers %d and %d units, want %d and %d", work, na, nb, len(a), len(b))
		}
	}
}

func TestMyersLimit(t *testing.T) {
	// Two regions with nothing in common in a repeated frame give up
	// after maxMyersD edits and still apply.
	var ob, nb strings.Builder
	for i := range 400 {
		fmt.Fprintf(&ob, "}\no%d\n", i%3)
		fmt.Fprintf(&nb, "}\nn%d\n", i%3)
	}
	h := hunks(t, "f.txt", ob.String(), nb.String(), 3)
	if got, err := apply(ob.String(), h); err != nil || got != nb.String() {
		t.Fatalf("apply: %v", err)
	}
}

func FuzzDiff(f *testing.F) {
	f.Add("a\nb\nc\n", "a\nc\nd\n", uint8(3))
	f.Add("", "x", uint8(0))
	f.Add("x\ny", "x\ny\n", uint8(1))
	f.Add("}\n}\n}\na\n}\n", "}\nb\n}\n}\n}\n", uint8(2))
	f.Add("one\r\ntwo\r\n", "one\ntwo\n", uint8(3))
	f.Add(numbered("l", 50), strings.Replace(numbered("l", 50), "l 7\n", "", 1)+"tail", uint8(3))
	f.Fuzz(func(t *testing.T, old, new string, ctxLines uint8) {
		if old == new || strings.ContainsRune(old+new, 0) || len(old) > maxLine || len(new) > maxLine {
			return
		}
		ot := coretest.Tree(map[string]string{"f.txt": old})
		nt := coretest.Tree(map[string]string{"f.txt": new})
		d, err := Differ{}.Diff(context.Background(), ot, nt)
		if err != nil {
			t.Fatal(err)
		}
		h, err := Differ{}.Hunks(context.Background(), d, "f.txt", int(ctxLines%8))
		if err != nil {
			t.Fatal(err)
		}
		if d.Changes[0].EOLOnly {
			if !eolOnly([]byte(old), []byte(new)) || h != nil {
				t.Fatalf("EOLOnly with hunks %+v", h)
			}
			return
		}
		got, err := apply(old, h)
		if err != nil {
			t.Fatalf("apply: %v\nhunks %+v", err, h)
		}
		if got != new {
			t.Fatalf("apply gave %q, want %q\nhunks %+v", got, new, h)
		}
	})
}
