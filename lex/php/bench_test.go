// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package php

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// corpus builds a WordPress-style input of at least n bytes from the
// templates in testdata/gen, numbering each copy so no two are equal.
// The templates are written for this test, not copied from a plugin.
func corpus(tb testing.TB, n int) []byte {
	tb.Helper()
	files, err := filepath.Glob(filepath.Join("testdata", "gen", "*.php.tmpl"))
	if err != nil || len(files) == 0 {
		tb.Fatalf("no templates: %v", err)
	}
	var tmpls []string
	for _, f := range files {
		b, err := os.ReadFile(f) // #nosec G304 -- test templates
		if err != nil {
			tb.Fatal(err)
		}
		tmpls = append(tmpls, string(b))
	}
	var b strings.Builder
	for i := 0; b.Len() < n; i++ {
		b.WriteString(strings.ReplaceAll(tmpls[i%len(tmpls)], "__N__", strconv.Itoa(i)))
		b.WriteString("\n")
	}
	return []byte(b.String())
}

func BenchmarkLexPHP(b *testing.B) {
	src := corpus(b, 4<<20)
	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for b.Loop() {
		_ = Lex(src)
	}
}

func TestCorpusLexesClean(t *testing.T) {
	src := corpus(t, 256<<10)
	toks := Lex(src)
	checkTokens(t, string(src), toks)
	for _, tk := range toks {
		if tk.Kind == Error {
			t.Fatalf("corpus has an Error token at line %d: %q", tk.Line, clip(tk.Text))
		}
	}
}

// TestLexThroughput guards the lexer's speed on the generated corpus.
// The target is 50 MB/s per core (BenchmarkLexPHP measures it); shared
// CI runners vary, so by default the test fails only below half of
// that, which still catches any super-linear or allocation regression.
// SIGHTREAD_PERF=1 (make bench, the release checklist) holds it to the
// full target. It takes the best of a few runs and skips under -short
// and -race.
func TestLexThroughput(t *testing.T) {
	if testing.Short() || raceSlowdown > 1 {
		t.Skip("throughput is measured without -short and -race")
	}
	src := corpus(t, 4<<20)
	best := time.Duration(1 << 62)
	for range 5 {
		start := time.Now()
		_ = Lex(src)
		best = min(best, time.Since(start))
	}
	mbs := float64(len(src)) / best.Seconds() / 1e6
	t.Logf("%.0f MB/s", mbs)
	floor := 25.0
	if os.Getenv("SIGHTREAD_PERF") == "1" {
		floor = 50
	}
	if mbs < floor {
		t.Errorf("lexed at %.0f MB/s, want at least %.0f", mbs, floor)
	}
}
