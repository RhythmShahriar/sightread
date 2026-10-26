// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"context"
	"slices"
	"strconv"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/lex/js"
	"github.com/RhythmShahriar/sightread/lex/php"
)

// codeFeatures returns every feature of one PHP or JavaScript file:
// data flows, the capabilities extraction finds, hosts and encoded
// blobs with what their payloads do. ctx is the file's context
// (pathContext). The result is sorted by line, kind and key.
func codeFeatures(l lang, path string, src []byte, ctx string) []core.Feature {
	fs, _ := analyzeCode(l, path, src, ctx, decodeEnv{budget: newDecodeBudget(), layers: maxLayers})
	return fs
}

// The Unanalysed reasons of a code file, besides reasonDecodeLimit.
const (
	reasonTimeLimit = "analysis time limit"
	reasonUnread    = "could not read the file"
)

// reasonUnterminated is the Unanalysed reason of a lexer Error token:
// "unterminated heredoc at line 12".
func reasonUnterminated(construct string, line int) string {
	return "unterminated " + construct + " at line " + strconv.Itoa(line)
}

// checkEvery is how many tokens the analysis walks between two looks at
// the clock: often enough to stop close to the budget, rarely enough to
// cost nothing.
const checkEvery = 64 << 10

// clock is one file's analysis time budget (Limits.FileBudget). The
// walk ticks it with the tokens it reads and looks at the context's
// deadline every checkEvery tokens; once over, every phase stops and
// the file is Unanalysed with reasonTimeLimit. A nil clock never runs
// out. One file's analysis runs on one goroutine, so it needs no lock.
type clock struct {
	ctx   context.Context
	count int
	over  bool
}

func newClock(ctx context.Context) *clock { return &clock{ctx: ctx} }

// tick counts n tokens and reports whether the budget is spent.
func (c *clock) tick(n int) bool {
	if c == nil {
		return false
	}
	if c.over {
		return true
	}
	c.count += n
	if c.count >= checkEvery {
		c.count = 0
		c.over = c.ctx.Err() != nil
	}
	return c.over
}

// expired looks at the deadline now and reports whether it passed.
func (c *clock) expired() bool {
	if c == nil {
		return false
	}
	if !c.over && c.ctx.Err() != nil {
		c.over = true
	}
	return c.over
}

// analyzeCode is codeFeatures with a decode budget shared by a package
// and the file's clock. It also returns why the file, or part of it,
// was not analysed: a lexer Error token (the code before it is still
// analysed), a blob that hit a decode limit, the time budget. Features
// found before the budget ran out are kept.
func analyzeCode(l lang, path string, src []byte, ctx string, env decodeEnv) ([]core.Feature, []core.Unanalysed) {
	lines := newLineIndex(src)
	var st *stream
	var ptoks []php.Token
	var jtoks []js.Token
	var un []core.Unanalysed
	if l == langPHP {
		ptoks = php.Lex(src)
		if t, ok := phpError(ptoks); ok && ctx != core.CtxDecoded {
			un = append(un, core.Unanalysed{Path: path, Reason: reasonUnterminated(t.Construct(), t.Line)})
		}
		st = newStream(langPHP, normPHP(ptoks))
	} else {
		jtoks = js.Lex(src)
		if t, ok := jsError(jtoks, len(src)); ok && ctx != core.CtxDecoded {
			un = append(un, core.Unanalysed{Path: path, Reason: reasonUnterminated(t.Construct(), t.Line)})
		}
		st = newStream(langJS, normJS(jtoks))
	}
	timeUp := func(out []core.Feature) ([]core.Feature, []core.Unanalysed) {
		sortFeatures(out)
		return out, append(un, core.Unanalysed{Path: path, Reason: reasonTimeLimit})
	}
	// Lexing is linear and runs before the clock is first read: at the
	// 4 MiB limit it takes a fraction of the budget.
	if env.clk.expired() {
		return timeUp(nil)
	}
	st.clk = env.clk
	col := newCollector(path, ctx, lines)
	ex := newExtractor(st, col)
	ex.own = env.own
	out := runFlow(st, lines, path, ctx, ex)
	if env.clk.expired() {
		return timeUp(append(out, col.out...))
	}
	ex.finish()
	if l == langPHP {
		ex.phpHosts(ptoks)
	} else {
		ex.jsHosts(jtoks)
	}
	unicodeFeatures(col, src, ptoks, jtoks, l == langPHP)
	if env.clk.expired() {
		return timeUp(append(out, col.out...))
	}
	bs := &blobScan{col: col, st: st, path: path, env: env}
	bs.scan()
	out = append(out, col.out...)
	out = append(out, bs.out...)
	sortFeatures(out)
	if bs.un {
		un = append(un, core.Unanalysed{Path: path, Reason: reasonDecodeLimit})
	}
	if env.clk.expired() {
		un = append(un, core.Unanalysed{Path: path, Reason: reasonTimeLimit})
	}
	return out, un
}

// phpError finds the Error token of a PHP file: the lexer turns the
// rest of the file into one when a string, heredoc or comment never
// ends.
func phpError(toks []php.Token) (php.Token, bool) {
	if n := len(toks); n > 0 && toks[n-1].Kind == php.Error {
		return toks[n-1], true
	}
	return php.Token{}, false
}

// jsError finds an Error token that runs to the end of a JavaScript
// file (a comment or template that never ends). An unterminated string
// stops at its line break and lexing goes on, so nothing after it is
// lost and it is not reported.
func jsError(toks []js.Token, size int) (js.Token, bool) {
	if n := len(toks); n > 0 && toks[n-1].Kind == js.Error && toks[n-1].End() == size {
		return toks[n-1], true
	}
	return js.Token{}, false
}

// finish runs the token scans and fills what waited for the whole file.
func (e *extractor) finish() {
	if e.h == nil {
		return
	}
	if e.lang == langPHP {
		e.phpScan()
	} else {
		e.jsScan()
	}
	e.finishSends()
}

// sortFeatures orders features by path, line, kind and key.
func sortFeatures(fs []core.Feature) {
	slices.SortStableFunc(fs, func(a, b core.Feature) int {
		if c := strings.Compare(a.Ev.Path, b.Ev.Path); c != 0 {
			return c
		}
		if a.Ev.Line != b.Ev.Line {
			return a.Ev.Line - b.Ev.Line
		}
		if c := strings.Compare(string(a.Kind), string(b.Kind)); c != 0 {
			return c
		}
		return strings.Compare(a.Key, b.Key)
	})
}
