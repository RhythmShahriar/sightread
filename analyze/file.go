// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"slices"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/lex/js"
	"github.com/RhythmShahriar/sightread/lex/php"
)

// codeFeatures returns every feature of one PHP or JavaScript file:
// data flows and the capabilities extraction finds. ctx is the file's
// context (pathContext). The result is sorted by line, kind and key.
func codeFeatures(l lang, path string, src []byte, ctx string) []core.Feature {
	lines := newLineIndex(src)
	var st *stream
	var ptoks []php.Token
	var jtoks []js.Token
	if l == langPHP {
		ptoks = php.Lex(src)
		st = newStream(langPHP, normPHP(ptoks))
	} else {
		jtoks = js.Lex(src)
		st = newStream(langJS, normJS(jtoks))
	}
	col := newCollector(path, ctx, lines)
	ex := newExtractor(st, col)
	out := runFlow(st, lines, path, ctx, ex)
	ex.finish()
	if l == langPHP {
		ex.phpHosts(ptoks)
	} else {
		ex.jsHosts(jtoks)
	}
	out = append(out, col.out...)
	sortFeatures(out)
	return out
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
