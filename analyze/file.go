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
// data flows, the capabilities extraction finds, hosts and encoded
// blobs with what their payloads do. ctx is the file's context
// (pathContext). The result is sorted by line, kind and key.
func codeFeatures(l lang, path string, src []byte, ctx string) []core.Feature {
	fs, _ := analyzeCode(l, path, src, ctx, decodeEnv{budget: newDecodeBudget(), layers: maxLayers})
	return fs
}

// analyzeCode is codeFeatures with a decode budget shared by a package.
// It also returns the file as Unanalysed when a blob hit a decode
// limit.
func analyzeCode(l lang, path string, src []byte, ctx string, env decodeEnv) ([]core.Feature, []core.Unanalysed) {
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
	bs := &blobScan{col: col, st: st, path: path, env: env}
	bs.scan()
	out = append(out, col.out...)
	out = append(out, bs.out...)
	sortFeatures(out)
	var un []core.Unanalysed
	if bs.un {
		un = append(un, core.Unanalysed{Path: path, Reason: reasonDecodeLimit})
	}
	return out, un
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
