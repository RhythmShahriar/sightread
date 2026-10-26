// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package js

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// bundle builds a minified one-line bundle of at least n bytes in the
// shape webpack and esbuild emit: a module table of arrow functions with
// short names, regexes, templates and string tables. It is generated
// here, not copied from a real package.
func bundle(n int) []byte {
	var b strings.Builder
	b.WriteString(`(()=>{"use strict";var __webpack_modules__={`)
	for i := 0; b.Len() < n; i++ {
		id := strconv.Itoa(i)
		b.WriteString(id + `:(e,t,r)=>{r.d(t,{a:()=>o` + id + `});const n=/^[a-z0-9_-]{3,16}$/i,s="x`)
		b.WriteString(id + `";function o` + id + `(e){if(!n.test(e))throw new Error(` + "`bad ${e} in " + id + "`" + `);`)
		b.WriteString(`return e.split("").map((c,i)=>c.charCodeAt(0)^i%7).reduce((a,b)=>a+b/2,0)>>>1}`)
		b.WriteString(`let l=[1,2,3].filter(x=>x/2>1&&x%3!==0),u={k:` + id + `,v:s+"-"+l.length};e.exports=u},`)
	}
	b.WriteString(`};var r=t=>__webpack_modules__[t]({}, {}, {d(){}});r(0)})();`)
	return []byte(b.String())
}

func BenchmarkLexJS(b *testing.B) {
	src := bundle(4 << 20)
	b.SetBytes(int64(len(src)))
	b.ResetTimer()
	for b.Loop() {
		_ = Lex(src)
	}
}

func TestBundleLexesClean(t *testing.T) {
	src := bundle(256 << 10)
	toks := Lex(src)
	checkTokens(t, string(src), toks)
	for _, tk := range toks {
		if tk.Kind == Error {
			t.Fatalf("bundle has an Error token at %d: %q", tk.Off, clip(tk.Text))
		}
	}
}

// TestMinifiedBundleTime lexes a 5 MiB one-line bundle within a second.
func TestMinifiedBundleTime(t *testing.T) {
	src := bundle(5 << 20)
	if strings.Contains(string(src), "\n") {
		t.Fatal("the bundle should be one line")
	}
	// Best of three, so one slow moment on a shared runner does not fail it.
	var toks []Token
	best := time.Hour
	for range 3 {
		start := time.Now()
		toks = Lex(src)
		best = min(best, time.Since(start))
	}
	if best > time.Second*raceSlowdown {
		t.Errorf("5 MiB bundle took %v", best)
	}
	if len(toks) == 0 || toks[len(toks)-1].End() != len(src) {
		t.Errorf("tokens do not cover the bundle")
	}
}
