// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"slices"
	"strings"
	"testing"
)

// recHooks records every call the evaluator resolves.
type recHooks struct{ calls []*callSite }

func (r *recHooks) call(_ *scope, c *callSite) taint         { r.calls = append(r.calls, c); return taint{} }
func (r *recHooks) include(*scope, res, [2]int, int, string) {}
func (r *recHooks) read(*scope, string, int) taint           { return taint{} }
func (r *recHooks) propagates(string) bool                   { return false }

func streamFor(l lang, src string) *stream {
	if l == langPHP {
		return phpStream([]byte(src))
	}
	return jsStream([]byte(src))
}

// calls evaluates src as one body and returns each resolved callee as
// "name" plus " (folded)" and " via <fn>" when they apply.
func calls(l lang, src string) []string {
	st := streamFor(l, src)
	h := &recHooks{}
	f := &fileCtx{st: st, h: h, skip: map[int]int{}, budget: 1 << 20}
	if l == langJS {
		f.aliases = jsAliases(st)
	}
	s := newScope(f, "")
	s.walk(0, len(st.toks))
	var out []string
	for _, c := range h.calls {
		d := c.name
		if c.folded {
			d += " (folded)"
		}
		if c.via != "" {
			d += " via " + c.via
		}
		out = append(out, d)
	}
	return out
}

// foldOf folds the value of "$v = <expr>;" (PHP) or "v = <expr>;" (JS).
func foldOf(l lang, expr string) (string, bool) {
	src := "<?php $v = " + expr + ";"
	key := "$v"
	if l == langJS {
		src, key = "v = "+expr+";", "v"
	}
	st := streamFor(l, src)
	f := &fileCtx{st: st, h: &recHooks{}, skip: map[int]int{}, budget: 1 << 20}
	s := newScope(f, "")
	s.walk(0, len(st.toks))
	v, ok := s.env[key]
	if !ok {
		return "", false
	}
	return v.str()
}

func TestFoldEvasions(t *testing.T) {
	tests := []struct {
		name string
		l    lang
		src  string
		want string // a call that must be among the resolved ones
	}{
		{"built decoder name", langPHP, `<?php $f='base'.'64_decode'; eval($f($x));`, "base64_decode (folded)"},
		{"comment between eval and paren", langPHP, `<?php eval /* c */ (base64_decode($x));`, "eval"},
		{"hash comment between eval and paren", langPHP, "<?php eval # c\n (base64_decode($x));", "eval"},
		{"built assert", langPHP, `<?php $a="as"."sert"; $a(base64_decode($x));`, "assert (folded)"},
		{"call_user_func of a built name", langPHP, `<?php call_user_func('ev'.'al', base64_decode($x));`, "eval (folded) via call_user_func"},
		{"call_user_func of a literal", langPHP, `<?php call_user_func('system', $c);`, "system via call_user_func"},
		{"array_map callback", langPHP, `<?php array_map('sys'.'tem', $cmds);`, "system (folded) via array_map"},
		{"str_rot13", langPHP, `<?php $f = str_rot13('flfgrz'); $f($c);`, "system (folded)"},
		{"strrev", langPHP, `<?php $f = strrev('tressa'); $f($c);`, "assert (folded)"},
		{"implode", langPHP, `<?php $f = implode('', ['sy', 'st', 'em']); $f($c);`, "system (folded)"},
		{"implode legacy order", langPHP, `<?php $f = implode(array('sy', 'stem'), ''); $f($c);`, "system (folded)"},
		{"chr chain", langPHP, `<?php $f = chr(115).chr(121).chr(115).chr(0x74).chr(101).chr(109); $f($c);`, "system (folded)"},
		{"base64 of a name", langPHP, `<?php $f = base64_decode('c3lzdGVt'); $f($c);`, "system (folded)"},
		{"str_replace", langPHP, `<?php $f = str_replace('X', '', 'sXysXtXem'); $f($c);`, "system (folded)"},
		{"str_replace arrays", langPHP, `<?php $f = str_replace(['1','2'], ['s','t'], '1ys2em'); $f($c);`, "system (folded)"},
		{"sprintf", langPHP, `<?php $f = sprintf('%s%s', 'sys', 'tem'); $f($c);`, "system (folded)"},
		{"sprintf numbered", langPHP, `<?php $f = sprintf('%2$s%1$s', 'tem', 'sys'); $f($c);`, "system (folded)"},
		{"append", langPHP, `<?php $f = 'sys'; $f .= 'tem'; $f($c);`, "system (folded)"},
		{"through two variables", langPHP, `<?php $p = 'sys'; $q = $p . 'tem'; $q($c);`, "system (folded)"},
		{"interpolated string", langPHP, `<?php $p = 'sys'; $q = "{$p}tem"; $q($c);`, "system (folded)"},
		{"variable variable", langPHP, `<?php $n = 'f'; $f = 'system'; $$n($c);`, "system (folded)"},
		{"leading backslash", langPHP, `<?php \SYSTEM($c);`, "system"},
		{"js join", langJS, `window[['e','v','a','l'].join('')](x)`, "eval (folded)"},
		{"js fromCharCode", langJS, `globalThis[String.fromCharCode(101,118,97,108)](x)`, "eval (folded)"},
		{"js variable", langJS, `const f = ['e','v','a','l'].join(''); global[f](x)`, "eval (folded)"},
		{"js split reverse join", langJS, `self['lave'.split('').reverse().join('')](x)`, "eval (folded)"},
		{"js atob", langJS, `window[atob('ZXZhbA==')](x)`, "eval (folded)"},
		{"js Buffer", langJS, `global[Buffer.from('ZXZhbA==', 'base64').toString()](x)`, "eval (folded)"},
		{"js concat", langJS, `window['ev' + 'al'](x)`, "eval (folded)"},
		{"js template", langJS, "window[`${'ev'}al`](x)", "eval (folded)"},
		{"js indirect eval", langJS, `(0, eval)(x)`, "eval (folded)"},
		{"js escaped name", langJS, `eval(x)`, "eval"},
		{"js member", langJS, `window.eval(x)`, "eval"},
		{"js call method", langJS, `eval.call(null, x)`, "eval via call"},
		{"js module alias", langJS, `const cp = require('child_process'); cp.exec(x)`, "child_process.exec"},
		{"js destructured alias", langJS, `const { exec: run } = require('node:child_process'); run(x)`, "child_process.exec"},
		{"js import alias", langJS, `import { spawn } from 'child_process'; spawn(x)`, "child_process.spawn"},
		{"js inline require", langJS, `require('child_process').execSync(x)`, "child_process.execSync"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := calls(tc.l, tc.src)
			if !slices.Contains(got, tc.want) {
				t.Errorf("calls %q, want %q among them", got, tc.want)
			}
		})
	}
}

func TestFoldUnknown(t *testing.T) {
	tests := []struct {
		name string
		l    lang
		src  string
		bad  string // a resolved name that must not appear
	}{
		{"non-literal concatenation", langPHP, `<?php $f = 'sys' . $y; $f($c);`, "system (folded)"},
		{"request callee", langPHP, `<?php $f = $_GET['f']; $f($c);`, "system (folded)"},
		{"reassigned", langPHP, `<?php $f = 'system'; $f = get_option('x'); $f($c);`, "system (folded)"},
		{"js unknown join", langJS, `window[[a,'v','a','l'].join('')](x)`, "eval (folded)"},
		{"js unknown variable", langJS, `window[name](x)`, "eval (folded)"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := calls(tc.l, tc.src)
			if slices.Contains(got, tc.bad) {
				t.Errorf("calls %q should not hold %q", got, tc.bad)
			}
		})
	}
}

func TestFoldValues(t *testing.T) {
	tests := []struct {
		l          lang
		expr, want string
		ok         bool
	}{
		{langPHP, `'https://' . 'evil' . '.example/x'`, "https://evil.example/x", true},
		{langPHP, `"a" . 1 . 'b'`, "a1b", true},
		{langPHP, `strtoupper('abc')`, "ABC", true},
		{langPHP, `hex2bin('6576616c')`, "eval", true},
		{langPHP, `'a' . $unknown`, "", false},
		{langPHP, `sprintf('%5s', 'a')`, "", false},
		{langJS, `'a' + 1 + 'b'`, "a1b", true},
		{langJS, `1 + 2`, "3", true},
		{langJS, `'abc'.toUpperCase()`, "ABC", true},
		{langJS, `'a-b'.replace('-', '.')`, "a.b", true},
		{langJS, `['a','b'].concat(['c']).join('')`, "abc", true},
		{langJS, `x + 'a'`, "", false},
	}
	for _, tc := range tests {
		got, ok := foldOf(tc.l, tc.expr)
		if ok != tc.ok || got != tc.want {
			t.Errorf("fold(%s) = %q, %v; want %q, %v", tc.expr, got, ok, tc.want, tc.ok)
		}
	}
}

func TestFoldLimits(t *testing.T) {
	// More than 16 steps in one expression gives up.
	parts := make([]string, 20)
	for i := range parts {
		parts[i] = "'a'"
	}
	if _, ok := foldOf(langPHP, strings.Join(parts, " . ")); ok {
		t.Errorf("20 concatenations should exceed the step budget")
	}
	if _, ok := foldOf(langPHP, strings.Join(parts[:10], " . ")); !ok {
		t.Errorf("10 concatenations are within the budget")
	}
	// A result over 64 KiB is not kept.
	big := "'" + strings.Repeat("a", 40<<10) + "'"
	if _, ok := foldOf(langPHP, big+" . "+big); ok {
		t.Errorf("an 80 KiB result should not fold")
	}
	// The budget is per statement: three statements of 10 steps each
	// all fold.
	got := calls(langPHP, "<?php $a = "+strings.Join(parts[:10], " . ")+"; $b = "+strings.Join(parts[:10], " . ")+
		"; $f = 'sys' . 'tem'; $f($c);")
	if !slices.Contains(got, "system (folded)") {
		t.Errorf("the budget should reset per statement: %q", got)
	}
	if v, ok := decodeBase64(strings.Repeat("QUFB", maxFoldBytes)); ok || v != "" {
		t.Errorf("an oversized base64 literal should not decode")
	}
}
