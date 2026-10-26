// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package js

import (
	"fmt"
	"strings"
	"testing"
)

// checkTokens asserts the lexer invariants: the tokens cover src exactly
// with strictly increasing offsets and lines match the newlines before
// each token.
func checkTokens(t testing.TB, src string, toks []Token) {
	t.Helper()
	if err := verify(src, toks); err != nil {
		t.Fatalf("%v\nsrc: %q", err, clip(src))
	}
}

func verify(src string, toks []Token) error {
	off, line, lineAt := 0, 1, 0
	for i, tk := range toks {
		if tk.Off != off {
			return fmt.Errorf("token %d (%s %q) at %d, want %d", i, tk.Kind, clip(tk.Text), tk.Off, off)
		}
		if tk.Text == "" {
			return fmt.Errorf("token %d (%s) is empty at %d", i, tk.Kind, tk.Off)
		}
		if src[tk.Off:tk.End()] != tk.Text {
			return fmt.Errorf("token %d text differs from the source", i)
		}
		line += strings.Count(src[lineAt:tk.Off], "\n")
		lineAt = tk.Off
		if tk.Line != line {
			return fmt.Errorf("token %d (%s %q) on line %d, want %d", i, tk.Kind, clip(tk.Text), tk.Line, line)
		}
		off = tk.End()
	}
	if off != len(src) {
		return fmt.Errorf("tokens end at %d, want %d", off, len(src))
	}
	return nil
}

func clip(s string) string {
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}

func sig(toks []Token) []string {
	var out []string
	for _, t := range toks {
		if t.Significant() {
			out = append(out, t.Kind.String()+":"+t.Text)
		}
	}
	return out
}

func lex(t *testing.T, src string) []Token {
	t.Helper()
	toks := Lex([]byte(src))
	checkTokens(t, src, toks)
	return toks
}

func TestLexKinds(t *testing.T) {
	tests := []struct {
		name, src string
		want      []string
	}{
		{"regex after return", "return /a\\/b[/]/gi.test(x)", []string{
			"Keyword:return", `RegExp:/a\/b[/]/gi`, "Punct:.", "Identifier:test", "Punct:(", "Identifier:x", "Punct:)"}},
		{"division after identifier", "a = b / c / d", []string{
			"Identifier:a", "Punct:=", "Identifier:b", "Punct:/", "Identifier:c", "Punct:/", "Identifier:d"}},
		{"division after paren and number", "(a) / 2 / (1 / x)", []string{
			"Punct:(", "Identifier:a", "Punct:)", "Punct:/", "Number:2", "Punct:/", "Punct:(", "Number:1", "Punct:/", "Identifier:x", "Punct:)"}},
		{"regex after operator and comma", "x = f(a, /'/g) || /\"/", []string{
			"Identifier:x", "Punct:=", "Identifier:f", "Punct:(", "Identifier:a", "Punct:,", "RegExp:/'/g", "Punct:)", "Punct:||", `RegExp:/"/`}},
		{"regex after block close", "if (a) { b() }\n/re/.test(s)", []string{
			"Keyword:if", "Punct:(", "Identifier:a", "Punct:)", "Punct:{", "Identifier:b", "Punct:(", "Punct:)", "Punct:}",
			"RegExp:/re/", "Punct:.", "Identifier:test", "Punct:(", "Identifier:s", "Punct:)"}},
		{"division after object close", "x = {a: 1} / 2", []string{
			"Identifier:x", "Punct:=", "Punct:{", "Identifier:a", "Punct::", "Number:1", "Punct:}", "Punct:/", "Number:2"}},
		{"keyword after dot is a name", "a.return / 2; this / 2", []string{
			"Identifier:a", "Punct:.", "Identifier:return", "Punct:/", "Number:2", "Punct:;", "Keyword:this", "Punct:/", "Number:2"}},
		{"unclosed regex is division", "a = (b) /x\n", []string{"Identifier:a", "Punct:=", "Punct:(", "Identifier:b", "Punct:)", "Punct:/", "Identifier:x"}},
		{"nested template", "`a${ `b${ c }d` }e${ {x:1}.x }f`", []string{
			"Template:`a${", "Template:`b${", "Identifier:c", "Template:}d`", "Template:}e${", "Punct:{", "Identifier:x", "Punct::", "Number:1", "Punct:}",
			"Punct:.", "Identifier:x", "Template:}f`"}},
		{"template without substitution", "t = `x\\`y $ {z}`", []string{"Identifier:t", "Punct:=", "Template:`x\\`y $ {z}`"}},
		{"comments", "#!/usr/bin/env node\n// one\n/* two */ a", []string{"Identifier:a"}},
		{"numbers", "0x1F 0o17 0b1 1_000n 1.5e-3 .5 10n", []string{
			"Number:0x1F", "Number:0o17", "Number:0b1", "Number:1_000n", "Number:1.5e-3", "Number:.5", "Number:10n"}},
		{"punctuation", "a >>>= b ?? c?.d ?.5 : e ... f", []string{
			"Identifier:a", "Punct:>>>=", "Identifier:b", "Punct:??", "Identifier:c", "Punct:?.", "Identifier:d", "Punct:?", "Number:.5",
			"Punct::", "Identifier:e", "Punct:...", "Identifier:f"}},
		{"unicode escapes and private names", `eval(x); this.#k; $el; ñame`, []string{
			`Identifier:eval`, "Punct:(", "Identifier:x", "Punct:)", "Punct:;", "Keyword:this", "Punct:.", "Identifier:#k", "Punct:;",
			"Identifier:$el", "Punct:;", "Identifier:ñame"}},
		{"jsx", "const el = <p className=\"a\">{x / 2}</p>;", []string{
			"Keyword:const", "Identifier:el", "Punct:=", "Punct:<", "Identifier:p", "Identifier:className", "Punct:=", `String:"a"`, "Punct:>",
			"Punct:{", "Identifier:x", "Punct:/", "Number:2", "Punct:}", "Punct:<", "Punct:/", "Identifier:p", "Punct:>", "Punct:;"}},
		{"strings", `'a\'b' "c\"d" 'line\
cont'`, []string{`String:'a\'b'`, `String:"c\"d"`, "String:'line\\\ncont'"}},
		{"regex after if head", "if (x) /'/.test(s) && eval(location.hash);", []string{
			"Keyword:if", "Punct:(", "Identifier:x", "Punct:)", "RegExp:/'/", "Punct:.", "Identifier:test", "Punct:(", "Identifier:s", "Punct:)",
			"Punct:&&", "Identifier:eval", "Punct:(", "Identifier:location", "Punct:.", "Identifier:hash", "Punct:)", "Punct:;"}},
		{"regex after while, for and with heads", "while (a) /x/g; for (;;) /y/; with (o) /z/", []string{
			"Keyword:while", "Punct:(", "Identifier:a", "Punct:)", "RegExp:/x/g", "Punct:;",
			"Keyword:for", "Punct:(", "Punct:;", "Punct:;", "Punct:)", "RegExp:/y/", "Punct:;",
			"Keyword:with", "Punct:(", "Identifier:o", "Punct:)", "RegExp:/z/"}},
		{"regex after a head with nested parens", "if (f(a) && (b)) /re/.test(c)", []string{
			"Keyword:if", "Punct:(", "Identifier:f", "Punct:(", "Identifier:a", "Punct:)", "Punct:&&", "Punct:(", "Identifier:b", "Punct:)", "Punct:)",
			"RegExp:/re/", "Punct:.", "Identifier:test", "Punct:(", "Identifier:c", "Punct:)"}},
		{"division after a call", "f(x) / 2 / g", []string{
			"Identifier:f", "Punct:(", "Identifier:x", "Punct:)", "Punct:/", "Number:2", "Punct:/", "Identifier:g"}},
		{"division after a method named if", "a.if(x) / 2 / b", []string{
			"Identifier:a", "Punct:.", "Identifier:if", "Punct:(", "Identifier:x", "Punct:)", "Punct:/", "Number:2", "Punct:/", "Identifier:b"}},
		{"division inside an if head", "if (a / b) / c", []string{
			"Keyword:if", "Punct:(", "Identifier:a", "Punct:/", "Identifier:b", "Punct:)", "Punct:/", "Identifier:c"}},
		{"line separator ends a line comment", "// hi\u2028eval(location.hash);", []string{
			"Identifier:eval", "Punct:(", "Identifier:location", "Punct:.", "Identifier:hash", "Punct:)", "Punct:;"}},
		{"paragraph separator ends a line comment", "// hi\u2029require('child_process')", []string{
			"Identifier:require", "Punct:(", "String:'child_process'", "Punct:)"}},
		{"line separator ends the hashbang", "#!/usr/bin/env node\u2028eval(x)", []string{
			"Identifier:eval", "Punct:(", "Identifier:x", "Punct:)"}},
		{"unicode spaces separate tokens", "\u00a0eval\u3000(\u2000y\u202f)\ufeff;\u1680", []string{
			"Identifier:eval", "Punct:(", "Identifier:y", "Punct:)", "Punct:;"}},
		{"regex ends at a line separator", "return /a\u2028/", []string{"Keyword:return", "Punct:/", "Identifier:a", "Punct:/"}},
		{"line separator inside a string is text", "s = 'a\u2028b'", []string{"Identifier:s", "Punct:=", "String:'a\u2028b'"}},
		{"other non-ASCII stays in a name", "caf\u00e9 = \u03c0", []string{"Identifier:caf\u00e9", "Punct:=", "Identifier:\u03c0"}},
		{"an open quote hides nothing", "x = 'a; eval(y)", []string{
			"Identifier:x", "Punct:=", "Error:'", "Identifier:a", "Punct:;", "Identifier:eval", "Punct:(", "Identifier:y", "Punct:)"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sig(lex(t, tc.src))
			if strings.Join(got, "\n") != strings.Join(tc.want, "\n") {
				t.Errorf("tokens:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(tc.want, "\n"))
			}
		})
	}
}

func TestLexErrors(t *testing.T) {
	tests := []struct {
		name, src, construct string
		line                 int
		rest                 bool // the Error token runs to the end; else it is one quote
	}{
		{"unterminated template", "a\n`abc ${x}\n eval(y)", "template", 2, true},
		{"unterminated substitution", "a\n`abc ${ f(\n eval(y)", "template", 2, true},
		{"unterminated nested template", "`a${ `b${ c }", "template", 1, true},
		{"unterminated comment", "x\n/* eval(y)", "comment", 2, true},
		{"unterminated string ends at the line", "s = 'abc\neval(y)", "string", 1, false},
		{"string open at the end", `s = "abc\`, "string", 1, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			toks := lex(t, tc.src)
			var e *Token
			for i := range toks {
				if toks[i].Kind == Error {
					e = &toks[i]
					break
				}
			}
			if e == nil {
				t.Fatalf("no Error token in %v", sig(toks))
			}
			if got := e.Construct(); got != tc.construct {
				t.Errorf("construct %q, want %q", got, tc.construct)
			}
			if e.Line != tc.line {
				t.Errorf("line %d, want %d", e.Line, tc.line)
			}
			if (e.End() == len(tc.src)) != tc.rest {
				t.Errorf("error token %q: runs to the end = %v, want %v", e.Text, e.End() == len(tc.src), tc.rest)
			}
			if !tc.rest && len(e.Text) != 1 {
				t.Errorf("an open quote should be a one-byte Error token, got %q", e.Text)
			}
			if !tc.rest && toks[len(toks)-1].Kind == Error {
				t.Errorf("lexing should go on after the quote: %v", sig(toks))
			}
		})
	}
}

func TestValues(t *testing.T) {
	tests := []struct{ src, want string }{
		{`'a\x41B\u{1F600}\n\101'`, "aAB\U0001F600\nA"},
		{`"q\"\\"`, `q"\`},
		{"`t\\`x`", "t`x"},
		{"'line\\\ncont'", "linecont"},
	}
	for _, tc := range tests {
		toks := lex(t, tc.src)
		v, ok := StringValue(toks[0])
		if !ok || v != tc.want {
			t.Errorf("StringValue(%s) = %q, %v; want %q", tc.src, v, ok, tc.want)
		}
	}
	toks := lex(t, "`a${b}c`")
	if _, ok := StringValue(toks[0]); ok {
		t.Errorf("a template head has no single value")
	}
	if v, _ := TemplateText(toks[0]); v != "a" {
		t.Errorf("head text %q", v)
	}
	if v, _ := TemplateText(toks[2]); v != "c" {
		t.Errorf("tail text %q", v)
	}
	if got := IdentName(lex(t, `ev\u{61}l`)[0]); got != "eval" {
		t.Errorf("IdentName = %q", got)
	}
	if Kind(99).String() != "Kind(?)" || RegExp.String() != "RegExp" {
		t.Errorf("kind names")
	}
}
