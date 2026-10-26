// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package php

import (
	"fmt"
	"strings"
	"testing"
)

// checkTokens asserts the lexer invariants: the tokens cover src exactly
// with strictly increasing offsets, lines match the newlines before each
// token and every string's parts cover the string the same way.
func checkTokens(t testing.TB, src string, toks []Token) {
	t.Helper()
	if err := verify(src, 0, len(src), toks); err != nil {
		t.Fatalf("%v\nsrc: %q", err, clip(src))
	}
}

func verify(src string, from, to int, toks []Token) error {
	off := from
	line, lineAt := 1, 0 // line of offset lineAt, counted forward
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
		if want := line; tk.Line != want {
			return fmt.Errorf("token %d (%s %q) on line %d, want %d", i, tk.Kind, clip(tk.Text), tk.Line, want)
		}
		if tk.Kind == Error && i != len(toks)-1 {
			return fmt.Errorf("error token %d is not the last", i)
		}
		if tk.Parts != nil {
			if err := verify(src, tk.Off, tk.End(), tk.Parts); err != nil {
				return fmt.Errorf("parts of token %d: %w", i, err)
			}
		}
		off = tk.End()
	}
	if off != to {
		return fmt.Errorf("tokens end at %d, want %d", off, to)
	}
	return nil
}

func clip(s string) string {
	if len(s) > 120 {
		return s[:120] + "..."
	}
	return s
}

// sig returns "Kind:text" for the significant tokens.
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
		{"open tag and call", "<?php echo strlen($a);", []string{
			"OpenTag:<?php ", "Keyword:echo", "Identifier:strlen", "Punct:(", "Variable:$a", "Punct:)", "Punct:;"}},
		{"html mix", "<b>x</b><?php if ($a): ?>\n<i>y</i>\n<?php endif; ?>tail", []string{
			"InlineHTML:<b>x</b>", "OpenTag:<?php ", "Keyword:if", "Punct:(", "Variable:$a", "Punct:)", "Operator::",
			"CloseTag:?>\n", "InlineHTML:<i>y</i>\n", "OpenTag:<?php ", "Keyword:endif", "Punct:;", "CloseTag:?>", "InlineHTML:tail"}},
		{"short tags", "<? system($c) ?><?= $x ?>", []string{
			"OpenTag:<?", "Identifier:system", "Punct:(", "Variable:$c", "Punct:)", "CloseTag:?>",
			"OpenTag:<?=", "Variable:$x", "CloseTag:?>"}},
		{"upper case open tag", "<?PHP\nEVAL($x);", []string{"OpenTag:<?PHP\n", "Keyword:EVAL", "Punct:(", "Variable:$x", "Punct:)", "Punct:;"}},
		{"comments between eval and paren", "<?php eval /* c */ # x\n // y\n ($x);", []string{
			"OpenTag:<?php ", "Keyword:eval", "Punct:(", "Variable:$x", "Punct:)", "Punct:;"}},
		{"hash comment vs attribute", "<?php # note\n#[Route('/a]b', m: [1])]\nfunction f() {}", []string{
			"OpenTag:<?php ", "Keyword:function", "Identifier:f", "Punct:(", "Punct:)", "Punct:{", "Punct:}"}},
		{"line comment ends at close tag", "<?php // hi ?>html", []string{"OpenTag:<?php ", "CloseTag:?>", "InlineHTML:html"}},
		{"variables", "<?php $$name; ${'a'.'b'}; $this->x;", []string{
			"OpenTag:<?php ", "Variable:$$name", "Punct:;", "Variable:$", "Punct:{", "String:'a'", "Operator:.", "String:'b'", "Punct:}", "Punct:;",
			"Variable:$this", "Operator:->", "Identifier:x", "Punct:;"}},
		{"namespaces", `<?php \Foo\Bar::baz(); namespace\f(); \strlen(1);`, []string{
			"OpenTag:<?php ", `Identifier:\Foo\Bar`, "Operator:::", "Identifier:baz", "Punct:(", "Punct:)", "Punct:;",
			`Identifier:namespace\f`, "Punct:(", "Punct:)", "Punct:;", `Identifier:\strlen`, "Punct:(", "Number:1", "Punct:)", "Punct:;"}},
		{"keywords after arrow are names", "<?php $wpdb->print; Foo::class; Foo::list();", []string{
			"OpenTag:<?php ", "Variable:$wpdb", "Operator:->", "Identifier:print", "Punct:;",
			"Identifier:Foo", "Operator:::", "Identifier:class", "Punct:;",
			"Identifier:Foo", "Operator:::", "Identifier:list", "Punct:(", "Punct:)", "Punct:;"}},
		{"casts", "<?php (int)$a; ( string )$b; (Bool) $c; (foo)", []string{
			"OpenTag:<?php ", "Cast:(int)", "Variable:$a", "Punct:;", "Cast:( string )", "Variable:$b", "Punct:;",
			"Cast:(Bool)", "Variable:$c", "Punct:;", "Punct:(", "Identifier:foo", "Punct:)"}},
		{"numbers", "<?php 0x1F 0b101 0o17 1_000 1.5e-3 .5 7", []string{
			"OpenTag:<?php ", "Number:0x1F", "Number:0b101", "Number:0o17", "Number:1_000", "Number:1.5e-3", "Number:.5", "Number:7"}},
		{"operators", "<?php $a <=> $b ?? $c ?-> d ... **= !== .= @f();", []string{
			"OpenTag:<?php ", "Variable:$a", "Operator:<=>", "Variable:$b", "Operator:??", "Variable:$c", "Operator:?->", "Identifier:d",
			"Operator:...", "Operator:**=", "Operator:!==", "Operator:.=", "Operator:@", "Identifier:f", "Punct:(", "Punct:)", "Punct:;"}},
		{"halt compiler", "<?php __halt_compiler(); <?php eval($x);", []string{
			"OpenTag:<?php ", "Keyword:__halt_compiler", "Punct:(", "Punct:)", "Punct:;", "InlineHTML: <?php eval($x);"}},
		{"halt compiler with close tag", "<?php __halt_compiler() ?>\x00\x01<?php", []string{
			"OpenTag:<?php ", "Keyword:__halt_compiler", "Punct:(", "Punct:)", "CloseTag:?>", "InlineHTML:\x00\x01<?php"}},
		{"no open tag", "just html <? ", []string{"InlineHTML:just html ", "OpenTag:<?"}},
		{"backtick", "<?php `ls $d`;", []string{"OpenTag:<?php ", "String:`ls $d`", "Punct:;"}},
		{"stray bytes", "<?php \\ \x01", []string{"OpenTag:<?php ", `Punct:\`, "Punct:\x01"}},
		// PHP ends a line at a bare \r too: the label after it closes the
		// heredoc and the code after it is code.
		{"heredoc closed after a bare CR", "<?php\n$a = <<<EOT\nx\rEOT;\reval($_POST[\"x\"]);\r$b = 1; // \nEOT;\n", []string{
			"OpenTag:<?php\n", "Variable:$a", "Operator:=", "String:<<<EOT\nx\rEOT", "Punct:;",
			"Keyword:eval", "Punct:(", "Variable:$_POST", "Punct:[", "String:\"x\"", "Punct:]", "Punct:)", "Punct:;",
			"Variable:$b", "Operator:=", "Number:1", "Punct:;", "Identifier:EOT", "Punct:;"}},
		{"nowdoc closed after a bare CR", "<?php $a = <<<'EOT'\nx\rEOT;\reval($x);", []string{
			"OpenTag:<?php ", "Variable:$a", "Operator:=", "String:<<<'EOT'\nx\rEOT", "Punct:;",
			"Keyword:eval", "Punct:(", "Variable:$x", "Punct:)", "Punct:;"}},
		{"heredoc header ends at a bare CR", "<?php $a = <<<EOT\rx\rEOT;\reval($x);", []string{
			"OpenTag:<?php ", "Variable:$a", "Operator:=", "String:<<<EOT\rx\rEOT", "Punct:;",
			"Keyword:eval", "Punct:(", "Variable:$x", "Punct:)", "Punct:;"}},
		{"heredoc with CRLF lines", "<?php $a = <<<EOT\r\nx\r\n  EOT;\r\neval($x);", []string{
			"OpenTag:<?php ", "Variable:$a", "Operator:=", "String:<<<EOT\r\nx\r\n  EOT", "Punct:;",
			"Keyword:eval", "Punct:(", "Variable:$x", "Punct:)", "Punct:;"}},
		{"heredoc label needs a line start", "<?php $a = <<<EOT\nx EOT;\rEOTX;\nEOT;", []string{
			"OpenTag:<?php ", "Variable:$a", "Operator:=", "String:<<<EOT\nx EOT;\rEOTX;\nEOT", "Punct:;"}},
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

func TestLexStrings(t *testing.T) {
	tests := []struct {
		name, src string
		value     string // StringValue of the first string, "" when not literal
		literal   bool
		segs      []string // Segments as "L:text" and "C:code"
	}{
		{"single quoted", `<?php 'it\'s \n \\';`, `it's \n \`, true, nil},
		{"double quoted escapes", `<?php "a\tb\x41\101\u{1F600}\$x\"\q";`, "a\tbAA\U0001F600$x\"\\q", true, nil},
		{"simple interpolation", `<?php "hi $name[0] $o->p {$a['k']} ${v} ${'x'.$y}!";`, "", false, []string{
			"L:hi ", "C:$name[0]", "L: ", "C:$o->p", "L: ", "C:$a['k']", "L: ", "C:${v}", "L: ", "C:${'x'.$y}", "L:!"}},
		{"heredoc with interpolation", "<?php $s = <<<EOT\nHello $who\n  {$x->y()} done\nEOT;\n", "", false, []string{
			"L:Hello ", "C:$who", "L:\n  ", "C:$x->y()", "L: done"}},
		{"indented heredoc", "<?php $s = <<<\"EOT\"\n    a\n      b\\tc\n    EOT;\n", "a\n  b\tc", true, nil},
		{"nowdoc", "<?php $s = <<<'EOT'\n  raw $x {$y} \\n\n  EOT;\n", "raw $x {$y} \\n", true, nil},
		{"empty heredoc", "<?php $s = <<<EOT\nEOT;\n", "", true, nil},
		{"heredoc label prefix is not the end", "<?php $s = <<<EOT\nEOTX\nEOT;\n", "EOTX", true, nil},
		{"nested interpolation", `<?php "{$a["{$b}"]}";`, "", false, []string{`C:$a["{$b}"]`}},
		{"heredoc with CR lines", "<?php $s = <<<EOT\ra\rb\rEOT;", "a\rb", true, nil},
		{"nowdoc with mixed lines", "<?php $s = <<<'EOT'\r\na\nb\rEOT;", "a\nb", true, nil},
		{"indented heredoc with CRLF", "<?php $s = <<<EOT\r\n  a\r\n    b\r\n  EOT;", "a\r\n  b", true, nil},
		{"heredoc with CR and interpolation", "<?php $s = <<<EOT\rHi $who\rEOT;", "", false, []string{"L:Hi ", "C:$who"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			toks := lex(t, tc.src)
			var str *Token
			for i := range toks {
				if toks[i].Kind == String {
					str = &toks[i]
					break
				}
			}
			if str == nil {
				t.Fatalf("no string token in %v", sig(toks))
			}
			v, ok := StringValue(*str)
			if ok != tc.literal || v != tc.value {
				t.Errorf("StringValue = %q, %v; want %q, %v", v, ok, tc.value, tc.literal)
			}
			if tc.segs == nil {
				return
			}
			var got []string
			for _, s := range Segments(*str) {
				if s.Code == nil {
					if s.Lit != "" {
						got = append(got, "L:"+s.Lit)
					}
					continue
				}
				var b strings.Builder
				for _, c := range s.Code {
					b.WriteString(c.Text)
				}
				got = append(got, "C:"+b.String())
			}
			if strings.Join(got, "|") != strings.Join(tc.segs, "|") {
				t.Errorf("segments %q, want %q", got, tc.segs)
			}
		})
	}
}

func TestLexErrors(t *testing.T) {
	tests := []struct {
		name, src, construct string
		line                 int
	}{
		{"unterminated heredoc", "<?php\n$a = 1;\n$s = <<<EOT\nbody\n" + strings.Repeat("pad\n", 50) + "eval($x);\n", "heredoc", 3},
		{"unterminated nowdoc", "<?php $s = <<<'X'\nbody", "nowdoc", 1},
		{"unterminated heredoc with CR lines", "<?php $s = <<<X\rbody\rXY\r", "heredoc", 1},
		{"unterminated double quoted", "<?php\n\"abc {$x} eval($y);", "string", 2},
		{"unterminated single quoted", "<?php 'abc\\'", "string", 1},
		{"unterminated comment", "<?php\n\n/* eval($x);", "comment", 3},
		{"unterminated attribute", "<?php #[A('x'", "attribute", 1},
		{"unterminated shell string", "<?php `rm", "shell string", 1},
		{"unterminated interpolation", "<?php \"a {$b", "string", 1},
		{"string inside interpolation", "<?php \"a {$b['c", "string", 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			toks := lex(t, tc.src)
			last := toks[len(toks)-1]
			if last.Kind != Error {
				t.Fatalf("last token %s %q, want Error", last.Kind, last.Text)
			}
			if got := last.Construct(); got != tc.construct {
				t.Errorf("construct %q, want %q", got, tc.construct)
			}
			if last.Line != tc.line {
				t.Errorf("line %d, want %d", last.Line, tc.line)
			}
		})
	}
}

func TestLexDepthLimit(t *testing.T) {
	// Deeper than MaxDepth: the lexer must stay bounded and still cover
	// the input.
	var b strings.Builder
	b.WriteString("<?php ")
	for range MaxDepth * 3 {
		b.WriteString(`"{$a[`)
	}
	src := b.String()
	toks := lex(t, src)
	if toks[len(toks)-1].Kind != Error {
		t.Errorf("deep unterminated nesting should end in an Error token")
	}
}

func TestTokenHelpers(t *testing.T) {
	toks := lex(t, `<?php \EVAL();`)
	if !toks[1].Is("eval") {
		t.Errorf("Is should ignore case and the leading backslash")
	}
	if toks[2].Is("eval") || Kind(200).String() != "Kind(?)" || Error.String() != "Error" {
		t.Errorf("helpers misreport")
	}
}
