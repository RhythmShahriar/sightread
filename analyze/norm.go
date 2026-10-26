// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"strings"

	"github.com/RhythmShahriar/sightread/lex/js"
	"github.com/RhythmShahriar/sightread/lex/php"
)

// lang is the language of a token stream.
type lang uint8

const (
	langPHP lang = iota
	langJS
)

// tkind is the class of a normalised token.
type tkind uint8

const (
	tName  tkind = iota // identifier or keyword
	tVar                // PHP $variable
	tStr                // string literal piece
	tNum                // number
	tPunct              // operator or punctuation
	tTag                // PHP open or close tag or inline HTML: ends a statement
	tOther              // regular expression, cast and the like
)

// tok is one significant token of either language. Comments and
// whitespace are gone, so `eval /* x */ (` reads as `eval (`.
// Interpolated strings and template literals are rewritten as the
// concatenation they mean: "a{$b}c" becomes ( "a" . ( $b ) . "c" ) and
// `a${b}c` becomes ( "a" + ( b ) + "c" ), so folding and taint tracking
// need no string special case.
//
// A 4 MiB minified file has millions of tokens, so the fields are
// ordered to pack: the two one-byte fields share the last word.
type tok struct {
	text  string // source text; for a PHP name lower case without a leading \
	raw   string // a name as written, for display
	val   string // a tStr's value
	line  int
	off   int
	k     tkind
	known bool // a tStr's value is exact
}

func (t tok) is(k tkind, text string) bool { return t.k == k && t.text == text }

func (t tok) punct(text string) bool { return t.k == tPunct && t.text == text }

// stream is a normalised token stream with its bracket matches.
type stream struct {
	lang  lang
	toks  []tok
	match []int32 // index of the matching bracket, or len(toks) when unbalanced; int32 halves it
	clk   *clock  // the file's time budget, ticked by the walk
	// deep is set when the walk skipped an expression nested deeper
	// than maxEvalDepth: what it holds was not evaluated, so the file
	// is listed as unanalysed rather than passed as clean.
	deep bool
}

func newStream(l lang, toks []tok) *stream {
	s := &stream{lang: l, toks: toks, match: make([]int32, len(toks))}
	var stack []int
	for i, t := range toks {
		s.match[i] = -1
		if t.k != tPunct {
			continue
		}
		switch t.text {
		case "(", "[", "{":
			stack = append(stack, i)
		case ")", "]", "}":
			// Pop to the nearest opener of the same family so one stray
			// bracket does not shift every later match.
			open := opener(t.text)
			for k := len(stack) - 1; k >= 0; k-- {
				if toks[stack[k]].text == open {
					s.match[stack[k]] = int32(i) // #nosec G115 -- a token index is far below 2^31
					s.match[i] = int32(stack[k]) // #nosec G115 -- as above
					stack = stack[:k]
					break
				}
			}
		}
	}
	for _, i := range stack {
		s.match[i] = int32(len(toks)) // #nosec G115 -- input is capped far below 2^31 tokens
	}
	return s
}

func opener(closer string) string {
	switch closer {
	case ")":
		return "("
	case "]":
		return "["
	}
	return "{"
}

// close returns the index of the bracket that closes the one at i, or
// len(toks) when it never closes.
func (s *stream) close(i int) int {
	if i < len(s.match) && int(s.match[i]) > i {
		return int(s.match[i])
	}
	return len(s.toks)
}

// normPHP turns PHP lexer tokens into a normalised stream. Error tokens
// are dropped: the caller reports that part as unanalysed.
func normPHP(src []php.Token) []tok {
	out := make([]tok, 0, len(src)/2)
	var add func(ts []php.Token)
	add = func(ts []php.Token) {
		for _, t := range ts {
			switch t.Kind {
			case php.Whitespace, php.Comment, php.Attribute, php.Error:
			case php.InlineHTML, php.OpenTag, php.CloseTag:
				out = append(out, tok{k: tTag, text: t.Text, line: t.Line, off: t.Off})
			case php.Variable:
				out = append(out, tok{k: tVar, text: t.Text, line: t.Line, off: t.Off})
			case php.Identifier, php.Keyword:
				raw := strings.TrimPrefix(t.Text, `\`)
				out = append(out, tok{k: tName, text: strings.ToLower(raw), raw: raw, line: t.Line, off: t.Off})
			case php.Number:
				out = append(out, tok{k: tNum, text: t.Text, line: t.Line, off: t.Off})
			case php.Cast:
				out = append(out, tok{k: tOther, text: strings.ToLower(strings.ReplaceAll(t.Text, " ", "")), line: t.Line, off: t.Off})
			case php.Operator, php.Punct:
				out = append(out, tok{k: tPunct, text: t.Text, line: t.Line, off: t.Off})
			case php.String:
				shell := strings.HasPrefix(t.Text, "`")
				if shell {
					// A backtick string runs a shell command: it is
					// shell_exec() of its text.
					out = append(out, tok{k: tName, text: "shell_exec", line: t.Line, off: t.Off},
						tok{k: tPunct, text: "(", line: t.Line, off: t.Off})
				}
				if v, ok := php.StringValue(t); ok {
					out = append(out, tok{k: tStr, text: t.Text, val: v, known: true, line: t.Line, off: t.Off})
				} else {
					segs := php.Segments(t)
					out = append(out, tok{k: tPunct, text: "(", line: t.Line, off: t.Off})
					for i, sg := range segs {
						if i > 0 {
							out = append(out, tok{k: tPunct, text: ".", line: sg.Line, off: t.Off})
						}
						if sg.Code == nil {
							out = append(out, tok{k: tStr, text: t.Text, val: sg.Lit, known: true, line: sg.Line, off: t.Off})
							continue
						}
						out = append(out, tok{k: tPunct, text: "(", line: sg.Line, off: t.Off})
						add(sg.Code)
						out = append(out, tok{k: tPunct, text: ")", line: sg.Line, off: t.Off})
					}
					if len(segs) == 0 {
						out = append(out, tok{k: tStr, text: t.Text, line: t.Line, off: t.Off})
					}
					out = append(out, tok{k: tPunct, text: ")", line: t.Line, off: t.Off})
				}
				if shell {
					out = append(out, tok{k: tPunct, text: ")", line: t.Line, off: t.Off})
				}
			}
		}
	}
	add(src)
	return out
}

// normJS turns JavaScript lexer tokens into a normalised stream.
func normJS(src []js.Token) []tok {
	n := 0
	for _, t := range src {
		if t.Kind != js.Whitespace && t.Kind != js.Comment {
			n++
		}
	}
	// A minified bundle has no whitespace to drop: size the stream once.
	out := make([]tok, 0, n+n/16)
	for _, t := range src {
		switch t.Kind {
		case js.Whitespace, js.Comment, js.Error:
		case js.Identifier, js.Keyword:
			name := js.IdentName(t)
			out = append(out, tok{k: tName, text: name, raw: name, line: t.Line, off: t.Off})
		case js.Number:
			out = append(out, tok{k: tNum, text: t.Text, line: t.Line, off: t.Off})
		case js.RegExp:
			out = append(out, tok{k: tOther, text: t.Text, line: t.Line, off: t.Off})
		case js.Punct:
			out = append(out, tok{k: tPunct, text: t.Text, line: t.Line, off: t.Off})
		case js.String:
			v, _ := js.StringValue(t)
			out = append(out, tok{k: tStr, text: t.Text, val: v, known: true, line: t.Line, off: t.Off})
		case js.Template:
			lit, _ := js.TemplateText(t)
			s := tok{k: tStr, text: t.Text, val: lit, known: true, line: t.Line, off: t.Off}
			p := func(x string) tok { return tok{k: tPunct, text: x, line: t.Line, off: t.Off} }
			head := t.Text[0] == '`'
			tail := strings.HasSuffix(t.Text, "`") && len(t.Text) >= 2 && !strings.HasSuffix(t.Text, "${")
			switch {
			case head && tail: // no substitutions
				out = append(out, s)
			case head:
				out = append(out, p("("), s, p("+"), p("("))
			case tail:
				out = append(out, p(")"), p("+"), s, p(")"))
			default:
				out = append(out, p(")"), p("+"), s, p("+"), p("("))
			}
		}
	}
	return out
}

// phpStream lexes and normalises PHP source.
func phpStream(src []byte) *stream { return newStream(langPHP, normPHP(php.Lex(src))) }

// jsStream lexes and normalises JavaScript source.
func jsStream(src []byte) *stream { return newStream(langJS, normJS(js.Lex(src))) }
