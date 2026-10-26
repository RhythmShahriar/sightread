// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package js

import "strings"

// braceKind is what an open brace on the stack belongs to.
type braceKind uint8

const (
	braceBlock    braceKind = iota // a statement block or a class body
	braceObject                    // an object literal or a destructuring pattern
	braceTemplate                  // a template substitution ${...}
)

type brace struct {
	kind braceKind
	head int // for a template: index of the token that opened the template
}

type lexer struct {
	src  string
	pos  int
	toks []Token

	lpos, line int // line is the line of offset lpos

	stack []brace

	// The previous significant token decides whether a slash starts a
	// regular expression and whether a brace opens a block.
	prevKind    Kind
	prevText    string
	havePrev    bool
	closedBlock bool // the previous token was a } that closed a block
	member      bool // the previous token was . or ?.

	// noRegexUntil stops a slash from being tried as a regular
	// expression again on a line where that already failed, which keeps
	// a crafted line of "(/[" from costing quadratic time.
	noRegexUntil int
}

// Lex splits src into tokens. It never fails: the tokens always cover
// src exactly with strictly increasing offsets. Lexing is linear in
// len(src) and never runs the code.
//
// Whether a slash starts a regular expression or is a division is
// decided by the previous significant token, as a parser would. JSX is
// tolerated: < and > are punctuation and text between tags is lexed as
// code, which can only produce harmless tokens.
//
// Unterminated constructs: a block comment or template literal (or a
// template substitution left open) turns the rest of the input into
// one Error token. A string cannot span lines in JavaScript, so an
// unterminated one is an Error token up to the end of its line and
// lexing goes on. A regular expression that does not close on its line
// was a division after all and is lexed as one.
func Lex(src []byte) []Token {
	l := &lexer{src: string(src), line: 1}
	// Minified bundles run near one token per two bytes; reserving that
	// up front avoids copying a large slice as it grows.
	l.toks = make([]Token, 0, len(src)/2+4)
	l.run()
	return l.toks
}

func (l *lexer) lineOf(off int) int {
	if off > l.lpos {
		seg := l.src[l.lpos:off]
		if len(seg) < 32 {
			for i := 0; i < len(seg); i++ {
				if seg[i] == '\n' {
					l.line++
				}
			}
		} else {
			l.line += strings.Count(seg, "\n")
		}
		l.lpos = off
	}
	return l.line
}

func (l *lexer) emit(k Kind, start int) {
	t := Token{Kind: k, Off: start, Line: l.lineOf(start), Text: l.src[start:l.pos]}
	l.toks = append(l.toks, t)
	if !t.Significant() || k == Error {
		return
	}
	l.prevKind, l.prevText, l.havePrev = k, t.Text, true
	l.member = k == Punct && (t.Text == "." || t.Text == "?.")
	l.closedBlock = false
}

// fail drops the tokens from index mark on and makes the rest of the
// input one Error token starting at off.
func (l *lexer) fail(mark, off int) {
	line := l.lineOf(off)
	if mark < len(l.toks) {
		line = l.toks[mark].Line
	}
	l.toks = append(l.toks[:mark], Token{Kind: Error, Off: off, Line: line, Text: l.src[off:]})
	l.pos = len(l.src)
	l.stack = l.stack[:0]
}

func (l *lexer) run() {
	s := l.src
	n := len(s)
	if strings.HasPrefix(s, "#!") {
		l.pos = lineEnd(s, 0)
		l.emit(Comment, 0)
	}
	for l.pos < n {
		start := l.pos
		c := s[start]
		var next byte
		if start+1 < n {
			next = s[start+1]
		}
		switch {
		case isSpace(c):
			l.pos++
			for l.pos < n && isSpace(s[l.pos]) {
				l.pos++
			}
			l.emit(Whitespace, start)
		case c == '/' && next == '/':
			l.pos = lineEnd(s, start)
			l.emit(Comment, start)
		case c == '/' && next == '*':
			end := strings.Index(s[start+2:], "*/")
			if end < 0 {
				l.fail(len(l.toks), start)
				return
			}
			l.pos = start + 2 + end + 2
			l.emit(Comment, start)
		case c == '/' && start >= l.noRegexUntil && l.regexAllowed() && l.regex():
		case c == '\'' || c == '"':
			l.str(c)
		case c == '`':
			if !l.template(start, len(l.toks)) {
				return
			}
		case c == '}' && len(l.stack) > 0 && l.stack[len(l.stack)-1].kind == braceTemplate:
			head := l.stack[len(l.stack)-1].head
			l.stack = l.stack[:len(l.stack)-1]
			if !l.template(start, head) {
				return
			}
		case c == '{':
			k := braceObject
			if l.braceOpensBlock() {
				k = braceBlock
			}
			l.stack = append(l.stack, brace{kind: k})
			l.pos++
			l.emit(Punct, start)
		case c == '}':
			block := true
			if len(l.stack) > 0 {
				block = l.stack[len(l.stack)-1].kind == braceBlock
				l.stack = l.stack[:len(l.stack)-1]
			}
			l.pos++
			l.emit(Punct, start)
			l.closedBlock = block
		case isIdentStart(c) || (c == '\\' && next == 'u') || (c == '#' && isIdentStart(next)):
			l.ident()
		case isDigit(c) || (c == '.' && isDigit(next)):
			l.number()
		default:
			l.punct()
		}
	}
	// A template substitution still open at the end: everything from
	// the outermost open template on is unterminated.
	for _, b := range l.stack {
		if b.kind == braceTemplate {
			off := l.toks[b.head].Off
			l.fail(b.head, off)
			return
		}
	}
}

func lineEnd(s string, j int) int {
	for j < len(s) && s[j] != '\n' && s[j] != '\r' {
		j++
	}
	return j
}

func (l *lexer) regexAllowed() bool {
	if !l.havePrev {
		return true
	}
	switch l.prevKind {
	case Punct:
		switch l.prevText {
		case ")", "]", "++", "--":
			return false
		case "}":
			return l.closedBlock
		}
		return true
	case Keyword:
		return !l.member && regexAfter[l.prevText]
	case Template:
		return strings.HasSuffix(l.prevText, "${")
	}
	return false
}

// braceOpensBlock tells a block from an object literal by what precedes
// the brace. Only the regex rule after "}" depends on it.
func (l *lexer) braceOpensBlock() bool {
	if !l.havePrev {
		return true
	}
	switch l.prevKind {
	case Punct:
		switch l.prevText {
		case ")", ";", "{", "}", "=>":
			return true
		}
		return false
	case Keyword:
		switch l.prevText {
		case "return", "typeof", "case", "delete", "in", "instanceof", "new", "throw", "void", "yield", "await":
			return false
		}
		return true
	case Template:
		return !strings.HasSuffix(l.prevText, "${")
	}
	return true
}

// regex lexes a regular expression literal at l.pos, or reports false
// when it does not close on its line.
func (l *lexer) regex() bool {
	s := l.src
	start := l.pos
	j := start + 1
	class := false
	for {
		if j >= len(s) || s[j] == '\n' || s[j] == '\r' {
			l.noRegexUntil = j
			return false
		}
		switch s[j] {
		case '\\':
			j++
			if j < len(s) && (s[j] == '\n' || s[j] == '\r') {
				l.noRegexUntil = j
				return false
			}
		case '[':
			class = true
		case ']':
			class = false
		case '/':
			if !class {
				j++
				for j < len(s) && isIdentChar(s[j]) {
					j++
				}
				l.pos = j
				l.emit(RegExp, start)
				return true
			}
		}
		j++
	}
}

// str lexes a quoted string. One left open at the end of its line is an
// Error token up to the line break.
func (l *lexer) str(q byte) {
	s := l.src
	start := l.pos
	j := start + 1
	set := "'\\\n\r"
	if q == '"' {
		set = "\"\\\n\r"
	}
	for {
		k := strings.IndexAny(s[j:], set)
		if k < 0 {
			l.pos = len(s)
			l.emit(Error, start)
			return
		}
		j += k
		switch s[j] {
		case q:
			l.pos = j + 1
			l.emit(String, start)
			return
		case '\\':
			// A backslash escapes the next character; before a line
			// break it continues the string on the next line.
			if strings.HasPrefix(s[j+1:], "\r\n") {
				j += 3
			} else {
				j += 2
			}
			if j > len(s) {
				l.pos = len(s)
				l.emit(Error, start)
				return
			}
		default:
			l.pos = j
			l.emit(Error, start)
			return
		}
	}
}

// template lexes template text from start (a backtick, or the } closing
// a substitution) up to the closing backtick or the next "${". head is
// the index of the token that opened the whole template, so an
// unterminated one can be turned into a single Error token.
func (l *lexer) template(start, head int) bool {
	s := l.src
	j := start + 1
	for {
		k := strings.IndexAny(s[j:], "`\\$")
		if k < 0 {
			l.fail(head, l.errOff(head, start))
			return false
		}
		j += k
		switch s[j] {
		case '`':
			l.pos = j + 1
			l.emit(Template, start)
			return true
		case '\\':
			j += 2
			if j > len(s) {
				l.fail(head, l.errOff(head, start))
				return false
			}
		default:
			if j+1 < len(s) && s[j+1] == '{' {
				l.pos = j + 2
				l.emit(Template, start)
				l.stack = append(l.stack, brace{kind: braceTemplate, head: head})
				return true
			}
			j++
		}
	}
}

// errOff is where the Error token of an unterminated template starts:
// at its head token when that was emitted, else at start.
func (l *lexer) errOff(head, start int) int {
	if head < len(l.toks) {
		return l.toks[head].Off
	}
	return start
}

func (l *lexer) ident() {
	s := l.src
	start := l.pos
	j := start
	if s[j] == '#' {
		j++
	}
	escaped := false
	for j < len(s) {
		if isIdentChar(s[j]) {
			j++
			continue
		}
		if s[j] == '\\' && j+1 < len(s) && s[j+1] == 'u' {
			if e := unicodeEscapeEnd(s, j); e > 0 {
				j = e
				escaped = true
				continue
			}
		}
		break
	}
	if j == start {
		// A lone "\u" that is not a valid escape.
		j++
	}
	l.pos = j
	k := Identifier
	if !escaped && !l.member && isKeyword(s[start:j]) {
		k = Keyword
	}
	l.emit(k, start)
}

// unicodeEscapeEnd returns the end of a \uXXXX or \u{X...} escape at j,
// or 0 when it is not one.
func unicodeEscapeEnd(s string, j int) int {
	k := j + 2
	if k < len(s) && s[k] == '{' {
		e := k + 1
		for e < len(s) && e-k <= 7 && isHex(s[e]) {
			e++
		}
		if e > k+1 && e < len(s) && s[e] == '}' {
			return e + 1
		}
		return 0
	}
	if k+4 <= len(s) && isHex(s[k]) && isHex(s[k+1]) && isHex(s[k+2]) && isHex(s[k+3]) {
		return k + 4
	}
	return 0
}

func (l *lexer) number() {
	s := l.src
	n := len(s)
	start := l.pos
	j := start
	if s[j] == '0' && j+1 < n && (s[j+1]|0x20 == 'x' || s[j+1]|0x20 == 'o' || s[j+1]|0x20 == 'b') {
		j += 2
		for j < n && (isHex(s[j]) || s[j] == '_') {
			j++
		}
	} else {
		for j < n && (isDigit(s[j]) || s[j] == '_') {
			j++
		}
		if j < n && s[j] == '.' {
			j++
			for j < n && (isDigit(s[j]) || s[j] == '_') {
				j++
			}
		}
		if j < n && s[j]|0x20 == 'e' {
			k := j + 1
			if k < n && (s[k] == '+' || s[k] == '-') {
				k++
			}
			if k < n && isDigit(s[k]) {
				j = k
				for j < n && (isDigit(s[j]) || s[j] == '_') {
					j++
				}
			}
		}
	}
	if j < n && s[j] == 'n' {
		j++ // BigInt
	}
	l.pos = j
	l.emit(Number, start)
}

var punct4 = map[string]bool{">>>=": true}

var punct3 = map[string]bool{
	"===": true, "!==": true, "**=": true, "<<=": true, ">>=": true,
	">>>": true, "...": true, "&&=": true, "||=": true, "??=": true,
}

var punct2 = map[string]bool{
	"=>": true, "==": true, "!=": true, "<=": true, ">=": true, "&&": true,
	"||": true, "??": true, "++": true, "--": true, "+=": true, "-=": true,
	"*=": true, "/=": true, "%=": true, "&=": true, "|=": true, "^=": true,
	"**": true, "<<": true, ">>": true,
}

func (l *lexer) punct() {
	start := l.pos
	rest := l.src[start:]
	switch {
	case len(rest) >= 4 && punct4[rest[:4]]:
		l.pos += 4
	case len(rest) >= 3 && punct3[rest[:3]]:
		l.pos += 3
	case strings.HasPrefix(rest, "?.") && (len(rest) == 2 || !isDigit(rest[2])):
		l.pos += 2
	case len(rest) >= 2 && punct2[rest[:2]]:
		l.pos += 2
	default:
		l.pos++
	}
	l.emit(Punct, start)
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

func isHex(c byte) bool { return isDigit(c) || ('a' <= c|0x20 && c|0x20 <= 'f') }

// identClass marks identifier bytes: 1 for bytes that may start a name
// (letters, _, $ and any byte from 0x80, so UTF-8 names are one
// identifier), 2 for digits.
var identClass = func() (t [256]uint8) {
	for c := range 256 {
		switch {
		case ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || c == '_' || c == '$' || c >= 0x80:
			t[c] = 1
		case isDigit(byte(c)):
			t[c] = 2
		}
	}
	return t
}()

func isIdentStart(c byte) bool { return identClass[c] == 1 }

func isIdentChar(c byte) bool { return identClass[c] != 0 }
