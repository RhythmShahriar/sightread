// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package php

import "strings"

// MaxDepth bounds how deep string interpolation nests ("{$a["{$b}"]}"
// and so on). Deeper "{$" and "${" are read as literal text, so a
// crafted file can never exhaust the stack.
const MaxDepth = 64

// stop is why code() returned.
type stop uint8

const (
	stopEOF   stop = iota // end of input
	stopClose             // a ?> close tag
	stopBrace             // the } that ends an interpolated expression
	stopError             // an unterminated construct; the rest is an Error token
)

type lexer struct {
	src  string
	pos  int
	toks []Token

	// lpos and line count newlines lazily: line is the line of lpos.
	lpos, line int

	depth int // interpolation nesting
	// member is set right after ->, ?-> or ::, where reserved words are
	// plain names ($wpdb->print, Foo::class).
	member bool
}

// Lex splits src into tokens. It never fails: the tokens always cover
// src exactly (their Text joined is src) with strictly increasing
// offsets. An unterminated string, heredoc, nowdoc, comment or
// attribute turns the rest of the input into one Error token. Lexing is
// linear in len(src) and never runs or evaluates the code.
//
// Like PHP, Lex starts in HTML mode: text before the first open tag
// (<?php, <?= or the short <?) is InlineHTML. Everything after
// __halt_compiler(); is InlineHTML too, since PHP stops parsing there.
func Lex(src []byte) []Token {
	l := &lexer{src: string(src), line: 1}
	// About one token per six bytes in typical WordPress code; a close
	// guess saves most slice growth.
	l.toks = make([]Token, 0, len(src)/3+4)
	l.run()
	return l.toks
}

func (l *lexer) run() {
	for l.pos < len(l.src) {
		i := strings.Index(l.src[l.pos:], "<?")
		if i < 0 {
			l.emitRestHTML()
			return
		}
		if i > 0 {
			start := l.pos
			l.pos += i
			l.emit(InlineHTML, start)
		}
		l.openTag()
		if l.code(false) != stopClose {
			return
		}
	}
}

// emitRestHTML makes everything from l.pos one InlineHTML token.
func (l *lexer) emitRestHTML() {
	if l.pos < len(l.src) {
		start := l.pos
		l.pos = len(l.src)
		l.emit(InlineHTML, start)
	}
}

func (l *lexer) lineOf(off int) int {
	if off > l.lpos {
		seg := l.src[l.lpos:off]
		if len(seg) < 32 {
			// Most gaps are one short token: a loop beats the call.
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

// emit appends the token from start to l.pos.
func (l *lexer) emit(k Kind, start int) {
	t := Token{Kind: k, Off: start, Line: l.lineOf(start), Text: l.src[start:l.pos]}
	l.toks = append(l.toks, t)
	if t.Significant() {
		l.member = k == Operator && (t.Text == "->" || t.Text == "?->" || t.Text == "::")
	}
}

// fail drops the tokens from mark on and makes everything from start to
// the end one Error token.
func (l *lexer) fail(mark, start, line int) {
	l.toks = append(l.toks[:mark], Token{Kind: Error, Off: start, Line: line, Text: l.src[start:]})
	l.pos = len(l.src)
}

func (l *lexer) openTag() {
	start := l.pos
	rest := l.src[start+2:]
	switch {
	case len(rest) >= 3 && strings.EqualFold(rest[:3], "php") && (len(rest) == 3 || isSpace(rest[3])):
		l.pos += 5
		// The long tag takes one whitespace character with it, as PHP's
		// T_OPEN_TAG does.
		if l.pos < len(l.src) {
			if strings.HasPrefix(l.src[l.pos:], "\r\n") {
				l.pos += 2
			} else {
				l.pos++
			}
		}
	case strings.HasPrefix(rest, "="):
		l.pos += 3
	default:
		l.pos += 2
	}
	l.emit(OpenTag, start)
}

// code lexes PHP code. With interp set it lexes the expression inside
// "{$...}" or "${...}" and stops before the closing brace.
func (l *lexer) code(interp bool) stop {
	braces := 0
	halt := 0 // progress through __halt_compiler ( ) ;
	n := len(l.src)
	for l.pos < n {
		start := l.pos
		mark := len(l.toks)
		c := l.src[start]
		var next byte
		if start+1 < n {
			next = l.src[start+1]
		}
		switch {
		case isSpace(c):
			l.pos++
			for l.pos < n && isSpace(l.src[l.pos]) {
				l.pos++
			}
			l.emit(Whitespace, start)
			continue
		case c == '$':
			l.variable()
		case isIdentStart(c) || (c == '\\' && isIdentStart(next)):
			l.ident()
		case isDigit(c) || (c == '.' && isDigit(next)):
			l.number()
		case c == '\'':
			if !l.singleQuoted() {
				return stopError
			}
		case c == '"' || c == '`':
			if !l.interpString(c) {
				return stopError
			}
		case c == '#' && next == '[':
			if !l.attribute() {
				return stopError
			}
		case c == '#' || (c == '/' && next == '/'):
			l.lineComment(interp)
		case c == '/' && next == '*':
			end := strings.Index(l.src[start+2:], "*/")
			if end < 0 {
				l.fail(mark, start, l.lineOf(start))
				return stopError
			}
			l.pos = start + 2 + end + 2
			l.emit(Comment, start)
		case c == '<' && strings.HasPrefix(l.src[start:], "<<<") && l.heredoc():
			if l.pos == n && l.toks[len(l.toks)-1].Kind == Error {
				return stopError
			}
		case c == '?' && next == '>' && !interp:
			l.pos += 2
			if strings.HasPrefix(l.src[l.pos:], "\r\n") {
				l.pos += 2
			} else if l.pos < n && l.src[l.pos] == '\n' {
				l.pos++
			}
			l.emit(CloseTag, start)
			if halt == 3 {
				l.emitRestHTML()
				return stopEOF
			}
			return stopClose
		case c == '(':
			if !l.cast() {
				l.pos++
				l.emit(Punct, start)
			}
		case c == '{':
			braces++
			l.pos++
			l.emit(Punct, start)
		case c == '}':
			if interp && braces == 0 {
				return stopBrace
			}
			braces--
			l.pos++
			l.emit(Punct, start)
		case c == ')' || c == '[' || c == ']' || c == ',' || c == ';':
			l.pos++
			l.emit(Punct, start)
		default:
			l.operator()
		}
		if interp || len(l.toks) == mark {
			continue
		}
		t := l.toks[len(l.toks)-1]
		if !t.Significant() {
			continue
		}
		switch {
		case t.Kind == Keyword && t.Is("__halt_compiler"):
			halt = 1
		case halt == 1 && t.Text == "(":
			halt = 2
		case halt == 2 && t.Text == ")":
			halt = 3
		case halt == 3 && t.Text == ";":
			l.emitRestHTML()
			return stopEOF
		default:
			halt = 0
		}
	}
	return stopEOF
}

func (l *lexer) variable() {
	start := l.pos
	j := start
	for j < len(l.src) && l.src[j] == '$' {
		j++
	}
	if j < len(l.src) && isIdentStart(l.src[j]) {
		j = identEnd(l.src, j)
	}
	l.pos = j
	l.emit(Variable, start)
}

func (l *lexer) ident() {
	start := l.pos
	j := start
	n := len(l.src)
	if l.src[j] == '\\' {
		j++
	}
	slash := j > start
	for {
		j = identEnd(l.src, j)
		if j+1 < n && l.src[j] == '\\' && isIdentStart(l.src[j+1]) {
			slash = true
			j++
			continue
		}
		break
	}
	l.pos = j
	k := Identifier
	if !slash && !l.member && isKeyword(l.src[start:j]) {
		k = Keyword
	}
	l.emit(k, start)
}

func isKeyword(s string) bool {
	if len(s) > 15 {
		return false
	}
	var buf [15]byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if 'A' <= c && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf[i] = c
	}
	return keywords[string(buf[:len(s)])]
}

func (l *lexer) number() {
	start := l.pos
	s := l.src
	n := len(s)
	j := start
	if s[j] == '0' && j+1 < n && (s[j+1]|0x20 == 'x' || s[j+1]|0x20 == 'b' || s[j+1]|0x20 == 'o') {
		j += 2
		for j < n && (isHex(s[j]) || s[j] == '_') {
			j++
		}
		l.pos = j
		l.emit(Number, start)
		return
	}
	for j < n && (isDigit(s[j]) || s[j] == '_') {
		j++
	}
	if j < n && s[j] == '.' && (j+1 >= n || s[j+1] != '.') {
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
	l.pos = j
	l.emit(Number, start)
}

func (l *lexer) singleQuoted() bool {
	start := l.pos
	j := start + 1
	for {
		k := strings.IndexAny(l.src[j:], `'\`)
		if k < 0 {
			l.fail(len(l.toks), start, l.lineOf(start))
			return false
		}
		j += k
		if l.src[j] == '\\' {
			j += 2
			if j > len(l.src) {
				l.fail(len(l.toks), start, l.lineOf(start))
				return false
			}
			continue
		}
		l.pos = j + 1
		l.emit(String, start)
		return true
	}
}

// interpString lexes a double quoted or backtick string.
func (l *lexer) interpString(q byte) bool {
	start := l.pos
	l.pos++
	set := "\\${\""
	if q == '`' {
		set = "\\${`"
	}
	return l.interp(start, set, q, "")
}

// interp lexes the body of an interpolating string from l.pos up to and
// including its closing delimiter: q for quoted strings, or the label at
// the start of a line for a heredoc (q 0). set lists the bytes the
// scanner must stop at.
func (l *lexer) interp(start int, set string, q byte, label string) bool {
	line := l.lineOf(start)
	mark := len(l.toks)
	s := l.src
	n := len(s)
	lit := start // where the pending literal piece starts
	j := l.pos
	flush := func(to int) {
		if to > lit {
			l.pos = to
			l.emit(String, lit)
		}
	}
	if q == 0 {
		if k := closeLabel(s, j, label); k >= 0 {
			j = k
			goto done
		}
	}
	for {
		k := strings.IndexAny(s[j:], set)
		if k < 0 {
			l.fail(mark, start, line)
			return false
		}
		j += k
		c := s[j]
		switch {
		case c == q:
			j++
			goto done
		case c == '\n' || c == '\r':
			// Only a heredoc stops here. PHP ends a line at \r, \n or
			// \r\n, so a label after a bare \r closes the heredoc too.
			j = lineBreakEnd(s, j)
			if k := closeLabel(s, j, label); k >= 0 {
				j = k
				goto done
			}
		case c == '\\':
			// A backslash escapes the next byte, except that a heredoc
			// line ending in a backslash still ends at the newline.
			if j+1 < n && (q != 0 || (s[j+1] != '\n' && s[j+1] != '\r')) {
				j += 2
			} else {
				j++
			}
		case c == '$' && j+1 < n && isIdentStart(s[j+1]):
			flush(j)
			l.pos = j
			l.simpleVar()
			j, lit = l.pos, l.pos
		case c == '$' && j+1 < n && s[j+1] == '{' && l.depth < MaxDepth:
			flush(j)
			if e := identEnd(s, j+2); e > j+2 && e < n && s[e] == '}' && isIdentStart(s[j+2]) {
				l.pos = e + 1
				l.emit(Variable, j)
			} else {
				l.pos = j + 2
				l.emit(Punct, j)
				if !l.nested(mark, start, line) {
					return false
				}
			}
			j, lit = l.pos, l.pos
		case c == '{' && j+1 < n && s[j+1] == '$' && l.depth < MaxDepth:
			flush(j)
			l.pos = j + 1
			l.emit(Punct, j)
			if !l.nested(mark, start, line) {
				return false
			}
			j, lit = l.pos, l.pos
		default:
			j++
		}
		if j > n {
			l.fail(mark, start, line)
			return false
		}
	}
done:
	flush(j)
	var parts []Token
	if len(l.toks)-mark > 1 {
		parts = make([]Token, len(l.toks)-mark)
		copy(parts, l.toks[mark:])
	}
	l.toks = append(l.toks[:mark], Token{Kind: String, Off: start, Line: line, Text: s[start:j], Parts: parts})
	l.pos = j
	l.member = false
	return true
}

// nested lexes an interpolated expression up to its closing brace.
func (l *lexer) nested(mark, start, line int) bool {
	l.depth++
	st := l.code(true)
	l.depth--
	if st != stopBrace {
		l.fail(mark, start, line)
		return false
	}
	b := l.pos
	l.pos++
	l.emit(Punct, b)
	return true
}

// simpleVar lexes "$name", "$name[key]" and "$name->prop" inside a
// string, PHP's simple interpolation syntax.
func (l *lexer) simpleVar() {
	s := l.src
	n := len(s)
	start := l.pos
	l.pos = identEnd(s, start+1)
	l.emit(Variable, start)
	j := l.pos
	switch {
	case j < n && s[j] == '[':
		k := j + 1
		kind := Identifier
		switch {
		case k < n && s[k] == '$' && k+1 < n && isIdentStart(s[k+1]):
			k = identEnd(s, k+1)
			kind = Variable
		case k < n && (isDigit(s[k]) || s[k] == '-'):
			e := k
			if s[e] == '-' {
				e++
			}
			for e < n && isDigit(s[e]) {
				e++
			}
			if e == k || (s[k] == '-' && e == k+1) {
				return
			}
			k = e
			kind = Number
		case k < n && isIdentStart(s[k]):
			k = identEnd(s, k)
		default:
			return
		}
		if k >= n || s[k] != ']' {
			return
		}
		l.pos = j + 1
		l.emit(Punct, j)
		l.pos = k
		l.emit(kind, j+1)
		l.pos = k + 1
		l.emit(Punct, k)
	case strings.HasPrefix(s[j:], "->") && j+2 < n && isIdentStart(s[j+2]):
		l.pos = j + 2
		l.emit(Operator, j)
		e := identEnd(s, j+2)
		l.pos = e
		l.emit(Identifier, j+2)
	case strings.HasPrefix(s[j:], "?->") && j+3 < n && isIdentStart(s[j+3]):
		l.pos = j + 3
		l.emit(Operator, j)
		e := identEnd(s, j+3)
		l.pos = e
		l.emit(Identifier, j+3)
	}
}

// closeLabel reports where a heredoc or nowdoc ends when its closing
// label starts the line at j (after optional indentation, PHP 7.3
// rules), or -1.
func closeLabel(s string, j int, label string) int {
	k := j
	for k < len(s) && (s[k] == ' ' || s[k] == '\t') {
		k++
	}
	if !strings.HasPrefix(s[k:], label) {
		return -1
	}
	e := k + len(label)
	if e < len(s) && isIdentChar(s[e]) {
		return -1
	}
	return e
}

// heredoc lexes <<<LABEL, <<<"LABEL" and <<<'LABEL' (nowdoc) strings. It
// returns false when the bytes at l.pos are not a heredoc header, so
// the caller reads them as operators.
func (l *lexer) heredoc() bool {
	s := l.src
	n := len(s)
	start := l.pos
	j := start + 3
	for j < n && (s[j] == ' ' || s[j] == '\t') {
		j++
	}
	var quote byte
	if j < n && (s[j] == '"' || s[j] == '\'') {
		quote = s[j]
		j++
	}
	if j >= n || !isIdentStart(s[j]) {
		return false
	}
	e := identEnd(s, j)
	label := s[j:e]
	j = e
	if quote != 0 {
		if j >= n || s[j] != quote {
			return false
		}
		j++
	}
	if j >= n || (s[j] != '\n' && s[j] != '\r') {
		return false
	}
	j = lineBreakEnd(s, j)
	if quote != '\'' {
		l.pos = j
		l.interp(start, "\\${\n\r", 0, label)
		return true
	}
	line := l.lineOf(start)
	for {
		if k := closeLabel(s, j, label); k >= 0 {
			l.pos = k
			l.emit(String, start)
			return true
		}
		nl := strings.IndexAny(s[j:], "\n\r")
		if nl < 0 {
			l.fail(len(l.toks), start, line)
			return true
		}
		j = lineBreakEnd(s, j+nl)
	}
}

// lineBreakEnd returns the offset after the line break at j: "\r\n",
// "\n" or a bare "\r", the three line endings PHP's scanner knows.
func lineBreakEnd(s string, j int) int {
	if s[j] == '\r' && j+1 < len(s) && s[j+1] == '\n' {
		return j + 2
	}
	return j + 1
}

func (l *lexer) lineComment(interp bool) {
	start := l.pos
	s := l.src
	j := start + 1
	for j < len(s) {
		c := s[j]
		if c == '\n' || c == '\r' {
			break
		}
		if c == '?' && !interp && j+1 < len(s) && s[j+1] == '>' {
			break
		}
		j++
	}
	l.pos = j
	l.emit(Comment, start)
}

// attribute lexes #[...] up to its matching bracket, skipping strings.
func (l *lexer) attribute() bool {
	start := l.pos
	s := l.src
	j := start + 2
	depth := 1
	for {
		k := strings.IndexAny(s[j:], "[]'\"")
		if k < 0 {
			l.fail(len(l.toks), start, l.lineOf(start))
			return false
		}
		j += k
		switch s[j] {
		case '[':
			depth++
			j++
		case ']':
			depth--
			j++
			if depth == 0 {
				l.pos = j
				l.emit(Attribute, start)
				return true
			}
		default:
			q := s[j]
			j++
			for j < len(s) && s[j] != q {
				if s[j] == '\\' {
					j++
				}
				j++
			}
			if j >= len(s) {
				l.fail(len(l.toks), start, l.lineOf(start))
				return false
			}
			j++
		}
	}
}

// cast lexes (int), ( string ) and the other casts.
func (l *lexer) cast() bool {
	s := l.src
	j := l.pos + 1
	for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
		j++
	}
	w := j
	for j < len(s) && j-w <= 8 && isAlpha(s[j]) {
		j++
	}
	if j == w || j-w > 7 {
		return false
	}
	word := strings.ToLower(s[w:j])
	for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
		j++
	}
	if j >= len(s) || s[j] != ')' || !casts[word] {
		return false
	}
	start := l.pos
	l.pos = j + 1
	l.emit(Cast, start)
	return true
}

var ops3 = map[string]bool{
	"<=>": true, "===": true, "!==": true, "**=": true, "...": true,
	"<<=": true, ">>=": true, "??=": true, "?->": true,
}

var ops2 = map[string]bool{
	"++": true, "--": true, "->": true, "=>": true, "::": true, "==": true,
	"!=": true, "<>": true, "<=": true, ">=": true, "&&": true, "||": true,
	"??": true, "+=": true, "-=": true, "*=": true, "/=": true, ".=": true,
	"%=": true, "&=": true, "|=": true, "^=": true, "<<": true, ">>": true,
	"**": true,
}

const ops1 = "+-*/%=<>!.&|^~?:@"

func (l *lexer) operator() {
	start := l.pos
	rest := l.src[start:]
	switch {
	case len(rest) >= 3 && ops3[rest[:3]]:
		l.pos += 3
	case len(rest) >= 2 && ops2[rest[:2]]:
		l.pos += 2
	default:
		l.pos++
		if !strings.Contains(ops1, rest[:1]) {
			// A lone backslash, a control byte or anything else PHP
			// would reject: one byte of punctuation.
			l.emit(Punct, start)
			return
		}
	}
	l.emit(Operator, start)
}

func isSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f'
}

func isDigit(c byte) bool { return '0' <= c && c <= '9' }

func isAlpha(c byte) bool { return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') }

func isHex(c byte) bool { return isDigit(c) || ('a' <= c|0x20 && c|0x20 <= 'f') }

// identClass marks identifier bytes: 1 for bytes that may start a name
// (PHP's label rule: a letter, an underscore or any byte from 0x80, so
// UTF-8 names are one identifier), 2 for digits. A table keeps the
// hottest loop of the lexer branch-free.
var identClass = func() (t [256]uint8) {
	for c := range 256 {
		switch {
		case isAlpha(byte(c)) || c == '_' || c >= 0x80:
			t[c] = 1
		case isDigit(byte(c)):
			t[c] = 2
		}
	}
	return t
}()

func isIdentStart(c byte) bool { return identClass[c] == 1 }

func isIdentChar(c byte) bool { return identClass[c] != 0 }

func identEnd(s string, j int) int {
	for j < len(s) && isIdentChar(s[j]) {
		j++
	}
	return j
}
