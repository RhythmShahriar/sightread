// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package php

import (
	"strings"
	"unicode/utf8"
)

// StringValue returns the value of a string literal token as PHP would
// see it: escapes decoded for double quoted strings and heredocs,
// indentation of a PHP 7.3 closing label removed. ok is false for a
// token that is not a String, a string with interpolation (its value is
// only known at run time) or a backtick shell string.
func StringValue(t Token) (string, bool) {
	if t.Kind != String || t.Parts != nil || t.Text == "" {
		return "", false
	}
	s := t.Text
	switch s[0] {
	case '\'':
		return unescapeSingle(s[1 : len(s)-1]), true
	case '"':
		return unescapeDouble(s[1:len(s)-1], '"'), true
	case '<':
		body, indent, nowdoc := heredocBody(s)
		body = dedent(body, indent, true)
		if nowdoc {
			return body, true
		}
		return unescapeDouble(body, 0), true
	}
	return "", false
}

// Segment is one piece of an interpolating string: either literal text
// (Code nil) or the tokens of one embedded variable or expression. For
// "{$expr}" Code holds the tokens between the braces; for "${expr}" it
// keeps the "${" and "}" so a reader can tell a variable variable.
type Segment struct {
	Lit  string
	Code []Token
	Line int
}

// Segments splits a string token into literal and code pieces. A string
// without interpolation gives one literal segment; anything that is not
// a String gives nil.
func Segments(t Token) []Segment {
	if t.Kind != String || t.Text == "" {
		return nil
	}
	if t.Parts == nil {
		v, ok := StringValue(t)
		if !ok {
			return nil
		}
		return []Segment{{Lit: v, Line: t.Line}}
	}
	s := t.Text
	var quote byte
	prefix, suffix, indent := 1, 1, ""
	switch s[0] {
	case '"', '`':
		quote = s[0]
	default:
		start, end, label := heredocBounds(s)
		prefix = start
		suffix = len(s) - end
		indent = leadingSpace(s[label:])
	}
	var out []Segment
	parts := t.Parts
	for i := 0; i < len(parts); i++ {
		p := parts[i]
		// Literal pieces only sit outside braces and codeEnd skips
		// whole interpolations, so a String reached here is literal.
		if p.Kind == String && p.Parts == nil {
			txt := p.Text
			lo, hi := 0, len(txt)
			if p.Off == t.Off {
				lo = min(prefix, hi)
			}
			if p.End() == t.End() {
				hi = max(lo, hi-suffix)
			}
			lit := txt[lo:hi]
			if indent != "" {
				lit = dedent(lit, indent, p.Off == t.Off)
			}
			out = append(out, Segment{Lit: unescapeDouble(lit, quote), Line: p.Line})
			continue
		}
		j := codeEnd(parts, i)
		seg := parts[i:j]
		if seg[0].Kind == Punct && seg[0].Text == "{" && len(seg) >= 2 {
			seg = seg[1 : len(seg)-1]
		}
		out = append(out, Segment{Code: seg, Line: p.Line})
		i = j - 1
	}
	return out
}

// codeEnd returns the index after the interpolation that starts at i.
func codeEnd(parts []Token, i int) int {
	p := parts[i]
	if p.Kind == Punct && (p.Text == "{" || p.Text == "${") {
		depth := 0
		for j := i; j < len(parts); j++ {
			switch parts[j].Text {
			case "{", "${":
				if parts[j].Kind == Punct {
					depth++
				}
			case "}":
				if parts[j].Kind == Punct {
					depth--
					if depth == 0 {
						return j + 1
					}
				}
			}
		}
		return len(parts)
	}
	j := i + 1
	if p.Kind != Variable {
		return j
	}
	// The simple syntax: $a[key] or $a->prop right after the variable.
	if j+2 < len(parts) && parts[j].Kind == Punct && parts[j].Text == "[" && parts[j].Off == p.End() {
		return j + 3
	}
	if j+1 < len(parts) && parts[j].Kind == Operator && parts[j].Off == p.End() {
		return j + 2
	}
	return j
}

// heredocBody splits a heredoc or nowdoc token into its body (without
// the header line and the newline before the closing label), the
// closing label's indentation and whether it is a nowdoc.
func heredocBody(s string) (body, indent string, nowdoc bool) {
	start, end, label := heredocBounds(s)
	nowdoc = strings.Contains(s[:start], "'")
	indent = leadingSpace(s[label:])
	if end <= start {
		return "", indent, nowdoc
	}
	return s[start:end], indent, nowdoc
}

// heredocBounds finds the parts of a heredoc or nowdoc token: the body
// starts after the header's line break and ends before the line break
// in front of the closing label, which starts at label. Lines end at
// "\r\n", "\n" or a bare "\r", as in PHP. An empty heredoc has one
// line break, so end can come before start.
func heredocBounds(s string) (start, end, label int) {
	nl := strings.IndexAny(s, "\r\n")
	start = nl + 1
	if s[nl] == '\r' && start < len(s) && s[start] == '\n' {
		start++
	}
	last := strings.LastIndexAny(s, "\r\n")
	label = last + 1
	end = last
	if s[last] == '\n' && last > 0 && s[last-1] == '\r' {
		end--
	}
	return start, end, label
}

func leadingSpace(s string) string {
	i := 0
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	return s[:i]
}

// dedent removes up to len(indent) leading blanks from each line, as
// PHP does for an indented closing label. atStart says s begins a line.
func dedent(s, indent string, atStart bool) string {
	if indent == "" {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	lineStart := atStart
	for i := 0; i < len(s); {
		if lineStart {
			k := 0
			for k < len(indent) && i < len(s) && (s[i] == ' ' || s[i] == '\t') {
				i++
				k++
			}
			lineStart = false
			continue
		}
		c := s[i]
		b.WriteByte(c)
		i++
		if c == '\n' || c == '\r' {
			lineStart = true
		}
	}
	return b.String()
}

func unescapeSingle(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && (s[i+1] == '\\' || s[i+1] == '\'') {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// unescapeDouble decodes PHP's double quoted escapes. quote is the
// string's delimiter ('"', '`' or 0 for a heredoc): only that one is
// escapable, as in PHP's scanner.
func unescapeDouble(s string, quote byte) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		e := s[i+1]
		switch e {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'v':
			b.WriteByte('\v')
		case 'e':
			b.WriteByte(0x1b)
		case 'f':
			b.WriteByte('\f')
		case '\\', '$':
			b.WriteByte(e)
		case 'x':
			v, k := 0, i+2
			for k < len(s) && k < i+4 && isHex(s[k]) {
				v = v*16 + hexVal(s[k])
				k++
			}
			if k == i+2 {
				b.WriteString(`\x`)
				i++
				continue
			}
			b.WriteByte(byte(v))
			i = k - 1
			continue
		case 'u':
			if i+2 < len(s) && s[i+2] == '{' {
				end := strings.IndexByte(s[i+3:], '}')
				if end > 0 && end <= 8 {
					v := 0
					okHex := true
					for _, h := range []byte(s[i+3 : i+3+end]) {
						if !isHex(h) {
							okHex = false
							break
						}
						v = v*16 + hexVal(h)
					}
					if okHex && utf8.ValidRune(rune(v)) {
						b.WriteRune(rune(v))
						i += 3 + end
						continue
					}
				}
			}
			b.WriteString(`\u`)
		default:
			if '0' <= e && e <= '7' {
				v, k := 0, i+1
				for k < len(s) && k < i+4 && '0' <= s[k] && s[k] <= '7' {
					v = v*8 + int(s[k]-'0')
					k++
				}
				b.WriteByte(byte(v & 0xff))
				i = k - 1
				continue
			}
			if quote != 0 && e == quote {
				b.WriteByte(e)
				break
			}
			b.WriteByte('\\')
			b.WriteByte(e)
		}
		i++
	}
	return b.String()
}

func hexVal(c byte) int {
	switch {
	case isDigit(c):
		return int(c - '0')
	default:
		return int(c|0x20-'a') + 10
	}
}
