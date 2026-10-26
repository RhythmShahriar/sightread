// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package js

import (
	"strings"
	"unicode/utf8"
)

// StringValue returns the value of a string literal or of a template
// literal without substitutions, escapes decoded. ok is false for any
// other token.
func StringValue(t Token) (string, bool) {
	s := t.Text
	switch {
	case t.Kind == String && len(s) >= 2:
		return unescape(s[1 : len(s)-1]), true
	case t.Kind == Template && len(s) >= 2 && s[0] == '`' && s[len(s)-1] == '`' && !strings.HasSuffix(s, "${"):
		return unescape(s[1 : len(s)-1]), true
	}
	return "", false
}

// TemplateText returns the literal text of one Template token: the part
// between "`" or "}" and "${" or "`", escapes decoded.
func TemplateText(t Token) (string, bool) {
	s := t.Text
	if t.Kind != Template || len(s) < 2 {
		return "", false
	}
	s = s[1:]
	if strings.HasSuffix(s, "${") {
		s = s[:len(s)-2]
	} else {
		s = s[:len(s)-1]
	}
	return unescape(s), true
}

// IdentName returns an identifier with its \u escapes decoded, so
// "eval" reads as "eval", the name the engine sees.
func IdentName(t Token) string {
	s := t.Text
	if !strings.Contains(s, `\u`) {
		return s
	}
	return unescape(s)
}

// unescape decodes JavaScript string escapes.
func unescape(s string) string {
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
		i++
		e := s[i]
		switch e {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'v':
			b.WriteByte('\v')
		case '\r':
			// A line continuation adds nothing.
			if i+1 < len(s) && s[i+1] == '\n' {
				i++
			}
		case '\n':
		case 'x':
			if i+2 < len(s) && isHex(s[i+1]) && isHex(s[i+2]) {
				b.WriteRune(hexVal(s[i+1])<<4 | hexVal(s[i+2]))
				i += 2
			} else {
				b.WriteByte('x')
			}
		case 'u':
			if r, n := unicodeEscape(s[i-1:]); n > 0 {
				b.WriteRune(r)
				i += n - 2
			} else {
				b.WriteByte('u')
			}
		default:
			if '0' <= e && e <= '7' {
				// Legacy octal escapes, still accepted in sloppy mode.
				v, k := 0, i
				for k < len(s) && k < i+3 && '0' <= s[k] && s[k] <= '7' && v*8+int(s[k]-'0') <= 0xff {
					v = v*8 + int(s[k]-'0')
					k++
				}
				b.WriteRune(rune(v))
				i = k - 1
				continue
			}
			b.WriteByte(e)
		}
	}
	return b.String()
}

// unicodeEscape decodes \uXXXX or \u{X...} at the start of s, returning
// the rune and the escape's length, or 0 when s holds no valid escape.
func unicodeEscape(s string) (rune, int) {
	e := unicodeEscapeEnd(s, 0)
	if e == 0 {
		return 0, 0
	}
	h := s[2:e]
	h = strings.TrimSuffix(strings.TrimPrefix(h, "{"), "}")
	v := 0
	for i := 0; i < len(h); i++ {
		v = v*16 + int(hexVal(h[i]))
	}
	r := rune(v)
	if !utf8.ValidRune(r) {
		r = utf8.RuneError
	}
	return r, e
}

func hexVal(c byte) rune {
	if isDigit(c) {
		return rune(c - '0')
	}
	return rune(c|0x20-'a') + 10
}
