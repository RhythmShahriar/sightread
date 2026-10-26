// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Folding bounds, per expression: a crafted file cannot make the
// analyzer build big strings or loop (SR-34).
const (
	maxFoldSteps = 16
	maxFoldBytes = 64 << 10
)

// vkind is what a folded value is.
type vkind uint8

const (
	vUnknown vkind = iota
	vStr           // a string known exactly
	vNum           // an integer known exactly
	vArr           // an array of values (elements may be unknown)
	vName          // a name or dotted path: a function, module or object
	vClosure       // a function literal
)

// value is the compile-time value of an expression, when folding can
// tell it.
type value struct {
	kind vkind
	s    string // vStr: the string; vName: the path, e.g. "child_process.exec"
	n    int64
	arr  []value
	cl   *closure
}

var unknown = value{}

func strVal(s string) value {
	if len(s) > maxFoldBytes {
		return unknown
	}
	return value{kind: vStr, s: s}
}

// str returns v as a string: a string, or an integer in decimal.
func (v value) str() (string, bool) {
	switch v.kind {
	case vStr:
		return v.s, true
	case vNum:
		return strconv.FormatInt(v.n, 10), true
	}
	return "", false
}

// num returns v as an integer: an integer, or a string of digits.
func (v value) num() (int64, bool) {
	switch v.kind {
	case vNum:
		return v.n, true
	case vStr:
		n, err := strconv.ParseInt(strings.TrimSpace(v.s), 10, 64)
		return n, err == nil
	}
	return 0, false
}

// folder counts the folding steps of one expression.
type folder struct{ steps int }

// step uses up one folding step and reports whether the budget allows
// it.
func (f *folder) step() bool {
	f.steps++
	return f.steps <= maxFoldSteps
}

// numLit parses a PHP or JavaScript integer literal.
func numLit(text string) value {
	t := strings.ReplaceAll(strings.TrimSuffix(text, "n"), "_", "")
	base := 10
	switch {
	case len(t) > 2 && t[0] == '0' && (t[1]|0x20 == 'x'):
		base, t = 16, t[2:]
	case len(t) > 2 && t[0] == '0' && (t[1]|0x20 == 'o'):
		base, t = 8, t[2:]
	case len(t) > 2 && t[0] == '0' && (t[1]|0x20 == 'b'):
		base, t = 2, t[2:]
	}
	n, err := strconv.ParseInt(t, base, 64)
	if err != nil {
		return unknown
	}
	return value{kind: vNum, n: n}
}

// concat folds a . b (PHP) or a + b (JavaScript).
func (f *folder) concat(a, b value, js bool) value {
	if js && a.kind == vNum && b.kind == vNum {
		if !f.step() {
			return unknown
		}
		return value{kind: vNum, n: a.n + b.n}
	}
	if js && a.kind != vStr && b.kind != vStr {
		return unknown // number + array and the like: not a string build
	}
	x, ok1 := a.str()
	y, ok2 := b.str()
	if !ok1 || !ok2 || !f.step() {
		return unknown
	}
	return strVal(x + y)
}

// callPHP folds a call of a PHP built-in on known arguments.
func (f *folder) callPHP(name string, args []value) value {
	switch name {
	case "implode", "join":
		var glue string
		var arr value
		switch {
		case len(args) == 1:
			arr = args[0]
		case len(args) == 2 && args[0].kind == vArr:
			arr, glue = args[0], strOr(args[1])
		case len(args) == 2:
			arr, glue = args[1], strOr(args[0])
		}
		return f.join(arr, glue)
	case "strrev":
		return f.unary(args, reverse)
	case "str_rot13":
		return f.unary(args, rot13)
	case "strtolower":
		return f.unary(args, strings.ToLower)
	case "strtoupper":
		return f.unary(args, strings.ToUpper)
	case "strval", "trim":
		return f.unary(args, func(s string) string {
			if name == "trim" {
				return strings.Trim(s, " \t\n\r\x00\x0b")
			}
			return s
		})
	case "chr":
		if len(args) == 1 {
			if n, ok := args[0].num(); ok && f.step() {
				return strVal(string([]byte{byte(((n % 256) + 256) % 256)}))
			}
		}
	case "base64_decode":
		return f.unaryOK(args, decodeBase64)
	case "hex2bin":
		return f.unaryOK(args, func(s string) (string, bool) {
			b, err := hex.DecodeString(s)
			return string(b), err == nil
		})
	case "str_replace":
		if len(args) >= 3 {
			return f.replace(args[0], args[1], args[2])
		}
	case "sprintf":
		if len(args) >= 1 {
			return f.sprintf(args[0], args[1:])
		}
	case "vsprintf":
		if len(args) == 2 && args[1].kind == vArr {
			return f.sprintf(args[0], args[1].arr)
		}
	}
	return unknown
}

// callJS folds a JavaScript global call such as String.fromCharCode.
func (f *folder) callJS(path string, args []value) value {
	switch path {
	case "String.fromCharCode":
		var b strings.Builder
		for _, a := range args {
			n, ok := a.num()
			if !ok || n < 0 || n > 0xffff {
				return unknown
			}
			b.WriteRune(rune(n))
		}
		if !f.step() {
			return unknown
		}
		return strVal(b.String())
	case "atob":
		return f.unaryOK(args, decodeBase64)
	case "Buffer.from":
		if len(args) == 0 {
			return unknown
		}
		enc := "utf8"
		if len(args) > 1 {
			enc = strOr(args[1])
		}
		switch enc {
		case "base64":
			return f.unaryOK(args[:1], decodeBase64)
		case "hex":
			return f.unaryOK(args[:1], func(s string) (string, bool) {
				b, err := hex.DecodeString(s)
				return string(b), err == nil
			})
		case "utf8", "utf-8", "binary", "latin1", "ascii":
			return f.unary(args[:1], func(s string) string { return s })
		}
	case "decodeURIComponent", "unescape":
		return unknown
	}
	return unknown
}

// methodJS folds a method call on a known value: join, split, reverse,
// concat, toString, case changes and replace.
func (f *folder) methodJS(recv value, method string, args []value) value {
	switch method {
	case "join":
		glue := ","
		if len(args) > 0 {
			glue = strOr(args[0])
		}
		return f.join(recv, glue)
	case "reverse":
		if recv.kind == vArr && f.step() {
			out := make([]value, len(recv.arr))
			for i, v := range recv.arr {
				out[len(out)-1-i] = v
			}
			return value{kind: vArr, arr: out}
		}
	case "split":
		s, ok := recv.str()
		if !ok || len(args) == 0 || !f.step() {
			return unknown
		}
		sep, ok := args[0].str()
		if !ok {
			return unknown
		}
		var parts []string
		if sep == "" {
			for _, r := range s {
				parts = append(parts, string(r))
			}
		} else {
			parts = strings.Split(s, sep)
		}
		out := make([]value, len(parts))
		for i, p := range parts {
			out[i] = strVal(p)
		}
		return value{kind: vArr, arr: out}
	case "concat":
		if recv.kind == vArr {
			if !f.step() {
				return unknown
			}
			out := append([]value(nil), recv.arr...)
			for _, a := range args {
				if a.kind == vArr {
					out = append(out, a.arr...)
				} else {
					out = append(out, a)
				}
			}
			return value{kind: vArr, arr: out}
		}
		v := recv
		for _, a := range args {
			v = f.concat(v, a, false)
		}
		return v
	case "toString":
		if recv.kind == vStr {
			return recv
		}
	case "toLowerCase":
		return f.unary([]value{recv}, strings.ToLower)
	case "toUpperCase":
		return f.unary([]value{recv}, strings.ToUpper)
	case "replace", "replaceAll":
		if len(args) == 2 {
			s, ok1 := recv.str()
			from, ok2 := args[0].str()
			to, ok3 := args[1].str()
			if ok1 && ok2 && ok3 && from != "" && f.step() {
				if method == "replace" {
					return strVal(strings.Replace(s, from, to, 1))
				}
				return strVal(strings.ReplaceAll(s, from, to))
			}
		}
	}
	return unknown
}

func strOr(v value) string {
	s, _ := v.str()
	return s
}

func (f *folder) unary(args []value, fn func(string) string) value {
	if len(args) == 0 {
		return unknown
	}
	s, ok := args[0].str()
	if !ok || !f.step() {
		return unknown
	}
	return strVal(fn(s))
}

func (f *folder) unaryOK(args []value, fn func(string) (string, bool)) value {
	if len(args) == 0 {
		return unknown
	}
	s, ok := args[0].str()
	if !ok || !f.step() {
		return unknown
	}
	out, ok := fn(s)
	if !ok {
		return unknown
	}
	return strVal(out)
}

func (f *folder) join(arr value, glue string) value {
	if arr.kind != vArr || !f.step() {
		return unknown
	}
	var b strings.Builder
	for i, v := range arr.arr {
		s, ok := v.str()
		if !ok {
			return unknown
		}
		if i > 0 {
			b.WriteString(glue)
		}
		b.WriteString(s)
		if b.Len() > maxFoldBytes {
			return unknown
		}
	}
	return strVal(b.String())
}

// replace folds str_replace with string or array search and replace.
func (f *folder) replace(search, repl, subject value) value {
	s, ok := subject.str()
	if !ok || !f.step() {
		return unknown
	}
	var from, to []string
	switch search.kind {
	case vArr:
		for i, v := range search.arr {
			x, ok := v.str()
			if !ok {
				return unknown
			}
			from = append(from, x)
			switch {
			case repl.kind == vArr && i < len(repl.arr):
				y, ok := repl.arr[i].str()
				if !ok {
					return unknown
				}
				to = append(to, y)
			case repl.kind == vArr:
				to = append(to, "")
			default:
				y, ok := repl.str()
				if !ok {
					return unknown
				}
				to = append(to, y)
			}
		}
	default:
		x, ok1 := search.str()
		y, ok2 := repl.str()
		if !ok1 || !ok2 {
			return unknown
		}
		from, to = []string{x}, []string{y}
	}
	for i := range from {
		if from[i] == "" {
			continue
		}
		s = strings.ReplaceAll(s, from[i], to[i])
		if len(s) > maxFoldBytes {
			return unknown
		}
	}
	return strVal(s)
}

// sprintf folds %s, %d, %c, %x and %% with plain or numbered (%1$s)
// arguments. Width, padding and precision make it give up.
func (f *folder) sprintf(format value, args []value) value {
	fs, ok := format.str()
	if !ok || !f.step() {
		return unknown
	}
	var b strings.Builder
	next := 0
	for i := 0; i < len(fs); i++ {
		c := fs[i]
		if c != '%' {
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(fs) {
			return unknown
		}
		if fs[i] == '%' {
			b.WriteByte('%')
			continue
		}
		idx := next
		j := i
		for j < len(fs) && '0' <= fs[j] && fs[j] <= '9' {
			j++
		}
		if j < len(fs) && j > i && fs[j] == '$' {
			n, _ := strconv.Atoi(fs[i:j])
			idx = n - 1
			i = j + 1
		} else {
			next++
		}
		if i >= len(fs) || idx < 0 || idx >= len(args) {
			return unknown
		}
		a := args[idx]
		switch fs[i] {
		case 's':
			s, ok := a.str()
			if !ok {
				return unknown
			}
			b.WriteString(s)
		case 'd':
			n, ok := a.num()
			if !ok {
				return unknown
			}
			b.WriteString(strconv.FormatInt(n, 10))
		case 'c':
			n, ok := a.num()
			if !ok {
				return unknown
			}
			b.WriteByte(byte(n & 0xff)) // #nosec G115 -- masked to a byte, as PHP's %c does
		case 'x':
			n, ok := a.num()
			if !ok {
				return unknown
			}
			b.WriteString(strconv.FormatInt(n, 16))
		default:
			return unknown
		}
		if b.Len() > maxFoldBytes {
			return unknown
		}
	}
	return strVal(b.String())
}

// decodeBase64 decodes like PHP's base64_decode: characters outside the
// alphabet are skipped and padding is optional. Input that could decode
// to more than maxFoldBytes is left alone.
func decodeBase64(s string) (string, bool) {
	if len(s) > maxFoldBytes/3*4+8 {
		return "", false
	}
	clean := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if ('A' <= c && c <= 'Z') || ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '+' || c == '/' {
			clean = append(clean, c)
		}
		if c == '-' {
			clean = append(clean, '+')
		}
		if c == '_' {
			clean = append(clean, '/')
		}
	}
	if len(clean)%4 == 1 {
		clean = clean[:len(clean)-1]
	}
	out, err := base64.RawStdEncoding.DecodeString(string(clean))
	if err != nil {
		return "", false
	}
	return string(out), true
}

func reverse(s string) string {
	b := []byte(s)
	for i, j := 0, len(b)-1; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return string(b)
}

func rot13(s string) string {
	b := []byte(s)
	for i, c := range b {
		switch {
		case 'a' <= c && c <= 'z':
			b[i] = 'a' + (c-'a'+13)%26
		case 'A' <= c && c <= 'Z':
			b[i] = 'A' + (c-'A'+13)%26
		}
	}
	return string(b)
}

// printable reports whether a folded name could be a function name,
// so binary noise from a decode is not taken for a callee.
func printable(s string) bool {
	if s == "" || len(s) > 256 || !utf8.ValidString(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}
