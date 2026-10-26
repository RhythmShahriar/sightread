// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package js

import "strings"

// Kind is the class of a token.
type Kind uint8

// The token kinds. A template literal with substitutions is several
// Template tokens with the substitution code between them: "`a${" (the
// head), "}b${" (a middle) and "}c`" (the tail); one without is a single
// Template token. Error marks an unterminated construct (see Lex).
const (
	Error Kind = iota
	Whitespace
	Comment
	String
	Template
	RegExp
	Identifier
	Keyword
	Number
	Punct
)

var kindNames = [...]string{
	Error:      "Error",
	Whitespace: "Whitespace",
	Comment:    "Comment",
	String:     "String",
	Template:   "Template",
	RegExp:     "RegExp",
	Identifier: "Identifier",
	Keyword:    "Keyword",
	Number:     "Number",
	Punct:      "Punct",
}

// String returns the kind's name, e.g. "Template".
func (k Kind) String() string {
	if int(k) < len(kindNames) {
		return kindNames[k]
	}
	return "Kind(?)"
}

// Token is one lexeme of the input.
type Token struct {
	Kind Kind
	Off  int    // byte offset of the first byte
	Line int    // 1-based line of the first byte
	Text string // the exact source text
}

// End is the offset just past the token.
func (t Token) End() int { return t.Off + len(t.Text) }

// Significant reports whether the token carries code meaning, so
// whitespace and comments can be skipped when matching patterns.
func (t Token) Significant() bool { return t.Kind != Whitespace && t.Kind != Comment }

// Construct names what an Error token failed to close: "string",
// "template", "comment" or "regular expression".
func (t Token) Construct() string {
	s := t.Text
	switch {
	case strings.HasPrefix(s, "/*"):
		return "comment"
	case strings.HasPrefix(s, "/"):
		return "regular expression"
	case strings.HasPrefix(s, "`"), strings.HasPrefix(s, "}"):
		return "template"
	}
	return "string"
}

// isKeyword reports JavaScript's reserved words plus let, static, yield
// and await. Contextual words that are common names (async, of, get,
// set) stay identifiers. A switch compiles to a length and binary
// search, faster than a map in the lexer's hottest path.
func isKeyword(s string) bool {
	if len(s) < 2 || len(s) > 10 || s[0] < 'a' || s[0] > 'y' {
		return false
	}
	switch s {
	case "await", "break", "case", "catch", "class", "const", "continue",
		"debugger", "default", "delete", "do", "else", "enum", "export",
		"extends", "false", "finally", "for", "function", "if", "import",
		"in", "instanceof", "let", "new", "null", "return", "static", "super",
		"switch", "this", "throw", "true", "try", "typeof", "var", "void",
		"while", "with", "yield":
		return true
	}
	return false
}

// regexAfter are the keywords after which a slash starts a regular
// expression rather than a division.
var regexAfter = map[string]bool{
	"await": true, "case": true, "delete": true, "do": true, "else": true,
	"in": true, "instanceof": true, "new": true, "return": true, "throw": true,
	"typeof": true, "void": true, "yield": true,
}
