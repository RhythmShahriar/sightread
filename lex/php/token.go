// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package php

import "strings"

// Kind is the class of a token.
type Kind uint8

// The token kinds. Error is the rest of the input after an unterminated
// string, heredoc, comment or attribute: the lexer gives up there rather
// than guess, so code after the break is never silently misread.
const (
	Error Kind = iota
	InlineHTML
	OpenTag
	CloseTag
	Comment
	Attribute
	Whitespace
	Variable
	Identifier
	Keyword
	String
	Number
	Cast
	Operator
	Punct
)

var kindNames = [...]string{
	Error:      "Error",
	InlineHTML: "InlineHTML",
	OpenTag:    "OpenTag",
	CloseTag:   "CloseTag",
	Comment:    "Comment",
	Attribute:  "Attribute",
	Whitespace: "Whitespace",
	Variable:   "Variable",
	Identifier: "Identifier",
	Keyword:    "Keyword",
	String:     "String",
	Number:     "Number",
	Cast:       "Cast",
	Operator:   "Operator",
	Punct:      "Punct",
}

// String returns the kind's name, e.g. "Variable".
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
	// Parts splits an interpolating string (double quoted, heredoc or
	// backtick) into literal pieces (Kind String, Parts nil) and the
	// tokens of each embedded variable or expression. The parts' Text
	// joined is the token's Text. Strings without interpolation have no
	// parts.
	Parts []Token
	// Deep is set on an interpolating string at MaxDepth that holds a
	// "{$" or "${" the lexer read as literal text. The code there is not
	// lexed, so a reader must treat the string as not analysed.
	Deep bool
}

// End is the offset just past the token.
func (t Token) End() int { return t.Off + len(t.Text) }

// Significant reports whether the token carries code meaning, so
// whitespace, comments and attributes can be skipped when matching
// patterns such as `eval /* x */ (`.
func (t Token) Significant() bool {
	switch t.Kind {
	case Whitespace, Comment, Attribute:
		return false
	}
	return true
}

// Is reports whether t is an identifier or keyword spelled name, ignoring
// case as PHP does for function names and keywords. A leading backslash
// (a fully qualified global name) is ignored too.
func (t Token) Is(name string) bool {
	if t.Kind != Identifier && t.Kind != Keyword {
		return false
	}
	return strings.EqualFold(strings.TrimPrefix(t.Text, `\`), name)
}

// Construct names what an Error token failed to close, for messages such
// as "unterminated heredoc at line 12": "string", "heredoc", "nowdoc",
// "comment", "attribute" or "shell string".
func (t Token) Construct() string {
	s := t.Text
	switch {
	case strings.HasPrefix(s, "/*"):
		return "comment"
	case strings.HasPrefix(s, "#["):
		return "attribute"
	case strings.HasPrefix(s, "`"):
		return "shell string"
	case strings.HasPrefix(s, "<<<"):
		h := strings.TrimLeft(s[3:], " \t")
		if strings.HasPrefix(h, "'") {
			return "nowdoc"
		}
		return "heredoc"
	}
	return "string"
}

// keywords are PHP's reserved words, lower case. Magic constants and
// true, false and null stay identifiers.
var keywords = map[string]bool{
	"abstract": true, "and": true, "array": true, "as": true, "break": true,
	"callable": true, "case": true, "catch": true, "class": true, "clone": true,
	"const": true, "continue": true, "declare": true, "default": true, "die": true,
	"do": true, "echo": true, "else": true, "elseif": true, "empty": true,
	"enddeclare": true, "endfor": true, "endforeach": true, "endif": true,
	"endswitch": true, "endwhile": true, "enum": true, "eval": true, "exit": true,
	"extends": true, "final": true, "finally": true, "fn": true, "for": true,
	"foreach": true, "function": true, "global": true, "goto": true, "if": true,
	"implements": true, "include": true, "include_once": true, "instanceof": true,
	"insteadof": true, "interface": true, "isset": true, "list": true, "match": true,
	"namespace": true, "new": true, "or": true, "print": true, "private": true,
	"protected": true, "public": true, "readonly": true, "require": true,
	"require_once": true, "return": true, "static": true, "switch": true,
	"throw": true, "trait": true, "try": true, "unset": true, "use": true,
	"var": true, "while": true, "xor": true, "yield": true, "__halt_compiler": true,
}

// casts are the type names PHP accepts in a cast such as (int).
var casts = map[string]bool{
	"int": true, "integer": true, "bool": true, "boolean": true, "float": true,
	"double": true, "real": true, "string": true, "binary": true, "array": true,
	"object": true, "unset": true,
}
