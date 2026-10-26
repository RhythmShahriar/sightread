// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package version

import (
	"fmt"
	"strings"
)

// maxVersion bounds a version string, as core.Ref bounds its parts.
const maxVersion = 256

// maxConstraint bounds a constraint or range string.
const maxConstraint = 1024

// WordPress is the version scheme of WordPress.org plugins and themes:
// loose versions such as 1.2, 1.2.3.4, 2.0-beta1 or 5.3-RC2, ordered by
// PHP's version_compare as WordPress orders them. A version starts with
// a digit and holds letters, digits and . - _ + only.
var WordPress = wpScheme{}

type wpScheme struct{}

// Valid reports whether v is a version WordPress can order.
func (wpScheme) Valid(v string) bool {
	if v == "" || len(v) > maxVersion || !isDigits(v) {
		return false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; !isAlnum(c) && c != '.' && c != '-' && c != '_' && c != '+' {
			return false
		}
	}
	return true
}

// Compare orders a and b with PHP's version_compare.
func (wpScheme) Compare(a, b string) int { return phpCompare(a, b) }

// Prerelease reports whether v carries a word that ranks below a
// release: dev, alpha, beta, RC or any word PHP does not know. "pl" and
// "p" (patch) are releases.
func (wpScheme) Prerelease(v string) bool {
	for _, p := range phpParts(v) {
		if !isDigits(p) && phpRank(p) < numberRank {
			return true
		}
	}
	return false
}

// Satisfies matches v against a list of comparisons. WordPress has no
// range syntax of its own; this takes "*", an exact version and the
// operators <, <=, >, >=, =, == and !=, with spaces or commas meaning
// AND and || meaning OR (">=5.0 <6.0 || 6.2").
func (s wpScheme) Satisfies(v, constraint string) (bool, error) {
	sets, err := parseComparisons(constraint, s)
	if err != nil {
		return false, err
	}
	if !s.Valid(v) {
		return false, nil
	}
	for _, set := range sets {
		if set.match(v, s.Compare) {
			return true, nil
		}
	}
	return false, nil
}

// comparison is one operator and version; op "*" matches anything.
type comparison struct{ op, v string }

// comparisons is a list that must all match.
type comparisons []comparison

func (cs comparisons) match(v string, cmp func(a, b string) int) bool {
	for _, c := range cs {
		if !compareOp(c.op, cmp(v, c.v)) {
			return false
		}
	}
	return true
}

// compareOp reports whether the result c of comparing a version with
// the operand satisfies op.
func compareOp(op string, c int) bool {
	switch op {
	case "*":
		return true
	case "<":
		return c < 0
	case "<=":
		return c <= 0
	case ">":
		return c > 0
	case ">=":
		return c >= 0
	case "!=", "<>":
		return c != 0
	}
	return c == 0
}

// parseComparisons reads the simple grammar of WordPress.Satisfies.
func parseComparisons(constraint string, s wpScheme) ([]comparisons, error) {
	if len(constraint) > maxConstraint {
		return nil, fmt.Errorf("constraint is over %d bytes", maxConstraint)
	}
	var sets []comparisons
	for _, or := range strings.Split(constraint, "||") {
		var set comparisons
		for _, tok := range strings.FieldsFunc(joinOps(or), func(r rune) bool { return r == ' ' || r == ',' || r == '\t' }) {
			op, v := splitOp(tok)
			if v == "*" && (op == "" || op == "=" || op == ">=") {
				set = append(set, comparison{op: "*"})
				continue
			}
			if !s.Valid(v) {
				return nil, fmt.Errorf("%q is not a WordPress version", tok)
			}
			if op == "" {
				op = "="
			}
			set = append(set, comparison{op: op, v: v})
		}
		if len(set) == 0 {
			set = comparisons{{op: "*"}}
		}
		sets = append(sets, set)
	}
	return sets, nil
}

// operators longest first, so ">=" is not read as ">".
var operators = []string{"<>", "!=", ">=", "<=", "==", ">", "<", "="}

// splitOp cuts the leading operator off tok.
func splitOp(tok string) (op, rest string) {
	for _, o := range operators {
		if strings.HasPrefix(tok, o) {
			return o, tok[len(o):]
		}
	}
	return "", tok
}

// joinOps removes the spaces between an operator and its version, so
// ">= 1.2" is one token.
func joinOps(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		b.WriteByte(s[i])
		if c := s[i]; c == '<' || c == '>' || c == '=' || c == '~' || c == '^' {
			for i+1 < len(s) && (s[i+1] == ' ' || s[i+1] == '\t') {
				i++
			}
		}
	}
	return b.String()
}
