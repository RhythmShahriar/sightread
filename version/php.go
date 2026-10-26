// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package version

import "strings"

// phpCompare orders two version strings the way PHP's version_compare
// does, which is what WordPress (and Composer, on normalised versions)
// use. Each string is cut into parts at '.', '-', '_', '+' and any other
// character that is not a letter or digit; a run of letters next to a
// run of digits is two parts. Parts compare as numbers when both are
// digits; otherwise by rank: any other word < dev < alpha = a < beta = b < RC = rc < number
// < pl = p, matched by prefix as PHP does ("patch" ranks as "p"). When
// one string runs out, the other is newer if its next part is a number
// or "pl" and older otherwise ("1.0-beta" < "1.0" < "1.0.0").
func phpCompare(a, b string) int {
	pa, pb := phpParts(a), phpParts(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		switch {
		case i >= len(pa):
			return -phpPartVsEnd(pb[i])
		case i >= len(pb):
			return phpPartVsEnd(pa[i])
		}
		if c := phpPart(pa[i], pb[i]); c != 0 {
			return c
		}
	}
	return 0
}

// phpParts cuts s into its parts.
func phpParts(s string) []string {
	var parts []string
	start := -1
	digits := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum, isDigit := isAlnum(c), c >= '0' && c <= '9'
		if start >= 0 && (!alnum || isDigit != digits) {
			parts = append(parts, s[start:i])
			start = -1
		}
		if alnum && start < 0 {
			start, digits = i, isDigit
		}
	}
	if start >= 0 {
		parts = append(parts, s[start:])
	}
	return parts
}

func isAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func isDigits(s string) bool { return s != "" && s[0] >= '0' && s[0] <= '9' }

// numberRank is the rank of a numeric part among the special words.
const numberRank = 4

// phpRank is the rank of a word part, by prefix in PHP's order.
func phpRank(w string) int {
	for _, f := range []struct {
		name string
		rank int
	}{{"dev", 0}, {"alpha", 1}, {"a", 1}, {"beta", 2}, {"b", 2}, {"RC", 3}, {"rc", 3}, {"#", numberRank}, {"pl", 5}, {"p", 5}} {
		if strings.HasPrefix(w, f.name) {
			return f.rank
		}
	}
	return -6
}

// phpPart compares two parts.
func phpPart(a, b string) int {
	da, db := isDigits(a), isDigits(b)
	switch {
	case da && db:
		return cmpDigits(a, b)
	case da:
		return sign(numberRank - phpRank(b))
	case db:
		return sign(phpRank(a) - numberRank)
	}
	return sign(phpRank(a) - phpRank(b))
}

// phpPartVsEnd compares a part with the end of the other string: a
// number is newer than nothing, a word compares as against a number.
func phpPartVsEnd(p string) int {
	if isDigits(p) {
		return 1
	}
	return sign(phpRank(p) - numberRank)
}

// cmpDigits compares two digit strings as numbers of any length.
func cmpDigits(a, b string) int {
	a, b = strings.TrimLeft(a, "0"), strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return sign(len(a) - len(b))
	}
	return strings.Compare(a, b)
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	}
	return 0
}
