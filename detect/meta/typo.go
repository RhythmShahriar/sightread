// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package meta

import (
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/RhythmShahriar/sightread/core"
)

// minTypoRunes is the shortest popular name (or Composer package part)
// the edit distance is measured against. One edit away from "qs" or "ms"
// is half the two letter names on npm, so short names are left to the
// separator, scope and look-alike checks.
const minTypoRunes = 4

// typoLimit is the most edits a name may be from popular name p and
// still count as near it: 1 up to 8 runes and 2 above (PRD 12.1).
func typoLimit(p string) int {
	if utf8.RuneCountInString(p) <= 8 {
		return 1
	}
	return 2
}

// Distance is the Damerau-Levenshtein distance between a and b (optimal
// string alignment: insertions, deletions, substitutions and swaps of
// two adjacent runes). It stops as soon as the answer is over max
// and then returns max+1, so comparing one name with thousands stays
// cheap. It is symmetric.
func Distance(a, b string, maxDist int) int {
	if a == b {
		return 0
	}
	ra, rb := []rune(a), []rune(b)
	if len(ra) < len(rb) {
		ra, rb = rb, ra
	}
	if len(ra)-len(rb) > maxDist {
		return maxDist + 1
	}
	// Three rows: the one two back is needed for a swap.
	prev2 := make([]int, len(rb)+1)
	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}
	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		low := cur[0]
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			d := min(prev[j]+1, cur[j-1]+1, prev[j-1]+cost)
			if i > 1 && j > 1 && ra[i-1] == rb[j-2] && ra[i-2] == rb[j-1] {
				d = min(d, prev2[j-2]+1)
			}
			cur[j] = d
			low = min(low, d)
		}
		if low > maxDist {
			return maxDist + 1
		}
		prev2, prev, cur = prev, cur, prev2
	}
	return min(prev[len(rb)], maxDist+1)
}

// confusables maps hand-picked Cyrillic and Greek letters to the Latin
// letter they look like. npm and Packagist names are ASCII today. A
// lockfile or a private registry may hold anything though; the table is
// what a reader's eye does anyway.
var confusables = map[rune]rune{
	// Cyrillic
	'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'к': 'k', 'м': 'm', 'н': 'h',
	'о': 'o', 'р': 'p', 'с': 'c', 'т': 't', 'у': 'y', 'х': 'x', 'ѕ': 's',
	'і': 'i', 'ї': 'i', 'ј': 'j', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ɡ': 'g',
	'һ': 'h', 'ӏ': 'l',
	// Greek
	'α': 'a', 'β': 'b', 'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'ν': 'v',
	'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x', 'ω': 'w', 'γ': 'y',
}

// Skeleton is the form of a name a reader can't tell apart from others:
// lower-case, look-alike letters mapped to Latin, 0 read as o, 1, i and
// l read as l; rn reads as m. Two different names with one skeleton
// are a look-alike pair.
func Skeleton(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		if c, ok := confusables[r]; ok {
			r = c
		}
		switch r {
		case '0':
			r = 'o'
		case '1', 'i':
			r = 'l'
		}
		b.WriteRune(r)
	}
	return strings.ReplaceAll(b.String(), "rn", "m")
}

// stripSeparators drops the separators npm and Composer names use
// between words, so lodash.merge and lodash-merge compare equal.
func stripSeparators(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '-', '_', '.':
			return -1
		}
		return r
	}, s)
}

// affixWords are the words a combosquat adds to a popular name to make
// it look official or fixed: plain-crypto-js next to crypto-js. The list
// is short on purpose: node-, -js, -utils and the like name real
// packages too often.
var affixWords = map[string]bool{
	"plain": true, "real": true, "true": true, "official": true, "secure": true,
	"safe": true, "fixed": true, "patched": true, "latest": true, "updated": true,
	"original": true, "pure": true, "legit": true, "verified": true,
}

// TypoIndex finds the popular names a new name is near. It holds one
// ecosystem's popular list (data/names); build it once and share it.
type TypoIndex struct {
	eco   core.Ecosystem
	names []string // lower-case, sorted, unique
	set   map[string]bool
}

// NewTypoIndex indexes popular, one ecosystem's list.
func NewTypoIndex(eco core.Ecosystem, popular []string) *TypoIndex {
	ix := &TypoIndex{eco: eco, set: make(map[string]bool, len(popular))}
	for _, n := range popular {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" || ix.set[n] {
			continue
		}
		ix.set[n] = true
		ix.names = append(ix.names, n)
	}
	slices.Sort(ix.names)
	return ix
}

// Popular reports whether name is on the list, ignoring case.
func (ix *TypoIndex) Popular(name string) bool {
	return ix != nil && ix.set[strings.ToLower(strings.TrimSpace(name))]
}

// Len is the number of names indexed.
func (ix *TypoIndex) Len() int {
	if ix == nil {
		return 0
	}
	return len(ix.names)
}

// Near returns the popular names name is near, sorted: one or two edits
// away, the same apart from separators, case or look-alike letters, a
// popular name with a word such as "plain" or "official" added, or for
// npm the same name under a confused scope (@type/node, types-node for
// @types/node). A popular name is never near anything: it is the real
// thing. Composer names compare vendor and package separately. A
// name under the popular one's own vendor or npm scope is never near it,
// since only that vendor can publish there.
func (ix *TypoIndex) Near(name string) []string {
	n := strings.ToLower(strings.TrimSpace(name))
	if ix == nil || n == "" || ix.set[n] {
		return nil
	}
	var out []string
	for _, p := range ix.names {
		var near bool
		if ix.eco == core.Composer {
			near = composerNear(n, p)
		} else {
			near = npmNear(n, p)
		}
		if near {
			out = append(out, p)
		}
	}
	return out
}

// near is the check every name gets: edits, separators and look-alikes.
func near(n, p string) bool {
	if n == p {
		return false
	}
	if utf8.RuneCountInString(p) >= minTypoRunes && Distance(n, p, typoLimit(p)) <= typoLimit(p) {
		return true
	}
	if stripSeparators(n) == stripSeparators(p) {
		return true
	}
	return Skeleton(n) == Skeleton(p) || Skeleton(stripSeparators(n)) == Skeleton(stripSeparators(p))
}

// splitScope splits "@scope/name" into scope and name; ok is false for
// an unscoped name.
func splitScope(n string) (scope, rest string, ok bool) {
	if !strings.HasPrefix(n, "@") {
		return "", n, false
	}
	scope, rest, ok = strings.Cut(n[1:], "/")
	return scope, rest, ok
}

// npmNear compares two npm names.
func npmNear(n, p string) bool {
	ns, nr, nScoped := splitScope(n)
	ps, pr, pScoped := splitScope(p)
	switch {
	case nScoped && pScoped && ns == ps:
		return false // the scope's owner publishes both
	case nScoped && pScoped && nr == pr:
		// @type/node for @types/node: a scope one edit away.
		return Distance(ns, ps, 1) <= 1 || Skeleton(ns) == Skeleton(ps)
	case !nScoped && pScoped:
		// types-node for @types/node.
		if stripSeparators(n) == stripSeparators(ps+pr) {
			return true
		}
	case nScoped && !pScoped:
		if stripSeparators(ns+nr) == stripSeparators(p) {
			return true
		}
		// @acme/react is a fork or a wrapper, not a typo of react.
		return false
	}
	return near(n, p) || combosquat(n, p)
}

// combosquat reports whether n is p with one affix word added in front
// or behind: plain-crypto-js, crypto-js-official.
func combosquat(n, p string) bool {
	if utf8.RuneCountInString(p) < minTypoRunes+1 {
		return false
	}
	for w := range affixWords {
		for _, sep := range []string{"-", "_", "."} {
			if n == w+sep+p || n == p+sep+w {
				return true
			}
		}
	}
	return false
}

// composerNear compares vendor and package parts of two Composer names.
func composerNear(n, p string) bool {
	nv, np, okN := strings.Cut(n, "/")
	pv, pp, okP := strings.Cut(p, "/")
	if !okN || !okP {
		return near(n, p)
	}
	if nv == pv {
		return false // only the vendor publishes under its own name
	}
	return partNear(nv, pv) && (np == pp || partNear(np, pp)) ||
		np == pp && combosquat(nv, pv)
}

// partNear is near for one part of a Composer name, where an exact match
// also counts.
func partNear(n, p string) bool { return n == p || near(n, p) }
