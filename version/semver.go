// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package version

import (
	"fmt"
	"regexp"
	"strings"
)

// NPM is the version scheme of npm: semver 2.0.0 versions and the range
// grammar of node-semver (exact, =, <, <=, >, >=, ^, ~, x and *
// wildcards, hyphen ranges, || unions and space-separated
// intersections), without its loose mode. As in node-semver, a
// prerelease satisfies a range only through a comparator with the same
// major.minor.patch that has a prerelease itself, so ^1.2.3 never picks
// 1.9.0-beta.
var NPM = npmScheme{}

type npmScheme struct{}

// semver is one parsed version. Numbers are kept as digit strings, so a
// version past 2^64 still orders.
type semver struct {
	nums [3]string
	pre  []string
}

// identifier is one dot-separated piece of a prerelease or build.
const identifier = `[0-9A-Za-z-]+`

var (
	numeric = `0|[1-9][0-9]*`
	// semverRe is a full version, with the v or = node-semver strips.
	semverRe = regexp.MustCompile(`^[v=]?\s*(` + numeric + `)\.(` + numeric + `)\.(` + numeric + `)` +
		`(?:-(` + identifier + `(?:\.` + identifier + `)*))?(?:\+` + identifier + `(?:\.` + identifier + `)*)?$`)
	// partialRe is a version in a range, where parts may be missing or
	// x, X or *.
	xr        = `x|X|\*|` + numeric
	partialRe = regexp.MustCompile(`^v?(` + xr + `)(?:\.(` + xr + `)(?:\.(` + xr + `)` +
		`(?:-(` + identifier + `(?:\.` + identifier + `)*))?(?:\+` + identifier + `(?:\.` + identifier + `)*)?)?)?$`)
	hyphenRe = regexp.MustCompile(`^\s*(\S+)\s+-\s+(\S+)\s*$`)
)

// parseSemver reads a full version.
func parseSemver(s string) (semver, bool) {
	if len(s) > maxVersion {
		return semver{}, false
	}
	m := semverRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return semver{}, false
	}
	v := semver{nums: [3]string{m[1], m[2], m[3]}}
	if m[4] != "" {
		v.pre = strings.Split(m[4], ".")
		for _, id := range v.pre {
			if len(id) > 1 && id[0] == '0' && allDigits(id) {
				return semver{}, false // numeric identifiers have no leading zeros
			}
		}
	}
	return v, true
}

func allDigits(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return s != ""
}

// compare orders two parsed versions by semver 2.0.0 precedence.
func (a semver) compare(b semver) int {
	for i := range a.nums {
		if c := cmpDigits(a.nums[i], b.nums[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(a.pre) == 0 && len(b.pre) == 0:
		return 0
	case len(a.pre) == 0:
		return 1
	case len(b.pre) == 0:
		return -1
	}
	for i := 0; i < len(a.pre) && i < len(b.pre); i++ {
		x, y := a.pre[i], b.pre[i]
		dx, dy := allDigits(x), allDigits(y)
		var c int
		switch {
		case dx && dy:
			c = cmpDigits(x, y)
		case dx:
			c = -1 // numeric identifiers rank below alphanumeric ones
		case dy:
			c = 1
		default:
			c = strings.Compare(x, y)
		}
		if c != 0 {
			return c
		}
	}
	return sign(len(a.pre) - len(b.pre))
}

func (a semver) sameTuple(b semver) bool { return a.nums == b.nums }

// Valid reports whether v is a semver 2.0.0 version.
func (npmScheme) Valid(v string) bool { _, ok := parseSemver(v); return ok }

// Compare orders a and b by semver precedence; build metadata is
// ignored. An invalid version orders before every valid one.
func (npmScheme) Compare(a, b string) int {
	va, oka := parseSemver(a)
	vb, okb := parseSemver(b)
	switch {
	case !oka && !okb:
		return strings.Compare(a, b)
	case !oka:
		return -1
	case !okb:
		return 1
	}
	return va.compare(vb)
}

// Prerelease reports whether v has a prerelease part.
func (npmScheme) Prerelease(v string) bool {
	s, ok := parseSemver(v)
	return ok && len(s.pre) > 0
}

// Satisfies reports whether v is in the node-semver range. An invalid v
// satisfies nothing; an invalid range is an error.
func (npmScheme) Satisfies(v, rng string) (bool, error) {
	sets, err := parseRange(rng)
	if err != nil {
		return false, err
	}
	sv, ok := parseSemver(v)
	if !ok {
		return false, nil
	}
	for _, set := range sets {
		if set.test(sv) {
			return true, nil
		}
	}
	return false, nil
}

// comparator is one bound; op "" matches any version.
type comparator struct {
	op string
	v  semver
}

type comparatorSet []comparator

// test is node-semver's testSet: every comparator matches and a
// prerelease is only let in by a comparator of its own tuple.
func (cs comparatorSet) test(v semver) bool {
	for _, c := range cs {
		if c.op != "" && !compareOp(c.op, v.compare(c.v)) {
			return false
		}
	}
	if len(v.pre) == 0 {
		return true
	}
	for _, c := range cs {
		if c.op != "" && len(c.v.pre) > 0 && c.v.sameTuple(v) {
			return true
		}
	}
	return false
}

// parseRange reads a range into its || alternatives.
func parseRange(rng string) ([]comparatorSet, error) {
	if len(rng) > maxConstraint {
		return nil, fmt.Errorf("range is over %d bytes", maxConstraint)
	}
	var sets []comparatorSet
	for _, part := range strings.Split(rng, "||") {
		set, err := parseRangePart(part)
		if err != nil {
			return nil, fmt.Errorf("range %q: %w", rng, err)
		}
		sets = append(sets, set)
	}
	return sets, nil
}

// parseRangePart reads one alternative: a hyphen range or a list of
// simple ranges that must all hold.
func parseRangePart(part string) (comparatorSet, error) {
	if m := hyphenRe.FindStringSubmatch(part); m != nil {
		return hyphenRange(m[1], m[2])
	}
	var set comparatorSet
	for _, tok := range strings.Fields(joinOps(part)) {
		cs, err := simpleRange(tok)
		if err != nil {
			return nil, err
		}
		set = append(set, cs...)
	}
	if len(set) == 0 {
		set = comparatorSet{{}} // "" is *
	}
	return set, nil
}

// partial is a version in a range with its x parts marked.
type partial struct {
	nums [3]string // "" where the part is x or missing
	pre  []string
}

func (p partial) x(i int) bool { return p.nums[i] == "" }

func parsePartial(s string) (partial, error) {
	m := partialRe.FindStringSubmatch(s)
	if m == nil {
		return partial{}, fmt.Errorf("%q is not a version", s)
	}
	var p partial
	for i := range 3 {
		if n := m[i+1]; n != "x" && n != "X" && n != "*" {
			p.nums[i] = n
		}
	}
	// node-semver reads 1.x.3 as 1.x: a part after an x is ignored.
	for i := 1; i < 3; i++ {
		if p.x(i - 1) {
			p.nums[i] = ""
		}
	}
	if m[4] != "" {
		p.pre = strings.Split(m[4], ".")
	}
	return p, nil
}

// at builds the version M.m.p with an optional prerelease.
func at(major, minor, patch string, pre ...string) semver {
	return semver{nums: [3]string{major, minor, patch}, pre: pre}
}

// lowest is the prerelease "0", the smallest of a tuple: <2.0.0-0 keeps
// 2.0.0's prereleases out.
var lowest = []string{"0"}

func ge(v semver) comparator { return comparator{op: ">=", v: v} }
func lt(v semver) comparator { return comparator{op: "<", v: v} }

// simpleRange desugars one token: ^, ~, an operator and a partial
// version, or a bare partial.
func simpleRange(tok string) ([]comparator, error) {
	switch {
	case strings.HasPrefix(tok, "^"):
		return caret(tok[1:])
	case strings.HasPrefix(tok, "~>"):
		return tilde(tok[2:])
	case strings.HasPrefix(tok, "~"):
		return tilde(tok[1:])
	}
	op, rest := splitOp(tok)
	switch op {
	case "<>", "!=", "==":
		return nil, fmt.Errorf("%q: npm ranges have no %s", tok, op)
	}
	return xRange(op, rest)
}

func tilde(s string) ([]comparator, error) {
	p, err := parsePartial(s)
	if err != nil {
		return nil, err
	}
	M, m, pt := p.nums[0], p.nums[1], p.nums[2]
	switch {
	case p.x(0):
		return []comparator{{}}, nil
	case p.x(1):
		return []comparator{ge(at(M, "0", "0")), lt(at(incr(M), "0", "0", lowest...))}, nil
	case p.x(2):
		return []comparator{ge(at(M, m, "0")), lt(at(M, incr(m), "0", lowest...))}, nil
	}
	return []comparator{ge(at(M, m, pt, p.pre...)), lt(at(M, incr(m), "0", lowest...))}, nil
}

func caret(s string) ([]comparator, error) {
	p, err := parsePartial(s)
	if err != nil {
		return nil, err
	}
	M, m, pt := p.nums[0], p.nums[1], p.nums[2]
	switch {
	case p.x(0):
		return []comparator{{}}, nil
	case p.x(1):
		return []comparator{ge(at(M, "0", "0")), lt(at(incr(M), "0", "0", lowest...))}, nil
	case p.x(2):
		if M == "0" {
			return []comparator{ge(at(M, m, "0")), lt(at(M, incr(m), "0", lowest...))}, nil
		}
		return []comparator{ge(at(M, m, "0")), lt(at(incr(M), "0", "0", lowest...))}, nil
	}
	low := ge(at(M, m, pt, p.pre...))
	switch {
	case M == "0" && m == "0":
		return []comparator{low, lt(at(M, m, incr(pt), lowest...))}, nil
	case M == "0":
		return []comparator{low, lt(at(M, incr(m), "0", lowest...))}, nil
	}
	return []comparator{low, lt(at(incr(M), "0", "0", lowest...))}, nil
}

// xRange is node-semver's replaceXRange plus the plain comparator.
func xRange(op, s string) ([]comparator, error) {
	p, err := parsePartial(s)
	if err != nil {
		return nil, err
	}
	if op == "=" {
		op = ""
	}
	M, m, pt := p.nums[0], p.nums[1], p.nums[2]
	anyX := p.x(0) || p.x(1) || p.x(2)
	switch {
	case p.x(0):
		if op == ">" || op == "<" {
			return []comparator{lt(at("0", "0", "0", lowest...))}, nil // nothing
		}
		return []comparator{{}}, nil
	case op != "" && anyX:
		if p.x(1) {
			m = "0"
		}
		pt = "0"
		var pre []string
		switch op {
		case ">":
			op = ">="
			if p.x(1) {
				M, m = incr(M), "0"
			} else {
				m = incr(m)
			}
		case "<=":
			op = "<"
			if p.x(1) {
				M = incr(M)
			} else {
				m = incr(m)
			}
		}
		if op == "<" {
			pre = lowest
		}
		return []comparator{{op: op, v: at(M, m, pt, pre...)}}, nil
	case p.x(1):
		return []comparator{ge(at(M, "0", "0")), lt(at(incr(M), "0", "0", lowest...))}, nil
	case p.x(2):
		return []comparator{ge(at(M, m, "0")), lt(at(M, incr(m), "0", lowest...))}, nil
	}
	if op == "" {
		op = "="
	}
	return []comparator{{op: op, v: at(M, m, pt, p.pre...)}}, nil
}

// hyphenRange is "from - to", inclusive on full versions.
func hyphenRange(from, to string) (comparatorSet, error) {
	f, err := parsePartial(from)
	if err != nil {
		return nil, err
	}
	t, err := parsePartial(to)
	if err != nil {
		return nil, err
	}
	var set comparatorSet
	switch {
	case f.x(0):
	case f.x(1):
		set = append(set, ge(at(f.nums[0], "0", "0")))
	case f.x(2):
		set = append(set, ge(at(f.nums[0], f.nums[1], "0")))
	default:
		set = append(set, ge(at(f.nums[0], f.nums[1], f.nums[2], f.pre...)))
	}
	switch {
	case t.x(0):
	case t.x(1):
		set = append(set, lt(at(incr(t.nums[0]), "0", "0", lowest...)))
	case t.x(2):
		set = append(set, lt(at(t.nums[0], incr(t.nums[1]), "0", lowest...)))
	default:
		set = append(set, comparator{op: "<=", v: at(t.nums[0], t.nums[1], t.nums[2], t.pre...)})
	}
	if len(set) == 0 {
		set = comparatorSet{{}}
	}
	return set, nil
}

// incr adds one to a digit string.
func incr(s string) string {
	b := []byte(s)
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] < '9' {
			b[i]++
			return string(b)
		}
		b[i] = '0'
	}
	return "1" + string(b)
}
