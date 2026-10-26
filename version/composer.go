// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package version

import (
	"fmt"
	"regexp"
	"strings"
)

// Composer is the version scheme of Composer, after its VersionParser:
// a v prefix, up to four numbers, stability suffixes (-dev, -alpha,
// -beta, -RC, -stable, -patch and the short a, b, p, pl), dev-<branch>
// and 1.x-dev branches, date versions and +build metadata. Constraints
// take ^, ~, * and x wildcards, comparison operators, hyphen ranges,
// "," or space as AND and "|" or "||" as OR. An @stability flag is
// accepted and changes nothing here: it lowers the minimum stability,
// which core.Newest leaves to its pre argument. A branch alias
// (extra.branch-alias) is resolved by the caller before it asks.
var Composer = composerScheme{}

type composerScheme struct{}

const (
	stabilities = `stable|beta|b|RC|alpha|a|patch|pl|p`
	modifier    = `[._-]?(?:(` + stabilities + `)((?:[.-]?\d+)*)?)?([.-]?dev)?`
	// branchMax stands for the x of a 1.x-dev branch.
	branchMax = "9999999"
)

var (
	classicalRe = regexp.MustCompile(`(?i)^v?(\d{1,5})(\.\d+)?(\.\d+)?(\.\d+)?` + modifier + `$`)
	dateRe      = regexp.MustCompile(`(?i)^v?(\d{4}(?:[.:-]?\d{2}){1,6}(?:[.:-]?\d{1,3}){0,2})` + modifier + `$`)
	branchRe    = regexp.MustCompile(`(?i)^v?(\d+)(\.(?:\d+|[xX*]))?(\.(?:\d+|[xX*]))?(\.(?:\d+|[xX*]))?$`)
	devSuffixRe = regexp.MustCompile(`(?i)^(.*?)[.-]?dev$`)
	aliasRe     = regexp.MustCompile(`^([^,\s]+) +as +([^,\s]+)$`)
	flagRe      = regexp.MustCompile(`(?i)^([^,\s]*?)@(stable|RC|beta|alpha|dev)$`)
	refRe       = regexp.MustCompile(`(?i)^(dev-[^,\s@]+?|[^,\s@]+?\.x-dev)#.+$`)
	anyRe       = regexp.MustCompile(`(?i)^(v)?[xX*](\.[xX*])*$`)
	versionPart = `v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?` + modifier + `(?:\+[^\s]+)?`
	tildeRe     = regexp.MustCompile(`(?i)^~` + versionPart + `$`)
	caretRe     = regexp.MustCompile(`(?i)^\^` + versionPart + `$`)
	wildcardRe  = regexp.MustCompile(`^v?(\d+)(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:\.[xX*])+$`)
	cHyphenRe   = regexp.MustCompile(`(?i)^(` + versionPart + `) +- +(` + versionPart + `)$`)
	basicRe     = regexp.MustCompile(`(?s)^(<>|!=|>=?|<=?|==?)?\s*(.*)$`)
	orSplitRe   = regexp.MustCompile(`\s*\|\|?\s*`)
	modEndRe    = regexp.MustCompile(`(?i)-` + modifier + `$`)
	stabilityRe = regexp.MustCompile(`(?i)` + modifier + `(?:\+.*)?$`)
)

// normalize turns a version into Composer's normal form, "1.2.0.0",
// "1.2.0.0-beta2", "1.9999999.9999999.9999999-dev" or "dev-main".
func normalize(v string) (string, error) {
	v = strings.TrimSpace(v)
	orig := v
	if len(v) > maxVersion || v == "" {
		return "", fmt.Errorf("invalid version %q", orig)
	}
	if m := aliasRe.FindStringSubmatch(v); m != nil {
		v = m[1]
	}
	if m := flagRe.FindStringSubmatch(v); m != nil && m[1] != "" {
		v = m[1]
	}
	switch low := strings.ToLower(v); {
	case low == "master" || low == "trunk" || low == "default":
		return "dev-" + v, nil
	case strings.HasPrefix(low, "dev-"):
		if len(v) == 4 {
			return "", fmt.Errorf("invalid version %q", orig)
		}
		return "dev-" + v[4:], nil
	}
	if i := strings.IndexByte(v, '+'); i > 0 && !strings.ContainsAny(v[:i], ", ") && !strings.ContainsAny(v[i+1:], " \t") {
		v = v[:i]
	}
	if m := classicalRe.FindStringSubmatch(v); m != nil {
		out := m[1] + or0(m[2]) + or0(m[3]) + or0(m[4])
		return withModifier(out, m[5], m[6], m[7]), nil
	}
	if m := dateRe.FindStringSubmatch(v); m != nil {
		out := strings.NewReplacer("-", ".", ":", ".").Replace(m[1])
		return withModifier(out, m[2], m[3], m[4]), nil
	}
	if m := devSuffixRe.FindStringSubmatch(v); m != nil {
		if b := branchRe.FindStringSubmatch(m[1]); b != nil {
			out := b[1]
			for _, p := range b[2:] {
				if p == "" {
					p = ".x"
				}
				out += strings.NewReplacer("*", "x", "X", "x").Replace(p)
			}
			return strings.ReplaceAll(out, "x", branchMax) + "-dev", nil
		}
	}
	return "", fmt.Errorf("invalid version %q", orig)
}

func or0(s string) string {
	if s == "" {
		return ".0"
	}
	return s
}

// withModifier appends the stability as Composer writes it.
func withModifier(v, stability, nums, dev string) string {
	if stability != "" {
		if stability == "stable" {
			return v
		}
		v += "-" + expandStability(stability) + strings.TrimLeft(nums, ".-")
	}
	if dev != "" {
		v += "-dev"
	}
	return v
}

func expandStability(s string) string {
	switch s = strings.ToLower(s); s {
	case "a":
		return "alpha"
	case "b":
		return "beta"
	case "p", "pl":
		return "patch"
	case "rc":
		return "RC"
	}
	return s
}

// stability is Composer's parseStability of a normal form.
func stability(n string) string {
	if strings.HasPrefix(n, "dev-") || strings.HasSuffix(n, "-dev") {
		return "dev"
	}
	m := stabilityRe.FindStringSubmatch(strings.ToLower(n))
	switch {
	case m == nil:
		return "stable"
	case m[3] != "":
		return "dev"
	case m[1] == "beta" || m[1] == "b":
		return "beta"
	case m[1] == "alpha" || m[1] == "a":
		return "alpha"
	case m[1] == "rc":
		return "RC"
	}
	return "stable"
}

// Valid reports whether Composer can normalise v.
func (composerScheme) Valid(v string) bool { _, err := normalize(v); return err == nil }

// Compare orders a and b by their normal forms with version_compare. A
// dev-<branch> orders before every numbered version and branches order
// by name; an invalid version orders first.
func (composerScheme) Compare(a, b string) int {
	na, ea := normalize(a)
	nb, eb := normalize(b)
	switch {
	case ea != nil && eb != nil:
		return strings.Compare(a, b)
	case ea != nil:
		return -1
	case eb != nil:
		return 1
	}
	return compareNormal(na, nb)
}

func compareNormal(a, b string) int {
	ba, bb := strings.HasPrefix(a, "dev-"), strings.HasPrefix(b, "dev-")
	switch {
	case ba && bb:
		return strings.Compare(a, b)
	case ba:
		return -1
	case bb:
		return 1
	}
	return phpCompare(a, b)
}

// Prerelease reports whether v is less than stable: dev, alpha, beta or
// RC, including every branch.
func (composerScheme) Prerelease(v string) bool {
	n, err := normalize(v)
	return err == nil && stability(n) != "stable"
}

// Satisfies reports whether v meets the constraint as Composer's
// constraint classes decide it: a branch matches only == or != of
// itself (and *).
func (composerScheme) Satisfies(v, constraint string) (bool, error) {
	sets, err := parseComposer(constraint)
	if err != nil {
		return false, err
	}
	n, err := normalize(v)
	if err != nil {
		return false, nil //nolint:nilerr // an invalid version satisfies nothing
	}
	for _, set := range sets {
		if set.match(n) {
			return true, nil
		}
	}
	return false, nil
}

// composerMatch is Constraint::versionCompare on normal forms.
func composerMatch(c comparison, n string) bool {
	if c.op == "*" {
		return true
	}
	ba, bb := strings.HasPrefix(n, "dev-"), strings.HasPrefix(c.v, "dev-")
	switch {
	case (c.op == "!=" || c.op == "<>") && (ba || bb):
		return n != c.v
	case ba && bb:
		return (c.op == "=" || c.op == "==") && n == c.v
	case ba || bb:
		return false
	}
	return compareOp(c.op, phpCompare(n, c.v))
}

// composerSet is a list of comparisons on normal forms.
type composerSet []comparison

func (cs composerSet) match(n string) bool {
	for _, c := range cs {
		if !composerMatch(c, n) {
			return false
		}
	}
	return true
}

// parseComposer reads a constraint into its OR alternatives.
func parseComposer(constraint string) ([]composerSet, error) {
	if len(constraint) > maxConstraint {
		return nil, fmt.Errorf("constraint is over %d bytes", maxConstraint)
	}
	c := strings.TrimSpace(constraint)
	if c == "" {
		return nil, fmt.Errorf("empty constraint")
	}
	if m := aliasRe.FindStringSubmatch(c); m != nil {
		c = m[1]
	}
	var sets []composerSet
	for _, or := range orSplitRe.Split(c, -1) {
		var set composerSet
		for _, part := range splitAnd(or) {
			cs, err := parseOneComposer(part)
			if err != nil {
				return nil, fmt.Errorf("constraint %q: %w", constraint, err)
			}
			set = append(set, cs...)
		}
		if len(set) == 0 {
			return nil, fmt.Errorf("constraint %q: empty alternative", constraint)
		}
		sets = append(sets, set)
	}
	return sets, nil
}

// splitAnd cuts one alternative at commas and spaces, keeping a hyphen
// range and an operator with its version together.
func splitAnd(s string) []string {
	s = joinOps(strings.TrimSpace(s))
	f := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
	var out []string
	for i := 0; i < len(f); i++ {
		if i+2 < len(f) && f[i+1] == "-" {
			out = append(out, f[i]+" - "+f[i+2])
			i += 2
			continue
		}
		out = append(out, f[i])
	}
	return out
}

// parseOneComposer is VersionParser::parseConstraint.
func parseOneComposer(c string) ([]comparison, error) {
	flag := ""
	if m := flagRe.FindStringSubmatch(c); m != nil {
		c = m[1]
		if c == "" {
			c = "*"
		}
		if !strings.EqualFold(m[2], "stable") {
			flag = strings.ToLower(m[2])
		}
	}
	if m := refRe.FindStringSubmatch(c); m != nil {
		c = m[1]
	}
	if m := anyRe.FindStringSubmatch(c); m != nil {
		if m[1] != "" || m[2] != "" {
			return []comparison{{op: ">=", v: "0.0.0.0-dev"}}, nil
		}
		return []comparison{{op: "*"}}, nil
	}
	if strings.HasPrefix(c, "~>") {
		return nil, fmt.Errorf("%q: ~> is not a Composer operator; use ~", c)
	}
	if m := tildeRe.FindStringSubmatch(c); m != nil {
		return composerTilde(c, m)
	}
	if m := caretRe.FindStringSubmatch(c); m != nil {
		return composerCaret(c, m)
	}
	if m := wildcardRe.FindStringSubmatch(c); m != nil {
		pos := 1
		switch {
		case isWildNum(m[3]):
			pos = 3
		case isWildNum(m[2]):
			pos = 2
		}
		nums := [5]string{"", m[1], m[2], m[3], ""}
		low := manipulate(nums, pos, 0) + "-dev"
		high := manipulate(nums, pos, 1) + "-dev"
		if low == "0.0.0.0-dev" {
			return []comparison{{op: "<", v: high}}, nil
		}
		return []comparison{{op: ">=", v: low}, {op: "<", v: high}}, nil
	}
	if m := cHyphenRe.FindStringSubmatch(c); m != nil {
		return composerHyphen(m)
	}
	m := basicRe.FindStringSubmatch(c)
	n, err := normalize(m[2])
	if err != nil {
		return nil, err
	}
	op := m[1]
	if op == "" {
		op = "="
	}
	switch {
	case op != "==" && op != "=" && flag != "" && stability(n) == "stable":
		n += "-" + flag
	case op == "<" || op == ">=":
		if !modEndRe.MatchString(strings.ToLower(m[2])) && !strings.HasPrefix(m[2], "dev-") {
			n += "-dev"
		}
	}
	return []comparison{{op: op, v: n}}, nil
}

func isWildNum(s string) bool { return s != "" && s != "x" && s != "X" && s != "*" }

// The submatches of versionPart: four numbers, the stability word, its
// numbers and the dev suffix.
const (
	vpStability = 5
	vpDev       = 7
)

func composerTilde(c string, m []string) ([]comparison, error) {
	pos := 1
	for i := 4; i > 1; i-- {
		if m[i] != "" {
			pos = i
			break
		}
	}
	suffix := ""
	if m[vpStability] == "" && m[vpDev] == "" {
		suffix = "-dev"
	}
	low, err := normalize(c[1:] + suffix)
	if err != nil {
		return nil, err
	}
	high := manipulate([5]string{"", m[1], m[2], m[3], m[4]}, max(1, pos-1), 1) + "-dev"
	return []comparison{{op: ">=", v: low}, {op: "<", v: high}}, nil
}

func composerCaret(c string, m []string) ([]comparison, error) {
	pos := 3
	switch {
	case m[1] != "0" || m[2] == "":
		pos = 1
	case m[2] != "0" || m[3] == "":
		pos = 2
	}
	suffix := ""
	if m[vpStability] == "" && m[vpDev] == "" {
		suffix = "-dev"
	}
	low, err := normalize(c[1:] + suffix)
	if err != nil {
		return nil, err
	}
	high := manipulate([5]string{"", m[1], m[2], m[3], m[4]}, pos, 1) + "-dev"
	return []comparison{{op: ">=", v: low}, {op: "<", v: high}}, nil
}

// composerHyphen is "from - to". The groups of cHyphenRe are the whole
// from (1), its versionPart groups (2-8), the whole to (9) and its
// groups (10-16).
func composerHyphen(m []string) ([]comparison, error) {
	from, to := m[1], m[9]
	suffix := ""
	if m[1+vpStability] == "" && m[1+vpDev] == "" {
		suffix = "-dev"
	}
	low, err := normalize(from)
	if err != nil {
		return nil, err
	}
	out := []comparison{{op: ">=", v: low + suffix}}
	high, err := normalize(to)
	if err != nil {
		return nil, err
	}
	t := m[9:]
	if t[2] != "" && t[3] != "" || t[vpStability] != "" || t[vpDev] != "" {
		return append(out, comparison{op: "<=", v: high}), nil
	}
	pos := 2
	if t[2] == "" {
		pos = 1
	}
	return append(out, comparison{op: "<", v: manipulate([5]string{"", t[1], t[2], t[3], t[4]}, pos, 1) + "-dev"}), nil
}

// manipulate is VersionParser::manipulateVersionString: zero the parts
// after pos and add inc to the part at pos.
func manipulate(nums [5]string, pos, inc int) string {
	for i := 4; i > 0; i-- {
		switch {
		case i > pos:
			nums[i] = "0"
		case i == pos && inc > 0:
			nums[i] = incr(strings.TrimLeft(nums[i], "0"))
		case nums[i] == "":
			nums[i] = "0"
		}
	}
	return nums[1] + "." + nums[2] + "." + nums[3] + "." + nums[4]
}
