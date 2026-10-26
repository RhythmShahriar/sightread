// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package meta

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
)

// The signals of the registry state detector.
const (
	SigWPOrgClosed         = "wporg-closed"
	SigKnownMalicious      = "known-malicious"
	SigKnownVulnerable     = "known-vulnerable"
	SigAbandoned           = "abandoned"
	SigLicenseChange       = "license-change"
	SigPHPRequirement      = "php-requirement"
	SigDependencyConfusion = "dependency-confusion"
	SigLocalDrift          = "local-drift"
)

// abandonedAfter is how long WordPress.org may show no update before a
// plugin or theme counts as abandoned (PRD 12.1: two years).
const abandonedAfter = 2 * 365 * 24 * time.Hour

func init() { core.RegisterDetector(registryDetector{}) }

// registryDetector reports what the sources and OSV say about the
// candidate: closed on WordPress.org, OSV records, abandoned, license
// and PHP requirement changes, a private name shadowed publicly or an
// installed copy that differs from the official one (PRD 12.1).
type registryDetector struct{}

func (registryDetector) Info() core.DetectorInfo {
	return core.DetectorInfo{Name: "meta-registry", Signals: []string{
		SigWPOrgClosed, SigKnownMalicious, SigKnownVulnerable, SigAbandoned,
		SigLicenseChange, SigPHPRequirement, SigDependencyConfusion, SigLocalDrift,
	}}
}

func (registryDetector) Detect(_ context.Context, s *core.Subject, emit func(core.Finding)) {
	out := newEmitter(s, emit)
	if s.New != nil {
		if f, ok := closedFinding(s.New); ok {
			out.send(f)
		}
		for _, f := range advisoryFindings(s) {
			out.send(f)
		}
		if f, ok := abandonedFinding(s); ok {
			out.send(f)
		}
		if f, ok := licenseFinding(s); ok {
			out.send(f)
		}
		if f, ok := phpFinding(s); ok {
			out.send(f)
		}
		if s.New.PublicShadow != "" {
			out.send(newFinding(SigDependencyConfusion, fmt.Sprintf(
				"%s is also published on the public registry, at %s, above the private version", s.New.Ref.Name, s.New.PublicShadow)))
		}
	}
	if f, ok := driftFinding(s); ok {
		out.send(f)
	}
}

// closedFinding gives wporg-closed for a closed plugin or theme: high
// when the author asked for it, critical otherwise (a guideline or
// security closure).
func closedFinding(m *core.Meta) (core.Finding, bool) {
	if !m.Closed {
		return core.Finding{}, false
	}
	reason := strings.TrimSpace(m.ClosedReason)
	ev := "closed on WordPress.org (no reason given)"
	if reason != "" {
		ev = "closed on WordPress.org: " + reason
	}
	f := newFinding(SigWPOrgClosed, ev)
	if strings.Contains(strings.ToLower(reason), "author request") {
		f.Severity = cli.SeverityHigh
	}
	return f, true
}

// advisoryFindings turns the candidate's OSV records into known-malicious
// and known-vulnerable. An advisory the candidate fixes compared with the
// installed version is info, titled "fixes <id>": it is a reason to
// update, not to hold.
func advisoryFindings(s *core.Subject) []core.Finding {
	var out []core.Finding
	listed := map[string]bool{}
	for _, a := range s.New.Advisories {
		listed[a.ID] = true
		ev := advisoryText(a)
		switch {
		case a.Malicious && !fixedBy(s.Update.Eco, a, s.New.Ref.Version):
			out = append(out, newFinding(SigKnownMalicious, ev))
		case a.Malicious:
			// A MAL record the candidate is outside of says nothing bad
			// about it; the source listed it for the package name only.
		case fixedBy(s.Update.Eco, a, s.New.Ref.Version):
			if s.Old != nil && !fixedBy(s.Update.Eco, a, s.Old.Ref.Version) {
				out = append(out, fixesFinding(a))
			}
		default:
			out = append(out, newFinding(SigKnownVulnerable, ev))
		}
	}
	if s.Old != nil {
		for _, a := range s.Old.Advisories {
			if !listed[a.ID] && !a.Malicious {
				listed[a.ID] = true
				out = append(out, fixesFinding(a))
			}
		}
	}
	return out
}

// fixesFinding is the info finding of an advisory the update fixes.
func fixesFinding(a core.Advisory) core.Finding {
	f := newFinding(SigKnownVulnerable, advisoryText(a))
	f.Title = "fixes " + a.ID
	f.Severity = cli.SeverityInfo
	f.Advice = "This update fixes it."
	return f
}

// advisoryText is "<id>: <summary> (fixed in <v>) <url>".
func advisoryText(a core.Advisory) string {
	t := a.ID
	if a.Summary != "" {
		t += ": " + a.Summary
	}
	if len(a.FixedIn) > 0 {
		t += " (fixed in " + strings.Join(a.FixedIn, ", ") + ")"
	}
	if a.URL != "" {
		t += " " + a.URL
	}
	return t
}

// fixedBy reports whether version v already has a's fix. With one
// fixed version per release line (OSV ranges), the fixes of v's own
// major line decide: 1.9.0 is not fixed by a 2.1.0 fix when 1.9.5 fixes
// the 1.x line. A line with no fix of its own is fixed when v is at or
// after any fix.
func fixedBy(eco core.Ecosystem, a core.Advisory, v string) bool {
	if v == "" || len(a.FixedIn) == 0 {
		return false
	}
	fixes := a.FixedIn
	var own []string
	for _, fix := range fixes {
		if majorOf(fix) == majorOf(v) {
			own = append(own, fix)
		}
	}
	if len(own) > 0 {
		fixes = own
	}
	for _, fix := range fixes {
		if fix == v || compareVersions(eco, v, fix) >= 0 {
			return true
		}
	}
	return false
}

// majorOf returns the first dotted part of a version.
func majorOf(v string) string {
	m, _, _ := strings.Cut(strings.TrimPrefix(v, "v"), ".")
	return m
}

// compareVersions orders two versions with the ecosystem's scheme when
// one is registered, else by their dotted numbers (pre-release text
// sorts before the release).
func compareVersions(eco core.Ecosystem, a, b string) int {
	if sc := core.Versions(eco); sc != nil && sc.Valid(a) && sc.Valid(b) {
		return sc.Compare(a, b)
	}
	return compareDotted(a, b)
}

// compareDotted compares "1.10.2" with "1.9" by number per part. A
// suffix after "-" makes a version sort before the same numbers without
// one.
func compareDotted(a, b string) int {
	a, b = strings.TrimPrefix(a, "v"), strings.TrimPrefix(b, "v")
	an, apre, _ := strings.Cut(a, "-")
	bn, bpre, _ := strings.Cut(b, "-")
	as, bs := strings.Split(an, "."), strings.Split(bn, ".")
	for i := range max(len(as), len(bs)) {
		x, y := part(as, i), part(bs, i)
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case apre == bpre:
		return 0
	case apre == "":
		return 1
	case bpre == "":
		return -1
	}
	return strings.Compare(apre, bpre)
}

func part(ps []string, i int) int {
	if i >= len(ps) {
		return 0
	}
	n, err := strconv.Atoi(ps[i])
	if err != nil {
		return 0
	}
	return n
}

// abandonedFinding gives abandoned when Packagist marks the candidate
// abandoned or WordPress.org shows no update for two years.
func abandonedFinding(s *core.Subject) (core.Finding, bool) {
	m := s.New
	if m.Abandoned {
		ev := "Packagist marks it abandoned"
		if s.Update.Eco != core.Composer {
			ev = "the source marks it abandoned"
		}
		return newFinding(SigAbandoned, ev), true
	}
	wp := s.Update.Eco == core.WPPlugin || s.Update.Eco == core.WPTheme
	if wp && !m.Published.IsZero() && !s.Now.IsZero() && s.Now.Sub(m.Published) > abandonedAfter {
		return newFinding(SigAbandoned, fmt.Sprintf("no update on WordPress.org since %s", m.Published.Format(time.DateOnly))), true
	}
	return core.Finding{}, false
}

// licenseFinding gives license-change when the declared license changed.
// Spellings of one license ("GPLv2 or later", "GPL-2.0-or-later") are
// the same license; a first declaration is not a change.
func licenseFinding(s *core.Subject) (core.Finding, bool) {
	if s.Old == nil {
		return core.Finding{}, false
	}
	o, n := strings.TrimSpace(s.Old.License), strings.TrimSpace(s.New.License)
	if o == "" || NormLicense(o) == NormLicense(n) {
		return core.Finding{}, false
	}
	if n == "" {
		n = "none declared"
	}
	return newFinding(SigLicenseChange, "license "+o+" to "+n), true
}

// licenseAliases maps common spellings to SPDX IDs, after lower-casing
// and squeezing spaces.
var licenseAliases = map[string]string{
	"gplv2":                       "gpl-2.0-only",
	"gpl v2":                      "gpl-2.0-only",
	"gpl-2.0":                     "gpl-2.0-only",
	"gpl2":                        "gpl-2.0-only",
	"gplv2 or later":              "gpl-2.0-or-later",
	"gplv2+":                      "gpl-2.0-or-later",
	"gpl-2.0+":                    "gpl-2.0-or-later",
	"gpl v2 or later":             "gpl-2.0-or-later",
	"gpl-2.0 or later":            "gpl-2.0-or-later",
	"gpl2+":                       "gpl-2.0-or-later",
	"gplv3":                       "gpl-3.0-only",
	"gpl v3":                      "gpl-3.0-only",
	"gpl-3.0":                     "gpl-3.0-only",
	"gpl3":                        "gpl-3.0-only",
	"gplv3 or later":              "gpl-3.0-or-later",
	"gplv3+":                      "gpl-3.0-or-later",
	"gpl-3.0+":                    "gpl-3.0-or-later",
	"gpl v3 or later":             "gpl-3.0-or-later",
	"gpl-3.0 or later":            "gpl-3.0-or-later",
	"the mit license":             "mit",
	"mit license":                 "mit",
	"apache 2.0":                  "apache-2.0",
	"apache-2":                    "apache-2.0",
	"apache license 2.0":          "apache-2.0",
	"apache license, version 2.0": "apache-2.0",
	"bsd":                         "bsd-3-clause",
	"isc license":                 "isc",
}

// NormLicense returns the comparable form of a license text: lower
// case, spaces squeezed, outer parentheses dropped and known spellings
// mapped to their SPDX ID.
func NormLicense(l string) string {
	l = strings.ToLower(strings.Join(strings.Fields(l), " "))
	l = strings.TrimSuffix(strings.TrimPrefix(l, "("), ")")
	if v, ok := licenseAliases[l]; ok {
		return v
	}
	return l
}

// phpFinding gives php-requirement when Requires PHP (WordPress) or
// require.php (Composer) moved.
func phpFinding(s *core.Subject) (core.Finding, bool) {
	if s.Old == nil {
		return core.Finding{}, false
	}
	o, n := strings.TrimSpace(s.Old.RequiresPHP), strings.TrimSpace(s.New.RequiresPHP)
	if o == n {
		return core.Finding{}, false
	}
	label := "Requires PHP"
	if s.Update.Eco == core.Composer {
		label = "require.php"
	}
	if o == "" {
		o = "none"
	}
	if n == "" {
		n = "none"
	}
	return newFinding(SigPHPRequirement, label+" "+o+" to "+n), true
}

// driftFinding gives local-drift when the installed copy differs from
// the official copy of its version. readme.txt and translation files
// are rebuilt or edited on sites all the time and are not counted.
func driftFinding(s *core.Subject) (core.Finding, bool) {
	if s.Drift == nil {
		return core.Finding{}, false
	}
	var files []string
	for _, p := range append(append([]string{}, s.Drift.Differ...), s.Drift.Missing...) {
		if !driftIgnored(p) {
			files = append(files, p)
		}
	}
	if len(files) == 0 {
		return core.Finding{}, false
	}
	installed := version(s.Old)
	if installed == "" {
		installed = "version"
	}
	ev := fmt.Sprintf("%s in this %s %s from the official %s. Updating will overwrite them.",
		plural(len(files), "file", "files"), packageWord(s.Update.Eco), verbFor(len(files)), installed)
	f := newFinding(SigLocalDrift, ev+" "+list(files))
	f.File = files[0]
	return f, true
}

// verbFor agrees "differ" with a count.
func verbFor(n int) string {
	if n == 1 {
		return "differs"
	}
	return "differ"
}

// driftIgnored reports whether a drifted path is one sites change on
// their own: readme.txt, .po, .mo and .pot catalogues anywhere and JSON
// script translations under languages/. PHP stays checked even there:
// a .l10n.php file is code PHP runs, so a site could hide an edit in it.
func driftIgnored(p string) bool {
	lp := strings.ToLower(p)
	if lp == "readme.txt" {
		return true
	}
	for _, ext := range []string{".po", ".mo", ".pot"} {
		if strings.HasSuffix(lp, ext) {
			return true
		}
	}
	return strings.HasPrefix(lp, "languages/") && strings.HasSuffix(lp, ".json")
}
