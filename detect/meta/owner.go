// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package meta

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/secrets"

	"github.com/RhythmShahriar/sightread/core"
)

// The signals of the publisher and provenance detector.
const (
	SigOwnerChange       = "owner-change"
	SigProvenanceDropped = "provenance-dropped"
	SigGitTagMissing     = "git-tag-missing"
)

// WPOrgAccount is the WordPress.org account that takes over plugins
// under the plugin team's control (the ACF to SCF case).
const WPOrgAccount = "wordpressdotorg"

// TakeoverNote opens the evidence of an owner-change WordPress.org
// itself caused; %s is plugin or theme.
const TakeoverNote = "WordPress.org took over this %s."

func init() { core.RegisterDetector(ownerDetector{}) }

// ownerDetector compares who stands behind the installed version with
// who stands behind the candidate. It also reports a candidate that lost
// its build provenance or its git tag (PRD 12.1, market.md must-have 4).
type ownerDetector struct{}

func (ownerDetector) Info() core.DetectorInfo {
	return core.DetectorInfo{Name: "meta-owner", Signals: []string{
		SigOwnerChange, SigProvenanceDropped, SigGitTagMissing,
	}}
}

func (ownerDetector) Detect(_ context.Context, s *core.Subject, emit func(core.Finding)) {
	out := newEmitter(s, emit)
	if s.New == nil {
		return
	}
	if f, ok := ownerFinding(s); ok {
		out.send(f)
	}
	if s.Old != nil && s.Old.Provenance != "" && s.New.Provenance == "" {
		out.send(newFinding(SigProvenanceDropped,
			s.Old.Ref.Version+" was published with "+s.Old.Provenance+" provenance; "+s.New.Ref.Version+" has none"))
	}
	if s.New.GitTag != nil && !*s.New.GitTag {
		ev := "no tag v" + s.New.Ref.Version + ", " + s.New.Ref.Version + " or " + s.New.Ref.Name + "@" + s.New.Ref.Version
		if repo := safeURL(s.New.Repository); repo != "" {
			ev += " in " + repo
		}
		out.send(newFinding(SigGitTagMissing, ev))
	}
}

// ident is one person as the evidence names them, with every key they
// can be recognised by (lower-case name, login, e-mail).
type ident struct {
	label string
	keys  []string
}

// personIdent makes the ident of p. The label never shows an e-mail in
// clear: an address alone is masked.
func personIdent(p core.Person) ident {
	id := ident{}
	for _, k := range []string{p.Login, p.Name, p.Email} {
		if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
			id.keys = append(id.keys, k)
		}
	}
	switch {
	case strings.TrimSpace(p.Login) != "":
		id.label = strings.TrimSpace(p.Login)
	case strings.TrimSpace(p.Name) != "":
		id.label = strings.TrimSpace(p.Name)
	default:
		id.label = maskEmail(p.Email)
	}
	return id
}

// maskEmail keeps the first letter of the local part and the domain.
func maskEmail(e string) string {
	local, domain, ok := strings.Cut(strings.TrimSpace(e), "@")
	if !ok {
		return secrets.Mask(e, 1)
	}
	return secrets.Mask(local, 1) + "@" + domain
}

// matches reports whether a and b share a key.
func (a ident) matches(b ident) bool {
	for _, x := range a.keys {
		for _, y := range b.keys {
			if x == y {
				return true
			}
		}
	}
	return false
}

// in reports whether a matches anyone in set.
func (a ident) in(set []ident) bool {
	for _, b := range set {
		if a.matches(b) {
			return true
		}
	}
	return false
}

// owners lists the people behind one version: npm and Packagist
// maintainers; for WordPress.org also the readme contributors and the
// author profile's account.
func owners(eco core.Ecosystem, m *core.Meta) []ident {
	var out []ident
	add := func(id ident) {
		if len(id.keys) > 0 && !id.in(out) {
			out = append(out, id)
		}
	}
	for _, p := range m.Maintainers {
		add(personIdent(p))
	}
	if eco == core.WPPlugin || eco == core.WPTheme {
		for _, c := range m.Contributors {
			add(personIdent(core.Person{Login: c}))
		}
		if slug := profileSlug(m.AuthorProfile); slug != "" {
			add(personIdent(core.Person{Login: slug}))
		}
	}
	return out
}

// profileSlug returns the account of a profiles.wordpress.org URL.
func profileSlug(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || !strings.HasSuffix(strings.ToLower(u.Hostname()), "wordpress.org") {
		return ""
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	return parts[len(parts)-1]
}

// labels lists the people of a set for the evidence.
func labels(set []ident) string {
	if len(set) == 0 {
		return "none listed"
	}
	ls := make([]string, len(set))
	for i, id := range set {
		ls[i] = id.label
	}
	return list(ls)
}

// ownerFinding applies the owner-change rules of PRD 12.1:
//   - WordPress.org taking a plugin over is high, with the takeover note;
//   - no old maintainer left, or a publisher nobody saw before who is
//     not a maintainer of the candidate either, is high;
//   - old maintainers left and a newly added one published is medium;
//   - a team that only grew stays quiet.
//
// The publishers of earlier releases are not in core.Release yet, so
// "seen before" means an old maintainer or the installed version's
// publisher. WordPress.org without the SVN tag creator falls back to
// contributors, with confidence likely (PRD 0).
func ownerFinding(s *core.Subject) (core.Finding, bool) {
	if s.Old == nil {
		return core.Finding{}, false
	}
	eco := s.Update.Eco
	wp := eco == core.WPPlugin || eco == core.WPTheme
	oldSet, newSet := owners(eco, s.Old), owners(eco, s.New)
	known := append([]ident{}, oldSet...)
	if s.Old.Publisher != nil {
		if id := personIdent(*s.Old.Publisher); len(id.keys) > 0 && !id.in(known) {
			known = append(known, id)
		}
	}
	var pub *ident
	if s.New.Publisher != nil {
		if id := personIdent(*s.New.Publisher); len(id.keys) > 0 {
			pub = &id
		}
	}
	remain := 0
	for _, o := range oldSet {
		if o.in(newSet) {
			remain++
		}
	}

	word := "Maintainers"
	if wp {
		word = "Contributors"
	}
	ev := word + " before: " + labels(oldSet) + "; now: " + labels(newSet)
	if pub != nil {
		ev += "; published by " + pub.label
	}

	sev := cli.SeverityNone
	note := ""
	wporg := ident{keys: []string{WPOrgAccount}}
	switch {
	case wp && (wporg.in(newSet) || pub != nil && pub.matches(wporg)) && !wporg.in(known):
		sev = cli.SeverityHigh
		note = fmt.Sprintf(TakeoverNote, packageWord(eco)) + " "
	case len(oldSet) > 0 && len(newSet) > 0 && remain == 0:
		sev = cli.SeverityHigh
	case pub != nil && len(known) > 0 && !pub.in(known):
		sev = cli.SeverityHigh
		if pub.in(newSet) && remain > 0 {
			sev = cli.SeverityMedium
		}
	}
	if sev == cli.SeverityNone {
		return core.Finding{}, false
	}
	f := newFinding(SigOwnerChange, note+ev)
	f.Severity = sev
	if wp && s.New.Publisher == nil {
		f.Confidence = core.Likely
	}
	return f, true
}
