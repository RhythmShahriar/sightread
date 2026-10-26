// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package meta

import (
	"strings"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
)

func people(names ...string) []core.Person {
	out := make([]core.Person, len(names))
	for i, n := range names {
		out[i] = core.Person{Name: n}
	}
	return out
}

func TestOwnerChangeRules(t *testing.T) {
	for _, c := range []struct {
		name     string
		old, new []string
		oldPub   string
		pub      string
		want     cli.Severity
	}{
		{"all replaced", []string{"alice", "bob"}, []string{"mallory"}, "alice", "mallory", cli.SeverityHigh},
		{"one replaced, new one published", []string{"alice", "bob"}, []string{"alice", "carol"}, "alice", "carol", cli.SeverityMedium},
		{"stranger published", []string{"acme"}, []string{"acme"}, "", "eve", cli.SeverityHigh},
		{"team grew", []string{"alice"}, []string{"alice", "bob"}, "alice", "alice", cli.SeverityNone},
		{"new member grew the team and published", []string{"alice"}, []string{"alice", "bob"}, "alice", "bob", cli.SeverityMedium},
		{"old publisher published again", []string{"alice"}, []string{"alice"}, "bob", "bob", cli.SeverityNone},
		{"no old evidence", nil, []string{"x"}, "", "x", cli.SeverityNone},
		{"same people", []string{"a", "b"}, []string{"b", "a"}, "", "", cli.SeverityNone},
	} {
		s := subject(core.NPM)
		s.Old.Maintainers, s.New.Maintainers = people(c.old...), people(c.new...)
		if c.oldPub != "" {
			s.Old.Publisher = &core.Person{Name: c.oldPub}
		}
		if c.pub != "" {
			s.New.Publisher = &core.Person{Name: c.pub}
		}
		f, ok := ownerFinding(s)
		got := cli.SeverityNone
		if ok {
			got = f.Severity
		}
		if got != c.want {
			t.Errorf("%s: severity %s, want %s (%q)", c.name, got, c.want, f.Evidence)
		}
	}
}

func TestOwnerChangeEvidence(t *testing.T) {
	s := subject(core.NPM)
	s.Old.Maintainers = people("alice", "bob")
	s.New.Maintainers = []core.Person{{Email: "mallory@evil.test"}}
	s.New.Publisher = &core.Person{Email: "mallory@evil.test"}
	f := only(t, run(t, ownerDetector{}, s), SigOwnerChange)
	ev := f.Evidence.String()
	if strings.Contains(ev, "mallory@") {
		t.Errorf("e-mail in clear: %q", ev)
	}
	if want := "Maintainers before: alice, bob; now: "; !strings.HasPrefix(ev, want) || !strings.Contains(ev, "@evil.test; published by ") {
		t.Errorf("evidence = %q", ev)
	}
	if f.Confidence != core.Confirmed || f.Severity != cli.SeverityHigh {
		t.Errorf("finding = %s %s", f.Severity, f.Confidence)
	}
}

func TestWordPressTakeoverNote(t *testing.T) {
	s := subject(core.WPPlugin)
	s.Old.Contributors = []string{"elliotcondon"}
	s.Old.AuthorProfile = "https://profiles.wordpress.org/deliciousbrains/"
	s.New.Contributors = []string{"elliotcondon", "wordpressdotorg"}
	f := only(t, run(t, ownerDetector{}, s), SigOwnerChange)
	want := "WordPress.org took over this plugin. Contributors before: elliotcondon, deliciousbrains; now: elliotcondon, wordpressdotorg"
	if f.Evidence.String() != want || f.Severity != cli.SeverityHigh {
		t.Errorf("finding = %s %q, want %q", f.Severity, f.Evidence, want)
	}
	// Without the SVN tag creator the evidence is contributors only.
	if f.Confidence != core.Likely {
		t.Errorf("confidence = %s, want likely", f.Confidence)
	}
}

func TestTakeoverAlreadyKnownIsQuiet(t *testing.T) {
	s := subject(core.WPTheme)
	s.Old.Contributors = []string{"wordpressdotorg"}
	s.New.Contributors = []string{"wordpressdotorg"}
	s.New.Publisher = &core.Person{Login: "wordpressdotorg"}
	for _, f := range run(t, ownerDetector{}, s) {
		t.Errorf("unexpected %s: %q", f.ID, f.Evidence)
	}
}

func TestProfileSlug(t *testing.T) {
	for in, want := range map[string]string{
		"https://profiles.wordpress.org/deliciousbrains/": "deliciousbrains",
		"https://profiles.wordpress.org/a":                "a",
		"https://example.test/a":                          "",
		"":                                                "",
		"::bad":                                           "",
	} {
		if got := profileSlug(in); got != want {
			t.Errorf("profileSlug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestProvenanceAndTagWording(t *testing.T) {
	s := subject(core.NPM)
	s.Old.Provenance = "slsa"
	no := false
	s.New.GitTag = &no
	s.New.Repository = "https://bot:secret@github.com/acme/fixture"
	fs := run(t, ownerDetector{}, s)
	if f := only(t, fs, SigProvenanceDropped); f.Evidence.String() != "1.0.0 was published with slsa provenance; 2.0.0 has none" {
		t.Errorf("provenance evidence = %q", f.Evidence)
	}
	if f := only(t, fs, SigGitTagMissing); f.Evidence.String() != "no tag v2.0.0, 2.0.0 or fixture@2.0.0 in https://github.com/acme/fixture" {
		t.Errorf("tag evidence = %q", f.Evidence)
	}
}
