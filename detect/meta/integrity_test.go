// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package meta

import (
	"strings"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
	_ "github.com/RhythmShahriar/sightread/detect" // explain text for Advice
)

// run runs one detector on s and returns what it emits.
func run(t *testing.T, d core.Detector, s *core.Subject) []core.Finding {
	t.Helper()
	var out []core.Finding
	d.Detect(t.Context(), s, func(f core.Finding) { out = append(out, f) })
	return out
}

// subject is an update of fixture from 1.0.0 to 2.0.0 in eco.
func subject(eco core.Ecosystem) *core.Subject {
	return &core.Subject{
		Update:  core.Ref{Eco: eco, Name: "fixture", Version: "2.0.0"},
		Old:     &core.Meta{Ref: core.Ref{Eco: eco, Name: "fixture", Version: "1.0.0"}},
		New:     &core.Meta{Ref: core.Ref{Eco: eco, Name: "fixture", Version: "2.0.0"}},
		OldTree: coretest.TreeWith(nil, nil), NewTree: coretest.TreeWith(nil, nil),
		Config: &core.Config{},
	}
}

func only(t *testing.T, fs []core.Finding, id string) core.Finding {
	t.Helper()
	var got []core.Finding
	for _, f := range fs {
		if f.ID == id {
			got = append(got, f)
		}
	}
	if len(got) != 1 {
		t.Fatalf("want one %s finding, got %d: %+v", id, len(got), fs)
	}
	return got[0]
}

func TestMismatchWordingPRDE6(t *testing.T) {
	s := subject(core.WPPlugin)
	s.NewIntegrity = core.Integrity{By: core.ByFailed, Mismatch: []string{"includes/loader.php", "a.php", "b.php"}}
	f := only(t, run(t, integrityDetector{}, s), SigIntegrityMismatch)
	want := "Archive does not match wordpress.org checksums: 3 files differ (includes/loader.php, a.php, b.php)"
	if f.Evidence.String() != want {
		t.Errorf("evidence = %q, want %q", f.Evidence, want)
	}
	if f.Advice != "Someone between you and wordpress.org changed it, or the release was edited; don't install this copy." {
		t.Errorf("advice = %q", f.Advice)
	}
	if f.File != "includes/loader.php" || f.Severity != cli.SeverityCritical {
		t.Errorf("file %q severity %s", f.File, f.Severity)
	}
}

func TestMismatchListsAtMostFive(t *testing.T) {
	s := subject(core.WPPlugin)
	s.OldIntegrity = core.Integrity{By: core.ByFailed, Mismatch: []string{"a", "b", "c", "d", "e", "f", "g"}}
	f := only(t, run(t, integrityDetector{}, s), SigIntegrityMismatch)
	want := "installed version 1.0.0: Archive does not match wordpress.org checksums: 7 files differ (a, b, c, d, e and 2 more)"
	if f.Evidence.String() != want {
		t.Errorf("evidence = %q, want %q", f.Evidence, want)
	}
}

func TestMismatchNPMWording(t *testing.T) {
	s := subject(core.NPM)
	s.NewIntegrity = core.Integrity{By: core.ByFailed, Mismatch: []string{"sha512"}}
	f := only(t, run(t, integrityDetector{}, s), SigIntegrityMismatch)
	if want := "Archive does not match the hash the npm registry publishes: sha512 differs"; f.Evidence.String() != want {
		t.Errorf("evidence = %q, want %q", f.Evidence, want)
	}
}

func TestParseSRI(t *testing.T) {
	got := ParseSRI("sha512-AAAA sha1-AQID?opt=1 md5-AAAA nonsense sha256-!!!")
	if got["sha512"] != "AAAA" || got["sha1"] != "AQID" || len(got) != 2 {
		t.Errorf("ParseSRI = %v", got)
	}
	if len(ParseSRI("")) != 0 {
		t.Error("empty SRI gave digests")
	}
}

func FuzzParseSRI(f *testing.F) {
	for _, s := range []string{"", "sha512-AAAA", "sha1-AQID?x sha256-AAAA", "sha512-", "-", "sha512-a-b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for algo, d := range ParseSRI(s) {
			switch algo {
			case "sha1", "sha256", "sha384", "sha512":
			default:
				t.Fatalf("unknown algorithm %q from %q", algo, s)
			}
			if d == "" {
				t.Fatalf("empty digest from %q", s)
			}
			// Parsing the normalised form again gives the same digest.
			if again := ParseSRI(algo + "-" + d)[algo]; again != d {
				t.Fatalf("not stable: %q then %q", d, again)
			}
		}
	})
}

func TestRepublishedComparesPerAlgorithm(t *testing.T) {
	m := &core.Meta{Ref: core.Ref{Version: "1.0.0"}, Archive: core.ArchiveRef{Integrity: "sha512-AAAA"}}
	lock := &core.Installed{Ref: core.Ref{Version: "1.0.0"}, Integrity: "sha1-AQID"}
	if _, ok := republished(core.NPM, lock, m); ok {
		t.Error("sha1 against sha512 fired")
	}
	lock.Integrity = "sha512-AAAB"
	ev, ok := republished(core.NPM, lock, m)
	if !ok || !strings.Contains(ev, "the lockfile recorded sha512-AAAB…, the npm registry now serves sha512-AAAA…") {
		t.Errorf("evidence = %q, %v", ev, ok)
	}
}

func TestRepublishedComposerReference(t *testing.T) {
	s := subject(core.Composer)
	s.Old.Archive.Reference = "9f8e7d6c5b4a39281706f5e4d3c2b1a098765432"
	s.OldLock = &core.Installed{Ref: core.Ref{Version: "1.0.0"}, Reference: "1a2b3c4d5e6f708192a3b4c5d6e7f80912345678", Lockfile: "composer.lock", LockLine: 77}
	f := only(t, run(t, integrityDetector{}, s), SigVersionRepublished)
	want := "1.0.0: the lockfile pins commit 1a2b3c4d5e6f, Packagist now points it at 9f8e7d6c5b4a"
	if f.Evidence.String() != want || f.File != "composer.lock" || f.Line != 77 {
		t.Errorf("finding = %q at %s:%d", f.Evidence, f.File, f.Line)
	}
}

func TestSourceChangeDropsCredentials(t *testing.T) {
	s := subject(core.NPM)
	s.OldLock = &core.Installed{ResolvedKind: core.ResolvedRegistry}
	tok := "ghp_" + strings.Repeat("Ab1", 12)
	s.NewLock = &core.Installed{ResolvedKind: core.ResolvedForeign, Resolved: "https://bot:" + tok + "@cdn.evil.test/x.tgz?token=" + tok}
	f := only(t, run(t, integrityDetector{}, s), SigLockfileSourceChange)
	if strings.Contains(f.Evidence.String(), tok) || strings.Contains(f.Evidence.String(), "bot") {
		t.Errorf("credentials in evidence: %q", f.Evidence)
	}
	if want := "the lock entry moved from the registry to another host: https://cdn.evil.test/x.tgz"; f.Evidence.String() != want {
		t.Errorf("evidence = %q, want %q", f.Evidence, want)
	}
}

func TestArchiveIssuesCapped(t *testing.T) {
	s := subject(core.NPM)
	for i := range 30 {
		s.NewTree.Issues = append(s.NewTree.Issues, core.ArchiveIssue{Kind: core.IssueLink, Path: "l" + string(rune('a'+i%26)) + "x", Other: "t"})
	}
	var links []core.Finding
	for _, f := range run(t, integrityDetector{}, s) {
		if f.ID == SigArchiveLink {
			links = append(links, f)
		}
	}
	if len(links) != maxPerSignal {
		t.Fatalf("got %d link findings, want %d", len(links), maxPerSignal)
	}
	if !strings.HasSuffix(links[maxPerSignal-1].Evidence.String(), "(and 10 more like it)") {
		t.Errorf("last evidence = %q", links[maxPerSignal-1].Evidence)
	}
}

func TestArchiveEntryNamesSanitised(t *testing.T) {
	s := subject(core.WPPlugin)
	s.NewTree.Issues = []core.ArchiveIssue{
		{Kind: core.IssuePathEscape, Path: "../\x1b[31mred"},
		{Kind: core.IssueCollision, Path: "a\u202e.php", Other: "A.php"},
	}
	for _, f := range run(t, integrityDetector{}, s) {
		for _, text := range []string{f.Evidence.String(), f.File} {
			if strings.ContainsAny(text, "\x1b\u202e") {
				t.Errorf("%s: raw control or bidi text in %q", f.ID, text)
			}
		}
	}
}

func TestOldIssuesNotedOnce(t *testing.T) {
	s := subject(core.WPPlugin)
	s.OldTree.Issues = []core.ArchiveIssue{
		{Kind: core.IssueLink, Path: "a"}, {Kind: core.IssueLinkEscape, Path: "b", Other: "../../x"},
		{Kind: core.IssuePathEscape, Path: "../c"},
	}
	fs := run(t, integrityDetector{}, s)
	f := only(t, fs, SigArchiveLink)
	if f.Severity != cli.SeverityInfo || f.Demoted != DemotedOldSide {
		t.Errorf("old link note = %s %q", f.Severity, f.Demoted)
	}
	if want := "the installed 1.0.0 had 2 link entries: a, b"; f.Evidence.String() != want {
		t.Errorf("evidence = %q, want %q", f.Evidence, want)
	}
	for _, f := range fs {
		if f.ID == SigArchivePathEscape {
			t.Errorf("old side path escape emitted: %+v", f)
		}
	}
}

func TestUnanalysedOncePerPath(t *testing.T) {
	s := subject(core.Composer)
	s.NewTree.Issues = []core.ArchiveIssue{{Kind: core.IssueEncrypted, Path: "src/A.php"}}
	s.NewFeatures = &core.FeatureSet{Unanalysed: []core.Unanalysed{{Path: "src/A.php", Reason: "encrypted"}, {Path: "src/B.php"}}}
	var got []string
	for _, f := range run(t, integrityDetector{}, s) {
		if f.ID == SigUnanalysed {
			got = append(got, f.File+": "+f.Evidence.String())
		}
	}
	want := []string{"src/A.php: encrypted entry, can't be read", "src/B.php: could not be analysed: no reason given"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("unanalysed = %q, want %q", got, want)
	}
}

func TestSafeURLWithoutHost(t *testing.T) {
	tok := "ghp_" + strings.Repeat("Cd2", 12)
	for in, want := range map[string]string{
		"bot:" + tok + "@cdn.evil.test/x.tgz":     "cdn.evil.test/x.tgz",
		"git@github.com:acme/x.git#" + tok:        "github.com:acme/x.git",
		"file:../vendor/x.tgz?k=" + tok:           "file:../vendor/x.tgz",
		"https://u:" + tok + "@h.test/x?y=" + tok: "https://h.test/x",
		"github:acme/x":                           "github:acme/x",
	} {
		if got := safeURL(in); got != want {
			t.Errorf("safeURL(%q) = %q, want %q", in, got, want)
		}
	}
}
