// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package meta

import (
	"testing"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
)

func TestDriftWording(t *testing.T) {
	s := subject(core.WPPlugin)
	s.Old.Ref.Version = "5.9.6"
	s.Drift = &core.Drift{Differ: []string{"a.php", "readme.txt", "b.php"}, Missing: []string{"c.php"}}
	f := only(t, run(t, registryDetector{}, s), SigLocalDrift)
	want := "3 files in this plugin differ from the official 5.9.6. Updating will overwrite them. a.php, b.php, c.php"
	if f.Evidence.String() != want || f.Severity != cli.SeverityInfo {
		t.Errorf("finding = %s %q, want %q", f.Severity, f.Evidence, want)
	}
	s.Drift = &core.Drift{Differ: []string{"style.css"}}
	s.Update.Eco = core.WPTheme
	f = only(t, run(t, registryDetector{}, s), SigLocalDrift)
	if want := "1 file in this theme differs from the official 5.9.6. Updating will overwrite them. style.css"; f.Evidence.String() != want {
		t.Errorf("evidence = %q, want %q", f.Evidence, want)
	}
}

func TestClosedSeverity(t *testing.T) {
	for reason, want := range map[string]cli.Severity{
		"Author Request":                 cli.SeverityHigh,
		"Closed by author request":       cli.SeverityHigh,
		"Security Issue":                 cli.SeverityCritical,
		"":                               cli.SeverityCritical,
		"Guideline Violation: Licensing": cli.SeverityCritical,
	} {
		f, ok := closedFinding(&core.Meta{Closed: true, ClosedReason: reason})
		if !ok || f.Severity != want {
			t.Errorf("reason %q: %v %s, want %s", reason, ok, f.Severity, want)
		}
	}
}

func TestAdvisoryFixesTitle(t *testing.T) {
	s := subject(core.NPM)
	s.New.Advisories = []core.Advisory{{ID: "GHSA-aaaa-bbbb-cccc", FixedIn: []string{"2.0.0"}}}
	f := only(t, run(t, registryDetector{}, s), SigKnownVulnerable)
	if f.Title != "fixes GHSA-aaaa-bbbb-cccc" || f.Severity != cli.SeverityInfo {
		t.Errorf("finding = %q %s", f.Title, f.Severity)
	}
}

func TestFixedBy(t *testing.T) {
	for _, c := range []struct {
		v     string
		fixes []string
		want  bool
	}{
		{"2.0.0", []string{"2.0.0"}, true},
		{"2.0.1", []string{"2.0.0"}, true},
		{"1.9.9", []string{"2.0.0"}, false},
		{"2.0.0", []string{"1.9.5", "2.1.0"}, false},
		{"1.9.6", []string{"1.9.5", "2.1.0"}, true},
		{"1.9.0", []string{"1.9.5", "2.1.0"}, false},
		{"3.0.0", []string{"2.1.0"}, true},
		{"1.10.0", []string{"1.9.0"}, true},
		{"2.0.0", nil, false},
		{"", []string{"1.0.0"}, false},
	} {
		if got := fixedBy(core.NPM, core.Advisory{FixedIn: c.fixes}, c.v); got != c.want {
			t.Errorf("fixedBy(%s, %v) = %v, want %v", c.v, c.fixes, got, c.want)
		}
	}
}

func TestCompareDotted(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.10.0", "1.9.0", 1}, {"1.0", "1.0.0", 0}, {"v2.0.0", "2.0.0", 0},
		{"2.0.0-rc.1", "2.0.0", -1}, {"2.0.0", "2.0.0-beta", 1}, {"1.0.0-a", "1.0.0-b", -1},
	} {
		if got := compareDotted(c.a, c.b); got != c.want {
			t.Errorf("compareDotted(%s, %s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func FuzzCompareDotted(f *testing.F) {
	for _, s := range []string{"1.0.0", "v2", "1.0.0-rc", "", "x.y", "1..2"} {
		f.Add(s, "1.0.0")
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		if compareDotted(a, a) != 0 {
			t.Fatalf("%q is not equal to itself", a)
		}
		if compareDotted(a, b) != -compareDotted(b, a) {
			t.Fatalf("not antisymmetric: %q %q", a, b)
		}
	})
}

func TestNormLicense(t *testing.T) {
	same := [][2]string{
		{"GPLv2 or later", "GPL-2.0-or-later"},
		{"GPL-2.0+", "gpl-2.0-or-later"},
		{"MIT", "The MIT License"},
		{"(MIT)", "mit"},
		{"Apache 2.0", "Apache-2.0"},
	}
	for _, p := range same {
		if NormLicense(p[0]) != NormLicense(p[1]) {
			t.Errorf("%q and %q differ: %q, %q", p[0], p[1], NormLicense(p[0]), NormLicense(p[1]))
		}
	}
	if NormLicense("GPL-2.0-only") == NormLicense("GPL-2.0-or-later") {
		t.Error("only and or-later are the same")
	}
}

func TestAbandonedByAge(t *testing.T) {
	s := subject(core.WPPlugin)
	s.Now = time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	s.New.Published = time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)
	f := only(t, run(t, registryDetector{}, s), SigAbandoned)
	if want := "no update on WordPress.org since 2024-01-15"; f.Evidence.String() != want {
		t.Errorf("evidence = %q, want %q", f.Evidence, want)
	}
	// Composer is judged by the Packagist flag only.
	s.Update.Eco = core.Composer
	for _, f := range run(t, registryDetector{}, s) {
		if f.ID == SigAbandoned {
			t.Errorf("composer by age: %+v", f)
		}
	}
}

func TestPHPAndLicenseWording(t *testing.T) {
	s := subject(core.Composer)
	s.Old.RequiresPHP, s.New.RequiresPHP = ">=7.4", "^8.1"
	s.Old.License = "MIT"
	fs := run(t, registryDetector{}, s)
	if f := only(t, fs, SigPHPRequirement); f.Evidence.String() != "require.php >=7.4 to ^8.1" {
		t.Errorf("php evidence = %q", f.Evidence)
	}
	if f := only(t, fs, SigLicenseChange); f.Evidence.String() != "license MIT to none declared" {
		t.Errorf("license evidence = %q", f.Evidence)
	}
}

func TestConfusionWording(t *testing.T) {
	s := subject(core.NPM)
	s.New.Ref.Name = "@acme/utils"
	s.New.PublicShadow = "99.0.0"
	f := only(t, run(t, registryDetector{}, s), SigDependencyConfusion)
	if want := "@acme/utils is also published on the public registry, at 99.0.0, above the private version"; f.Evidence.String() != want {
		t.Errorf("evidence = %q, want %q", f.Evidence, want)
	}
}
