// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package version

import (
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
)

// The normal forms and constraint expansions below are copied by hand
// from Composer's VersionParserTest and the examples of
// getcomposer.org/doc/articles/versions.md.

func TestComposerNormalize(t *testing.T) {
	for in, want := range map[string]string{
		"1.0.0":                        "1.0.0.0",
		"1.2.3.4":                      "1.2.3.4",
		"1.0.0RC1dev":                  "1.0.0.0-RC1-dev",
		"1.0.0-rC15-dev":               "1.0.0.0-RC15-dev",
		"1.0.0.RC.15-dev":              "1.0.0.0-RC15-dev",
		"1.0.0-rc1":                    "1.0.0.0-RC1",
		"1.0.0.pl3-dev":                "1.0.0.0-patch3-dev",
		"1.0-dev":                      "1.0.0.0-dev",
		"0":                            "0.0.0.0",
		"10.4.13-beta":                 "10.4.13.0-beta",
		"10.4.13beta2":                 "10.4.13.0-beta2",
		"10.4.13beta.2":                "10.4.13.0-beta2",
		"v1.13.11-beta.0":              "1.13.11.0-beta0",
		"10.4.13-b":                    "10.4.13.0-beta",
		"10.4.13-b5":                   "10.4.13.0-beta5",
		"v1.0.0":                       "1.0.0.0",
		"2010.01":                      "2010.01.0.0",
		"2010.01.02":                   "2010.01.02.0",
		"2010.1.555":                   "2010.1.555.0",
		"v20100102":                    "20100102",
		"2010-01-02":                   "2010.01.02",
		"2010-01-02.5":                 "2010.01.02.5",
		"20100102-203040":              "20100102.203040",
		"20100102203040-10":            "20100102203040.10",
		"20100102-203040-p1":           "20100102.203040-patch1",
		"201903.x-dev":                 "201903.9999999.9999999.9999999-dev",
		"dev-master":                   "dev-master",
		"master":                       "dev-master",
		"dev-trunk":                    "dev-trunk",
		"1.x-dev":                      "1.9999999.9999999.9999999-dev",
		"2.1.x-dev":                    "2.1.9999999.9999999-dev",
		"dev-feature-foo":              "dev-feature-foo",
		"DEV-FOOBAR":                   "dev-FOOBAR",
		"dev-feature/foo":              "dev-feature/foo",
		"dev-master as 1.0.0":          "dev-master",
		"1.0.0+foo@dev":                "1.0.0.0",
		"dev-load-varnish@stable":      "dev-load-varnish",
		"dev-load-varnish@dev as ^2.0": "dev-load-varnish",
		"1.0.0-beta.5+foo":             "1.0.0.0-beta5",
		"1.0.0+foo":                    "1.0.0.0",
		"1.0.0-alpha.3.1+foo":          "1.0.0.0-alpha3.1",
		"1.0.0-alpha-2.1-3+foo":        "1.0.0.0-alpha2.1-3",
		"1.0.0+foo as 2.0":             "1.0.0.0",
		"00.01.03.04":                  "00.01.03.04",
		"0700":                         "0700.0.0.0",
		"041.x-dev":                    "041.9999999.9999999.9999999-dev",
		" 1.0.0":                       "1.0.0.0",
		"1.0.0 ":                       "1.0.0.0",
		"1.0.0-stable":                 "1.0.0.0",
		"1.0.0-patch1":                 "1.0.0.0-patch1",
		"1.0.0-a1":                     "1.0.0.0-alpha1",
		"dev-1.0.0-dev<1.0.5-dev":      "dev-1.0.0-dev<1.0.5-dev",
		"dev-feature+issue-1":          "dev-feature+issue-1",
		"v2.0.0-RC2":                   "2.0.0.0-RC2",
		"3.12.1":                       "3.12.1.0",
		"1.0.0-beta2-dev":              "1.0.0.0-beta2-dev",
		"dev-load-varnish-when-used":   "dev-load-varnish-when-used",
		"1.2.3.4-stable":               "1.2.3.4",
		"v10.0":                        "10.0.0.0",
		"0.0.1-alpha":                  "0.0.1.0-alpha",
		"1.0.0.0-dev":                  "1.0.0.0-dev",
		"5.0.0-RC.1":                   "5.0.0.0-RC1",
		"2.0.0-pl1":                    "2.0.0.0-patch1",
		"1.0.0beta":                    "1.0.0.0-beta",
		"1.0.0-p":                      "1.0.0.0-patch",
		"1.0.0-dev":                    "1.0.0.0-dev",
		"1.1.x-dev":                    "1.1.9999999.9999999-dev",
		"1.X-dev":                      "1.9999999.9999999.9999999-dev",
		"1.*-dev":                      "1.9999999.9999999.9999999-dev",
		"1.0.0-alpha1+foo-bar.5":       "1.0.0.0-alpha1",
		"default":                      "dev-default",
		"dev-default":                  "dev-default",
		"trunk":                        "dev-trunk",
		"1.0.0-alpha1.2":               "1.0.0.0-alpha1.2",
		"1.0.0-alpha-1":                "1.0.0.0-alpha1",
		"1.0.0-beta.2.3":               "1.0.0.0-beta2.3",
		"1":                            "1.0.0.0",
		"1.2":                          "1.2.0.0",
		"1.2.3":                        "1.2.3.0",
		"v1":                           "1.0.0.0",
	} {
		got, err := normalize(in)
		if err != nil || got != want {
			t.Errorf("normalize(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "a", "1.0.0-meh", "1.0.0.0.0", "feature-foo", "1.0 .2", "dev-", "^1.0", "1.0.*", "latest", "1.0.0-1"} {
		if got, err := normalize(bad); err == nil {
			t.Errorf("normalize(%q) = %q, want an error", bad, got)
		}
	}
}

// show writes parsed comparisons as Composer's tests print them.
func show(sets []composerSet) string {
	var ors []string
	for _, set := range sets {
		var ands []string
		for _, c := range set {
			if c.op == "*" {
				ands = append(ands, "*")
				continue
			}
			ands = append(ands, c.op+" "+c.v)
		}
		ors = append(ors, strings.Join(ands, ", "))
	}
	return strings.Join(ors, " | ")
}

func TestComposerConstraints(t *testing.T) {
	for in, want := range map[string]string{
		"*":                    "*",
		"*.*":                  ">= 0.0.0.0-dev",
		"x":                    "*",
		"v*":                   ">= 0.0.0.0-dev",
		"*@dev":                "*",
		"@dev":                 "*",
		">1.0.0":               "> 1.0.0.0",
		"<1.2.3.4":             "< 1.2.3.4-dev",
		"<=1.2.3":              "<= 1.2.3.0",
		">=1.2.3":              ">= 1.2.3.0-dev",
		"=1.2.3":               "= 1.2.3.0",
		"==1.2.3":              "== 1.2.3.0",
		"1.2.3":                "= 1.2.3.0",
		"<>1.2.3":              "<> 1.2.3.0",
		"!=1.2.3":              "!= 1.2.3.0",
		"> 1.0.0":              "> 1.0.0.0",
		"<1.2.3-beta":          "< 1.2.3.0-beta",
		">=1.2.3@beta":         ">= 1.2.3.0-beta",
		"<1.2.3@dev":           "< 1.2.3.0-dev",
		"dev-master":           "= dev-master",
		"dev-master#abc123":    "= dev-master",
		"1.0.x-dev#abc123":     "= 1.0.9999999.9999999-dev",
		"2.*":                  ">= 2.0.0.0-dev, < 3.0.0.0-dev",
		"20.*":                 ">= 20.0.0.0-dev, < 21.0.0.0-dev",
		"2.0.*":                ">= 2.0.0.0-dev, < 2.1.0.0-dev",
		"2.x":                  ">= 2.0.0.0-dev, < 3.0.0.0-dev",
		"2.x.x":                ">= 2.0.0.0-dev, < 3.0.0.0-dev",
		"2.2.x":                ">= 2.2.0.0-dev, < 2.3.0.0-dev",
		"2.10.X":               ">= 2.10.0.0-dev, < 2.11.0.0-dev",
		"2.1.3.*":              ">= 2.1.3.0-dev, < 2.1.4.0-dev",
		"0.*":                  "< 1.0.0.0-dev",
		"0.*.*":                "< 1.0.0.0-dev",
		"0.x.x.x":              "< 1.0.0.0-dev",
		"~1":                   ">= 1.0.0.0-dev, < 2.0.0.0-dev",
		"~1.0":                 ">= 1.0.0.0-dev, < 2.0.0.0-dev",
		"~1.0.0":               ">= 1.0.0.0-dev, < 1.1.0.0-dev",
		"~1.2":                 ">= 1.2.0.0-dev, < 2.0.0.0-dev",
		"~1.2.3":               ">= 1.2.3.0-dev, < 1.3.0.0-dev",
		"~1.2.3.4":             ">= 1.2.3.4-dev, < 1.2.4.0-dev",
		"~1.2-beta":            ">= 1.2.0.0-beta, < 2.0.0.0-dev",
		"~1.2-b2":              ">= 1.2.0.0-beta2, < 2.0.0.0-dev",
		"~1.2-BETA2":           ">= 1.2.0.0-beta2, < 2.0.0.0-dev",
		"~1.2.2-dev":           ">= 1.2.2.0-dev, < 1.3.0.0-dev",
		"~1.2.2-stable":        ">= 1.2.2.0, < 1.3.0.0-dev",
		"^1":                   ">= 1.0.0.0-dev, < 2.0.0.0-dev",
		"^0":                   ">= 0.0.0.0-dev, < 1.0.0.0-dev",
		"^0.0":                 ">= 0.0.0.0-dev, < 0.1.0.0-dev",
		"^1.2":                 ">= 1.2.0.0-dev, < 2.0.0.0-dev",
		"^1.2.3-beta.2":        ">= 1.2.3.0-beta2, < 2.0.0.0-dev",
		"^1.2.3.4":             ">= 1.2.3.4-dev, < 2.0.0.0-dev",
		"^1.2.3":               ">= 1.2.3.0-dev, < 2.0.0.0-dev",
		"^0.2.3":               ">= 0.2.3.0-dev, < 0.3.0.0-dev",
		"^0.2":                 ">= 0.2.0.0-dev, < 0.3.0.0-dev",
		"^0.2.0":               ">= 0.2.0.0-dev, < 0.3.0.0-dev",
		"^0.0.3":               ">= 0.0.3.0-dev, < 0.0.4.0-dev",
		"^0.0.3-alpha":         ">= 0.0.3.0-alpha, < 0.0.4.0-dev",
		"^0.0.3-dev":           ">= 0.0.3.0-dev, < 0.0.4.0-dev",
		"1 - 2":                ">= 1.0.0.0-dev, < 3.0.0.0-dev",
		"1.2.3 - 2.3.4.5":      ">= 1.2.3.0-dev, <= 2.3.4.5",
		"1.2-beta - 2.3":       ">= 1.2.0.0-beta, < 2.4.0.0-dev",
		"1.2-beta - 2.3-dev":   ">= 1.2.0.0-beta, <= 2.3.0.0-dev",
		"1.2-RC - 2.3.1":       ">= 1.2.0.0-RC, <= 2.3.1.0",
		"1.2.3-alpha - 2.3-RC": ">= 1.2.3.0-alpha, <= 2.3.0.0-RC",
		"1 - 2.0":              ">= 1.0.0.0-dev, < 2.1.0.0-dev",
		"1 - 2.1":              ">= 1.0.0.0-dev, < 2.2.0.0-dev",
		"1.2 - 2.1.0":          ">= 1.2.0.0-dev, <= 2.1.0.0",
		"1.3 - 2.1.3":          ">= 1.3.0.0-dev, <= 2.1.3.0",
		"1.0 - 2.0":            ">= 1.0.0.0-dev, < 2.1.0.0-dev",
		"1.0.0 - 2.1.0":        ">= 1.0.0.0-dev, <= 2.1.0.0",
		">=1.0 <1.1 || >=1.2":  ">= 1.0.0.0-dev, < 1.1.0.0-dev | >= 1.2.0.0-dev",
		">=1.0,<2.0":           ">= 1.0.0.0-dev, < 2.0.0.0-dev",
		">=1.0, <2.0":          ">= 1.0.0.0-dev, < 2.0.0.0-dev",
		"^1.0 || ^2.0":         ">= 1.0.0.0-dev, < 2.0.0.0-dev | >= 2.0.0.0-dev, < 3.0.0.0-dev",
		"~1.0|~2.0":            ">= 1.0.0.0-dev, < 2.0.0.0-dev | >= 2.0.0.0-dev, < 3.0.0.0-dev",
		"^1.0@beta":            ">= 1.0.0.0-dev, < 2.0.0.0-dev",
		"1.0.*@dev":            ">= 1.0.0.0-dev, < 1.1.0.0-dev",
		"dev-master as 1.0.0":  "= dev-master",
		">= 1.0 < 2.0":         ">= 1.0.0.0-dev, < 2.0.0.0-dev",
	} {
		sets, err := parseComposer(in)
		if err != nil || show(sets) != want {
			t.Errorf("parse(%q) = %q, %v\nwant          %q", in, show(sets), err, want)
		}
	}
	for _, bad := range []string{"", "~>1.0", "^", "1.0 ||", ">=nope", "^latest", "1.0.0 - ", strings.Repeat("1", 2000)} {
		if sets, err := parseComposer(bad); err == nil {
			t.Errorf("parse(%q) = %q, want an error", bad, show(sets))
		}
	}
}

func TestComposerSatisfies(t *testing.T) {
	for _, tc := range []struct {
		v, c string
		want bool
	}{
		{"1.2.3", "^1.2", true},
		{"1.9.9", "^1.2", true},
		{"2.0.0", "^1.2", false},
		{"2.0.0-beta1", "^1.2", false},
		{"1.1.9", "^1.2", false},
		{"0.3.5", "^0.3", true},
		{"0.4.0", "^0.3", false},
		{"0.0.3", "^0.0.3", true},
		{"0.0.4", "^0.0.3", false},
		{"1.2.3", "~1.2", true},
		{"1.9.0", "~1.2", true},
		{"2.0.0", "~1.2", false},
		{"1.2.9", "~1.2.3", true},
		{"1.3.0", "~1.2.3", false},
		{"1.0.5", "1.0.*", true},
		{"1.1.0", "1.0.*", false},
		{"1.0.0", "1.0 - 2.0", true},
		{"2.0.9", "1.0 - 2.0", true},
		{"2.1.0", "1.0 - 2.0", false},
		{"2.1.0", "1.0.0 - 2.1.0", true},
		{"2.1.1", "1.0.0 - 2.1.0", false},
		{"1.0.0", ">=1.0", true},
		{"0.9.0", ">=1.0", false},
		{"1.5.0", ">=1.0 <1.1 || >=1.2", true},
		{"1.0.5", ">=1.0 <1.1 || >=1.2", true},
		{"1.1.5", ">=1.0 <1.1 || >=1.2", false},
		{"1.0.2", "1.0.2", true},
		{"v1.0.2", "1.0.2", true},
		{"1.0.3", "1.0.2", false},
		{"1.0.3", "!=1.0.2", true},
		{"1.0.2", "!=1.0.2", false},
		{"1.9.0", "<2.0", true},
		{"2.0.0-RC1", "<2.0", false},
		{"2.0.0", "<=2.0", true},
		{"1.5.0", "^1.0 || ^2.0", true},
		{"2.5.0", "~1.0|~2.0", true},
		{"3.0.0", "~1.0|~2.0", false},
		{"1.3.0-beta2", "^1.2", true},
		{"1.3.0-beta2", "^1.0@beta", true},
		{"1.0.0-patch1", ">1.0.0", true},
		{"1.0.0-RC2", ">1.0.0-RC1", true},
		{"1.0.0-RC1", ">1.0.0-RC1", false},
		{"1.0.0", ">1.0.0-RC1", true},
		{"dev-main", "dev-main", true},
		{"dev-main", "dev-other", false},
		{"dev-main", "^1.0", false},
		{"dev-main", "!=1.0", true},
		{"dev-main", "*", true},
		{"1.2.0", "*", true},
		{"1.x-dev", "^1.0", true},
		{"2.x-dev", "^1.0", false},
		{"3.12.1", "^3.0", true},
		{"not-a-version", "*", false},
	} {
		got, err := Composer.Satisfies(tc.v, tc.c)
		if err != nil || got != tc.want {
			t.Errorf("Satisfies(%q, %q) = %v, %v", tc.v, tc.c, got, err)
		}
	}
}

func TestComposerOrder(t *testing.T) {
	ordered := []string{"dev-alpha", "dev-main", "1.0.0-dev", "1.0.0-alpha1", "1.0.0-beta1", "1.0.0-beta2", "1.0.0-RC1", "1.0.0", "1.0.0-patch1", "1.0.1", "1.1.x-dev", "2.0.0"}
	for i := range ordered {
		for j := range ordered {
			if got, want := Composer.Compare(ordered[i], ordered[j]), sign(i-j); got != want {
				t.Errorf("Compare(%s, %s) = %d, want %d", ordered[i], ordered[j], got, want)
			}
		}
	}
	if Composer.Compare("v1.0.0", "1.0") != 0 || Composer.Compare("1.0.0+a", "1.0.0") != 0 {
		t.Error("equal forms differ")
	}
	for v, want := range map[string]bool{"1.0.0": false, "1.0.0-patch1": false, "1.0.0-RC1": true, "1.0.0-b": true, "dev-main": true, "1.x-dev": true, "1.0.0-alpha": true} {
		if Composer.Prerelease(v) != want {
			t.Errorf("Prerelease(%s) = %v", v, !want)
		}
	}
}

func TestNewestComposer(t *testing.T) {
	versions := []string{"1.0.0", "1.5.0", "1.6.0-beta1", "2.0.0", "v2.0.1", "dev-main", "2.1.x-dev"}
	for _, tc := range []struct {
		constraint string
		pre        bool
		want       string
	}{
		{"", false, "v2.0.1"},
		{"^1.0", false, "1.5.0"},
		{"^1.0", true, "1.6.0-beta1"},
		{"~1.0.0", false, "1.0.0"},
		{"^2.0", true, "2.1.x-dev"},
		{"^3.0", false, ""},
		{"~>1.0", false, ""},
	} {
		if got := core.Newest(Composer, versions, tc.constraint, tc.pre); got != tc.want {
			t.Errorf("Newest(%q, pre %v) = %q, want %q", tc.constraint, tc.pre, got, tc.want)
		}
	}
}

func FuzzComposerConstraint(f *testing.F) {
	f.Add("1.2.3", "1.0.0-beta2", "^1.2 || ~2.0@dev")
	f.Add("dev-main", "1.x-dev", ">=1.0, <2.0")
	f.Add("20100102-203040-p1", "v1.0.0+foo", "1.0 - 2.0")
	f.Add("1.0.0.RC.15-dev", "0700", "1.0.*")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		checkOrder(t, Composer.Compare, a, b, c)
		_, _ = Composer.Satisfies(a, c)
		Composer.Prerelease(b)
		if n, err := normalize(a); err == nil {
			// A normal form is a fixed point.
			if again, err := normalize(n); err != nil || again != n && !strings.HasPrefix(n, "dev-") {
				t.Fatalf("normalize(%q) = %q; normalize(%q) = %q, %v", a, n, n, again, err)
			}
		}
		if sets, err := parseComposer(c); err == nil && len(sets) == 0 {
			t.Fatalf("constraint %q parsed to nothing", c)
		}
	})
}
