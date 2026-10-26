// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package version

import (
	"testing"

	"github.com/RhythmShahriar/sightread/core"
)

// The cases below are copied by hand from node-semver's test fixtures
// (comparisons.js, range-include.js and range-exclude.js), leaving out
// the loose and includePrerelease ones Sightread does not use.

func TestSemverCompare(t *testing.T) {
	// Each pair is newer, older.
	for _, tc := range [][2]string{
		{"0.0.0", "0.0.0-foo"},
		{"0.0.1", "0.0.0"},
		{"1.0.0", "0.9.9"},
		{"0.10.0", "0.9.0"},
		{"0.99.0", "0.10.0"},
		{"2.0.0", "1.2.3"},
		{"v0.0.0", "0.0.0-foo"},
		{"v0.0.1", "0.0.0"},
		{"1.2.3", "1.2.3-asdf"},
		{"1.2.3", "1.2.3-4"},
		{"1.2.3", "1.2.3-4-foo"},
		{"1.2.3-5-foo", "1.2.3-5"},
		{"1.2.3-5", "1.2.3-4"},
		{"1.2.3-5-foo", "1.2.3-5-Foo"},
		{"3.0.0", "2.7.2+asdf"},
		{"1.2.3-a.10", "1.2.3-a.5"},
		{"1.2.3-a.b", "1.2.3-a.5"},
		{"1.2.3-a.b", "1.2.3-a"},
		{"1.2.3-a.b.c.10.d.5", "1.2.3-a.b.c.5.d.100"},
		{"1.2.3-r2", "1.2.3-r100"},
		{"1.2.3-r100", "1.2.3-R2"},
		// The semver 2.0.0 precedence example.
		{"1.0.0-alpha.1", "1.0.0-alpha"},
		{"1.0.0-alpha.beta", "1.0.0-alpha.1"},
		{"1.0.0-beta", "1.0.0-alpha.beta"},
		{"1.0.0-beta.2", "1.0.0-beta"},
		{"1.0.0-beta.11", "1.0.0-beta.2"},
		{"1.0.0-rc.1", "1.0.0-beta.11"},
		{"1.0.0", "1.0.0-rc.1"},
		// Numbers past 2^64 still order.
		{"1.0.18446744073709551617", "1.0.18446744073709551616"},
	} {
		if NPM.Compare(tc[0], tc[1]) != 1 || NPM.Compare(tc[1], tc[0]) != -1 {
			t.Errorf("Compare(%s, %s) = %d", tc[0], tc[1], NPM.Compare(tc[0], tc[1]))
		}
	}
	for _, tc := range [][2]string{{"1.2.3", "v1.2.3"}, {"1.2.3", "=1.2.3"}, {"1.2.3+build.1", "1.2.3+build.2"}, {"1.2.3-beta+a", "1.2.3-beta"}} {
		if NPM.Compare(tc[0], tc[1]) != 0 {
			t.Errorf("Compare(%s, %s) != 0", tc[0], tc[1])
		}
	}
}

func TestSemverValid(t *testing.T) {
	for v, want := range map[string]bool{
		"1.2.3": true, "v1.2.3": true, "1.2.3-beta.1+build.5": true, "0.0.0": true,
		"1.2": false, "01.2.3": false, "1.2.3-01": false, "1.2.3beta": false, "": false,
		"1.2.3-": false, "1.2.3+": false, "latest": false, "1.2.3.4": false,
	} {
		if NPM.Valid(v) != want {
			t.Errorf("Valid(%q) = %v", v, !want)
		}
	}
	if !NPM.Prerelease("1.0.0-rc.1") || NPM.Prerelease("1.0.0+build") || NPM.Prerelease("nope") {
		t.Error("Prerelease")
	}
}

func TestSemverRangeInclude(t *testing.T) {
	for _, tc := range [][2]string{
		{"1.0.0 - 2.0.0", "1.2.3"},
		{"^1.2.3+build", "1.2.3"},
		{"^1.2.3+build", "1.3.0"},
		{"1.2.3-pre+asdf - 2.4.3-pre+asdf", "1.2.3"},
		{"1.2.3-pre+asdf - 2.4.3-pre+asdf", "1.2.3-pre.2"},
		{"1.2.3-pre+asdf - 2.4.3-pre+asdf", "2.4.3-alpha"},
		{"1.2.3+asdf - 2.4.3+asdf", "1.2.3"},
		{"1.0.0", "1.0.0"},
		{">=*", "0.2.4"},
		{"", "1.0.0"},
		{"*", "1.2.3"},
		{">=1.0.0", "1.0.0"},
		{">=1.0.0", "1.0.1"},
		{">=1.0.0", "1.1.0"},
		{">1.0.0", "1.0.1"},
		{">1.0.0", "1.1.0"},
		{"<=2.0.0", "2.0.0"},
		{"<=2.0.0", "1.9999.9999"},
		{"<=2.0.0", "0.2.9"},
		{"<2.0.0", "1.9999.9999"},
		{"<2.0.0", "0.2.9"},
		{">= 1.0.0", "1.0.0"},
		{">=  1.0.0", "1.0.1"},
		{">=   1.0.0", "1.1.0"},
		{"> 1.0.0", "1.0.1"},
		{">  1.0.0", "1.1.0"},
		{"<=   2.0.0", "2.0.0"},
		{"<= 2.0.0", "1.9999.9999"},
		{"<=  2.0.0", "0.2.9"},
		{"<    2.0.0", "1.9999.9999"},
		{"<\t2.0.0", "0.2.9"},
		{">=0.1.97", "v0.1.97"},
		{">=0.1.97", "0.1.97"},
		{"0.1.20 || 1.2.4", "1.2.4"},
		{">=0.2.3 || <0.0.1", "0.0.0"},
		{">=0.2.3 || <0.0.1", "0.2.3"},
		{">=0.2.3 || <0.0.1", "0.2.4"},
		{"||", "1.3.4"},
		{"2.x.x", "2.1.3"},
		{"1.2.x", "1.2.3"},
		{"1.2.x || 2.x", "2.1.3"},
		{"1.2.x || 2.x", "1.2.3"},
		{"x", "1.2.3"},
		{"2.*.*", "2.1.3"},
		{"1.2.*", "1.2.3"},
		{"1.2.* || 2.*", "2.1.3"},
		{"1.2.* || 2.*", "1.2.3"},
		{"2", "2.1.2"},
		{"2.3", "2.3.1"},
		{"~0.0.1", "0.0.1"},
		{"~0.0.1", "0.0.2"},
		{"~x", "0.0.9"},
		{"~2", "2.0.9"},
		{"~2.4", "2.4.0"},
		{"~2.4", "2.4.5"},
		{"~>3.2.1", "3.2.2"},
		{"~1", "1.2.3"},
		{"~>1", "1.2.3"},
		{"~> 1", "1.2.3"},
		{"~1.0", "1.0.2"},
		{"~ 1.0", "1.0.2"},
		{"~ 1.0.3", "1.0.12"},
		{">=1", "1.0.0"},
		{">= 1", "1.0.0"},
		{"<1.2", "1.1.1"},
		{"< 1.2", "1.1.1"},
		{"~v0.5.4-pre", "0.5.5"},
		{"~v0.5.4-pre", "0.5.4"},
		{"=0.7.x", "0.7.2"},
		{"<=0.7.x", "0.7.2"},
		{">=0.7.x", "0.7.2"},
		{"<=0.7.x", "0.6.2"},
		{"~1.2.1 >=1.2.3", "1.2.3"},
		{"~1.2.1 =1.2.3", "1.2.3"},
		{"~1.2.1 1.2.3", "1.2.3"},
		{"~1.2.1 >=1.2.3 1.2.3", "1.2.3"},
		{"~1.2.1 1.2.3 >=1.2.3", "1.2.3"},
		{">=1.2.1 1.2.3", "1.2.3"},
		{"1.2.3 >=1.2.1", "1.2.3"},
		{">=1.2.3 >=1.2.1", "1.2.3"},
		{">=1.2.1 >=1.2.3", "1.2.3"},
		{">=1.2", "1.2.8"},
		{"^1.2.3", "1.8.1"},
		{"^0.1.2", "0.1.2"},
		{"^0.1", "0.1.2"},
		{"^0.0.1", "0.0.1"},
		{"^1.2", "1.4.2"},
		{"^1.2 ^1", "1.4.2"},
		{"^1.2.3-alpha", "1.2.3-pre"},
		{"^1.2.0-alpha", "1.2.0-pre"},
		{"^0.0.1-alpha", "0.0.1-beta"},
		{"^0.0.1-alpha", "0.0.1"},
		{"^0.1.1-alpha", "0.1.1-beta"},
		{"^x", "1.2.3"},
		{"x - 1.0.0", "0.9.7"},
		{"x - 1.x", "0.9.7"},
		{"1.0.0 - x", "1.9.7"},
		{"1.x - x", "1.9.7"},
		{"<=7.x", "7.9.9"},
	} {
		ok, err := NPM.Satisfies(tc[1], tc[0])
		if err != nil || !ok {
			t.Errorf("%q should include %s (err %v)", tc[0], tc[1], err)
		}
	}
}

func TestSemverRangeExclude(t *testing.T) {
	for _, tc := range [][2]string{
		{"1.0.0 - 2.0.0", "2.2.3"},
		{"1.2.3+asdf - 2.4.3+asdf", "1.2.3-pre.2"},
		{"1.2.3+asdf - 2.4.3+asdf", "2.4.3-alpha"},
		{"^1.2.3+build", "2.0.0"},
		{"^1.2.3+build", "1.2.0"},
		{"^1.2.3", "1.2.3-pre"},
		{"^1.2", "1.2.0-pre"},
		{">1.2", "1.3.0-beta"},
		{"<=1.2.3", "1.2.3-beta"},
		{"^1.2.3", "1.2.3-beta"},
		{"=0.7.x", "0.7.0-asdf"},
		{">=0.7.x", "0.7.0-asdf"},
		{"<=0.7.x", "0.7.0-asdf"},
		{"1", "1.0.0beta"},
		{"<1", "1.0.0beta"},
		{"1.0.0", "1.0.1"},
		{">=1.0.0", "0.0.0"},
		{">=1.0.0", "0.0.1"},
		{">=1.0.0", "0.1.0"},
		{">1.0.0", "0.0.1"},
		{">1.0.0", "0.1.0"},
		{"<=2.0.0", "3.0.0"},
		{"<=2.0.0", "2.9999.9999"},
		{"<=2.0.0", "2.2.9"},
		{"<2.0.0", "2.9999.9999"},
		{"<2.0.0", "2.2.9"},
		{">=0.1.97", "v0.1.93"},
		{">=0.1.97", "0.1.93"},
		{"0.1.20 || 1.2.4", "1.2.3"},
		{">=0.2.3 || <0.0.1", "0.0.3"},
		{">=0.2.3 || <0.0.1", "0.2.2"},
		{"2.x.x", "3.1.3"},
		{"1.2.x", "1.3.3"},
		{"1.2.x || 2.x", "3.1.3"},
		{"1.2.x || 2.x", "1.1.3"},
		{"2.*.*", "1.1.3"},
		{"2.*.*", "3.1.3"},
		{"1.2.*", "1.3.3"},
		{"1.2.* || 2.*", "3.1.3"},
		{"1.2.* || 2.*", "1.1.3"},
		{"2", "1.1.2"},
		{"2.3", "2.4.1"},
		{"~0.0.1", "0.1.0-alpha"},
		{"~0.0.1", "0.1.0"},
		{"~2.4", "2.5.0"},
		{"~2.4", "2.3.9"},
		{"~>3.2.1", "3.3.2"},
		{"~>3.2.1", "3.2.0"},
		{"~1", "0.2.3"},
		{"~>1", "2.2.3"},
		{"~1.0", "1.1.0"},
		{"<1", "1.0.0"},
		{">=1.2", "1.1.1"},
		{"~v0.5.4-beta", "0.5.4-alpha"},
		{"=0.7.x", "0.8.2"},
		{">=0.7.x", "0.6.2"},
		{"<0.7.x", "0.7.2"},
		{"<1.2.3", "1.2.3-beta"},
		{"=1.2.3", "1.2.3-beta"},
		{">1.2", "1.2.8"},
		{"^0.0.1", "0.0.2-alpha"},
		{"^0.0.1", "0.0.2"},
		{"^1.2.3", "2.0.0-alpha"},
		{"^1.2.3", "1.2.2"},
		{"^1.2", "1.1.9"},
		{"^1.0.0", "2.0.0-rc1"},
		{"1 - 2", "2.0.0-pre"},
		{"1 - 2", "1.0.0-pre"},
		{"1.0 - 2", "1.0.0-pre"},
		{"1.1.x", "1.0.0-a"},
		{"1.1.x", "1.1.0-a"},
		{"1.1.x", "1.2.0-a"},
		{"1.x", "1.0.0-a"},
		{"1.x", "1.1.0-a"},
		{"1.x", "1.2.0-a"},
		{">=1.0.0 <1.1.0", "1.1.0"},
		{">=1.0.0 <1.1.0", "1.1.0-pre"},
		{">=1.0.0 <1.1.0-pre", "1.1.0-pre"},
		{"<*", "1.0.0"},
		{">*", "1.0.0"},
	} {
		ok, err := NPM.Satisfies(tc[1], tc[0])
		if err != nil || ok {
			t.Errorf("%q should exclude %s (err %v)", tc[0], tc[1], err)
		}
	}
}

func TestSemverRangeErrors(t *testing.T) {
	for _, r := range []string{"blerg", "== 1.0.0", "1.2.3.4", ">=01.0.0", "^latest", "1.0.0 - ", "!=1.0.0", string(make([]byte, 2000))} {
		if _, err := NPM.Satisfies("1.0.0", r); err == nil {
			t.Errorf("range %q parsed", r)
		}
	}
}

func TestNewestNPM(t *testing.T) {
	versions := []string{"1.0.0", "1.2.0", "1.3.0-beta.1", "2.0.0", "2.1.0-rc.1", "not-a-version"}
	for _, tc := range []struct {
		constraint string
		pre        bool
		want       string
	}{
		{"", false, "2.0.0"},
		{"", true, "2.1.0-rc.1"},
		{"^1.0.0", false, "1.2.0"},
		// node-semver's rule holds with --pre: ^1.0.0 lets in no 1.3.0
		// prerelease, only a range naming one does.
		{"^1.0.0", true, "1.2.0"},
		{"^1.3.0-beta.0", true, "1.3.0-beta.1"},
		{"~2.1.0-rc.0", true, "2.1.0-rc.1"},
		{">=3", false, ""},
		{"not a range", false, ""},
	} {
		if got := core.Newest(NPM, versions, tc.constraint, tc.pre); got != tc.want {
			t.Errorf("Newest(%q, pre %v) = %q, want %q", tc.constraint, tc.pre, got, tc.want)
		}
	}
}

func TestRegistered(t *testing.T) {
	for eco, want := range map[core.Ecosystem]core.VersionScheme{
		core.WPPlugin: WordPress, core.WPTheme: WordPress, core.Composer: Composer, core.NPM: NPM,
	} {
		if core.Versions(eco) != want {
			t.Errorf("%s: wrong scheme", eco)
		}
	}
}

// checkOrder fails when cmp is not antisymmetric or not transitive on
// a, b and c.
func checkOrder(t *testing.T, cmp func(a, b string) int, a, b, c string) {
	t.Helper()
	for _, p := range [][2]string{{a, b}, {b, c}, {a, c}} {
		if cmp(p[0], p[1]) != -cmp(p[1], p[0]) {
			t.Fatalf("Compare(%q, %q) = %d but the reverse is %d", p[0], p[1], cmp(p[0], p[1]), cmp(p[1], p[0]))
		}
	}
	if cmp(a, a) != 0 {
		t.Fatalf("Compare(%q, itself) != 0", a)
	}
	ab, bc, ac := cmp(a, b), cmp(b, c), cmp(a, c)
	if ab <= 0 && bc <= 0 && ac > 0 || ab >= 0 && bc >= 0 && ac < 0 {
		t.Fatalf("not transitive: %q %q %q give %d %d %d", a, b, c, ab, bc, ac)
	}
}

func FuzzSemverCompare(f *testing.F) {
	f.Add("1.2.3", "1.2.3-beta.1", "^1.2.0 || 2.x")
	f.Add("1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0 - 2.0.0")
	f.Add("0.0.1", "v0.0.1+build", "~0.0.1 >=0.0.1-0")
	f.Add("10.0.0-0", "10.0.0-a", "<=*")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		checkOrder(t, NPM.Compare, a, b, c)
		_, _ = NPM.Satisfies(a, c)
		_, _ = NPM.Satisfies(b, c)
		NPM.Prerelease(a)
		if NPM.Valid(a) && NPM.Compare(a, b) == 0 && NPM.Valid(b) {
			ok1, err1 := NPM.Satisfies(a, c)
			ok2, err2 := NPM.Satisfies(b, c)
			// Equal versions differ at most in build metadata, which
			// ranges ignore.
			if ok1 != ok2 || (err1 == nil) != (err2 == nil) {
				t.Fatalf("%q and %q compare equal but %q matches only one", a, b, c)
			}
		}
	})
}
