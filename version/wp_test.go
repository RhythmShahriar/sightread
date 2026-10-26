// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package version

import (
	"testing"

	"github.com/RhythmShahriar/sightread/core"
)

// The expectations follow PHP's version_compare, checked by hand
// against php.net's documentation of the function.
func TestWordPressCompare(t *testing.T) {
	// Each pair is older, newer.
	for _, tc := range [][2]string{
		{"5.2", "5.2.0"},
		{"1.0rc1", "1.0"},
		{"1.0", "1.0pl1"},
		{"1.0", "1.0-patch1"},
		{"1.0-dev", "1.0-alpha"},
		{"1.0-alpha", "1.0-beta"},
		{"1.0-beta", "1.0-RC"},
		{"1.0-RC", "1.0"},
		{"1.0.0-beta1", "1.0.0-beta2"},
		{"1.0.0-beta2", "1.0.0-RC1"},
		{"1.0.0-RC1", "1.0.0"},
		{"1.9", "1.10"},
		{"1.2.3", "1.2.3.4"},
		{"5.3.5", "5.3.10"},
		{"1.0-foo", "1.0-dev"},
		{"2.6.7", "2.6.8"},
		{"6.4.3", "6.5"},
		{"1.0.0", "1.0.0.1"},
		{"1.0-beta1", "1.0"},
		{"4.9.99", "5.0-beta1"},
		{"1.0-RC2", "1.0-RC10"},
		{"1.0", "1.0.0"},
		{"1.0a", "1.0b"},
		{"1.0-b", "1.0-rc"},
		{"0.9", "1.0-dev"},
	} {
		if WordPress.Compare(tc[0], tc[1]) != -1 || WordPress.Compare(tc[1], tc[0]) != 1 {
			t.Errorf("Compare(%s, %s) = %d", tc[0], tc[1], WordPress.Compare(tc[0], tc[1]))
		}
	}
	for _, tc := range [][2]string{{"1.0a", "1.0alpha"}, {"1.01", "1.1"}, {"1.0-beta", "1.0.beta"}, {"1.0_RC1", "1.0-rc1"}, {"5.3.5", "5.3.5"}, {"1.0+1", "1.0.1"}} {
		if WordPress.Compare(tc[0], tc[1]) != 0 {
			t.Errorf("Compare(%s, %s) = %d, want 0", tc[0], tc[1], WordPress.Compare(tc[0], tc[1]))
		}
	}
}

func TestWordPressValid(t *testing.T) {
	for v, want := range map[string]bool{
		"1.2": true, "1.2.3.4": true, "2.0-beta1": true, "5.3-RC2": true, "1": true, "1.0_rc1": true,
		"": false, "trunk": false, "v1.0": false, "1.0 beta": false, "1.0/2": false, "-1": false,
	} {
		if WordPress.Valid(v) != want {
			t.Errorf("Valid(%q) = %v", v, !want)
		}
	}
	for v, want := range map[string]bool{"1.0": false, "1.0-beta1": true, "1.0-RC2": true, "1.0-dev": true, "1.0-pl1": false, "1.0-patch1": false, "1.0-foo": true} {
		if WordPress.Prerelease(v) != want {
			t.Errorf("Prerelease(%q) = %v", v, !want)
		}
	}
}

func TestWordPressSatisfies(t *testing.T) {
	for _, tc := range []struct {
		v, c string
		want bool
	}{
		{"5.3.5", "*", true},
		{"5.3.5", "", true},
		{"5.3.5", "5.3.5", true},
		{"5.3.5", "5.3.6", false},
		{"5.3.5", ">=5.0 <6.0", true},
		{"6.0", ">=5.0 <6.0", false},
		{"6.0-beta1", ">=5.0 <6.0", true},
		{"6.2", ">=5.0 <6.0 || 6.2", true},
		{"5.3.5", ">= 5.0, < 6.0", true},
		{"5.3.5", "!=5.3.5", false},
		{"trunk", "*", false},
	} {
		got, err := WordPress.Satisfies(tc.v, tc.c)
		if err != nil || got != tc.want {
			t.Errorf("Satisfies(%q, %q) = %v, %v", tc.v, tc.c, got, err)
		}
	}
	for _, bad := range []string{"^1.0", "~1.2", ">=trunk", "1.0 - 2.0"} {
		if _, err := WordPress.Satisfies("1.0", bad); err == nil {
			t.Errorf("constraint %q parsed", bad)
		}
	}
}

func TestNewestWordPress(t *testing.T) {
	versions := []string{"1.0", "1.2.3", "2.0-beta1", "1.10", "trunk"}
	if got := core.Newest(WordPress, versions, "", false); got != "1.10" {
		t.Errorf("latest %q", got)
	}
	if got := core.Newest(WordPress, versions, "", true); got != "2.0-beta1" {
		t.Errorf("latest with prereleases %q", got)
	}
	if got := core.Newest(WordPress, versions, "<1.5", false); got != "1.2.3" {
		t.Errorf("below 1.5 %q", got)
	}
}

func FuzzWPVersion(f *testing.F) {
	f.Add("1.2.3", "1.2.3-beta1", ">=1.0 <2.0")
	f.Add("1.0", "1.0.0", "1.0pl1")
	f.Add("1.0-RC2", "1.0_rc10", "*")
	f.Add("1.0a", "1.0-foo", "1.0.0.0.1")
	f.Fuzz(func(t *testing.T, a, b, c string) {
		// Order is checked on the versions WordPress accepts; PHP's own
		// function is not transitive on every string (a leading "#").
		if WordPress.Valid(a) && WordPress.Valid(b) && WordPress.Valid(c) {
			checkOrder(t, WordPress.Compare, a, b, c)
		}
		_, _ = WordPress.Satisfies(a, c)
		WordPress.Prerelease(b)
	})
}
