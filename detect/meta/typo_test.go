// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package meta

import (
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
)

var npmPopular = []string{
	"crypto-js", "react", "react-dom", "preact", "lodash", "lodash.merge",
	"colors", "color", "@types/node", "@types/react", "axios", "express",
	"chalk", "debug", "qs", "ms", "node-fetch", "commander",
}

var composerPopular = []string{
	"laravel/framework", "symfony/console", "symfony/polyfill-php80",
	"monolog/monolog", "guzzlehttp/guzzle", "phpunit/phpunit",
}

func TestDistance(t *testing.T) {
	for _, c := range []struct {
		a, b string
		max  int
		want int
	}{
		{"react", "react", 2, 0},
		{"react", "raect", 2, 1}, // a swap is one edit
		{"lodash", "lodahs", 2, 1},
		{"axios", "axois", 2, 1},
		{"axios", "axio", 2, 1},
		{"express", "expres", 2, 1},
		{"kitten", "sitting", 5, 3},
		{"kitten", "sitting", 1, 2}, // early exit: max+1
		{"a", "abcdef", 2, 3},
		{"", "abc", 5, 3},
		{"ñandú", "nandu", 3, 2}, // runes, not bytes
	} {
		if got := Distance(c.a, c.b, c.max); got != c.want {
			t.Errorf("Distance(%q, %q, %d) = %d, want %d", c.a, c.b, c.max, got, c.want)
		}
	}
}

func TestSkeleton(t *testing.T) {
	for in, want := range map[string]string{
		"React":    "react",
		"l0dash":   "lodash",
		"1odash":   "lodash",
		"rnoment":  "moment",
		"ехрress":  "express", // Cyrillic е, х and р
		"аxios":    "axlos",   // Cyrillic а
		"crурto":   "crypto",  // Cyrillic у and р
		"lint":     "llnt",
		"νue-ροοt": "vue-poot",
	} {
		if got := Skeleton(in); got != want {
			t.Errorf("Skeleton(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTyposquatNear(t *testing.T) {
	npm := NewTypoIndex(core.NPM, npmPopular)
	composer := NewTypoIndex(core.Composer, composerPopular)
	for _, c := range []struct {
		ix   *TypoIndex
		name string
		want []string
	}{
		// positives
		{npm, "plain-crypto-js", []string{"crypto-js"}},
		{npm, "crypto-js-official", []string{"crypto-js"}},
		{npm, "crypto_js", []string{"crypto-js"}},
		{npm, "cryptojs", []string{"crypto-js"}},
		{npm, "@type/node", []string{"@types/node"}},
		{npm, "types-node", []string{"@types/node"}},
		{npm, "@types-node/x", nil},
		{npm, "axois", []string{"axios"}},
		{npm, "аxios", []string{"axios"}}, // Cyrillic а
		{npm, "lodash-merge", []string{"lodash.merge"}},
		{npm, "exprss", []string{"express"}},
		{npm, "commandr", []string{"commander"}},
		{npm, "rnorgan", nil},
		{npm, "Axios", nil}, // the popular name itself, in another case
		{composer, "laravell/framework", []string{"laravel/framework"}},
		{composer, "laravel/framwork", nil}, // the vendor's own name: only laravel publishes there
		{composer, "laravell/framwork", []string{"laravel/framework"}},
		{composer, "monolog-official/monolog", []string{"monolog/monolog"}},
		{composer, "guzzlehtp/guzzle", []string{"guzzlehttp/guzzle"}},
		// negatives
		{npm, "preact", nil},
		{npm, "react-dom", nil},
		{npm, "lodash.merge", nil},
		{npm, "colors", nil},
		{npm, "color", nil},
		{npm, "@acme/react", nil},
		{npm, "@types/lodash", nil}, // under @types, published by DefinitelyTyped
		{npm, "ns", nil},            // too short for edits: qs and ms are popular
		{npm, "left-pad", nil},
		{npm, "node-fetch-native", nil},
		{composer, "symfony/polyfill-php84", nil},
		{composer, "acme/framework", nil},
	} {
		got := c.ix.Near(c.name)
		if !slices.Equal(got, c.want) {
			t.Errorf("Near(%q) = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestTypoIndexPopular(t *testing.T) {
	ix := NewTypoIndex(core.NPM, []string{" React ", "react", ""})
	if !ix.Popular("REACT") || ix.Popular("preact") || ix.Len() != 1 {
		t.Errorf("Popular/Len wrong: %v %v %d", ix.Popular("REACT"), ix.Popular("preact"), ix.Len())
	}
	var nilIx *TypoIndex
	if nilIx.Popular("react") || nilIx.Near("raect") != nil || nilIx.Len() != 0 {
		t.Error("a nil index must know no names")
	}
}

// FuzzTyposquat checks the engine's laws: the distance is symmetric and
// zero only for equal names; no name is a typosquat of itself.
func FuzzTyposquat(f *testing.F) {
	for _, s := range [][2]string{
		{"plain-crypto-js", "crypto-js"}, {"@type/node", "@types/node"}, {"laravell/framework", "laravel/framework"},
		{"аxios", "axios"}, {"", "x"}, {"ab", "ba"}, {"rnoment", "moment"},
	} {
		f.Add(s[0], s[1])
	}
	f.Fuzz(func(t *testing.T, a, b string) {
		if len(a) > 64 || len(b) > 64 {
			return
		}
		for _, m := range []int{0, 1, 2, 5} {
			ab, ba := Distance(a, b, m), Distance(b, a, m)
			if ab != ba {
				t.Fatalf("Distance(%q, %q, %d) = %d but reversed %d", a, b, m, ab, ba)
			}
			if ab > m+1 || ab < 0 {
				t.Fatalf("Distance(%q, %q, %d) = %d, out of range", a, b, m, ab)
			}
			if (ab == 0) != (a == b) && string([]rune(a)) == a && string([]rune(b)) == b {
				t.Fatalf("Distance(%q, %q, %d) = %d", a, b, m, ab)
			}
		}
		for _, eco := range []core.Ecosystem{core.NPM, core.Composer} {
			ix := NewTypoIndex(eco, []string{b})
			for _, p := range ix.names {
				if got := ix.Near(p); got != nil {
					t.Fatalf("popular %q is near %q", p, got)
				}
			}
			if slices.Contains(ix.Near(a), strings.ToLower(a)) {
				t.Fatalf("%q is near itself", a)
			}
		}
	})
}
