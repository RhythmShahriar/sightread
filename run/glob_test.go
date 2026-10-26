// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run_test

import (
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/run"
)

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"*", "", true},
		{"composer:*", "composer:monolog/monolog", true},
		{"npm:@acme/*", "npm:@acme/billing", true},
		{"npm:@acme/*", "npm:@acmex/billing", false},
		{"remote-*", "remote-fetch-exec", true},
		{"*-exec", "decode-exec", true},
		{"*-exec", "decode-execs", false},
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
		{"exact", "exact", true},
		{"exact", "exactly", false},
	}
	for _, c := range cases {
		if got := run.Match(c.pattern, c.s); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.s, got, c.want)
		}
	}
}

func TestSelected(t *testing.T) {
	cases := []struct {
		only, skip []string
		eco        core.Ecosystem
		name       string
		want       bool
	}{
		{nil, nil, core.NPM, "left-pad", true},
		{[]string{"npm"}, nil, core.NPM, "left-pad", true},
		{[]string{"npm"}, nil, core.Composer, "a/b", false},
		{[]string{"plugin:*"}, nil, core.WPPlugin, "akismet", true},
		{[]string{"wp-plugin:*,npm:@acme/*"}, nil, core.WPTheme, "astra", false},
		{[]string{"wp-plugin:*", "npm:@acme/*"}, nil, core.NPM, "@acme/ui", true},
		{nil, []string{"wp-theme"}, core.WPTheme, "astra", false},
		{nil, []string{"npm:left-*"}, core.NPM, "left-pad", false},
		{nil, []string{"npm:left-*"}, core.NPM, "right-pad", true},
	}
	for _, c := range cases {
		if got := run.Selected(c.eco, c.name, c.only, c.skip); got != c.want {
			t.Errorf("Selected(%s:%s, only %q, skip %q) = %v", c.eco, c.name, c.only, c.skip, got)
		}
	}
}

func TestSplitCommand(t *testing.T) {
	cases := []struct {
		in    string
		want  []string
		err   string
		posix bool // a backslash escape, which Windows keeps literal
	}{
		{in: "wp --path=/srv/www", want: []string{"wp", "--path=/srv/www"}},
		{in: `ssh deploy@host -- wp --path='/srv/my site'`, want: []string{"ssh", "deploy@host", "--", "wp", "--path=/srv/my site"}},
		{in: `wp "a \"b\" c" d\ e`, want: []string{"wp", `a "b" c`, "d e"}, posix: true},
		{in: "wp; rm -rf ~ $HOME", want: []string{"wp;", "rm", "-rf", "~", "$HOME"}},
		{in: `''`, want: []string{""}},
		{in: "wp 'open", err: "a quote is not closed"},
		{in: `wp \`, err: "it ends with a backslash", posix: true},
		{in: "  ", err: "it is empty"},
	}
	for _, c := range cases {
		if c.posix && runtime.GOOS == "windows" {
			continue
		}
		got, err := run.SplitCommand(c.in)
		switch {
		case c.err != "":
			if err == nil || err.Error() != c.err {
				t.Errorf("%q: error %v, want %q", c.in, err, c.err)
			}
		case err != nil || !reflect.DeepEqual(got, c.want):
			t.Errorf("%q: %q, %v; want %q", c.in, got, err, c.want)
		}
	}
}

// FuzzSplitCommand: any input either fails or splits into words that
// join back without a shell ever being involved; it never panics.
func FuzzSplitCommand(f *testing.F) {
	for _, s := range []string{"wp --path=/srv/www", `ssh h -- wp --path='/a b'`, `"x\"y"`, `a\ b`, "'", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		args, err := run.SplitCommand(s)
		if err != nil {
			return
		}
		if len(args) == 0 {
			t.Fatalf("%q: no words and no error", s)
		}
		if strings.Trim(s, " \t\n\r") == "" {
			t.Fatalf("%q: blank input split into %q", s, args)
		}
	})
}

func FuzzMatch(f *testing.F) {
	f.Add("composer:*", "composer:a/b")
	f.Add("a*b?c", "axbyc")
	f.Fuzz(func(t *testing.T, pattern, s string) {
		if !strings.ContainsAny(pattern, "*?") && run.Match(pattern, s) != (pattern == s) {
			t.Fatalf("literal %q vs %q", pattern, s)
		}
		if !run.Match("*", s) {
			t.Fatalf("* did not match %q", s)
		}
	})
}
