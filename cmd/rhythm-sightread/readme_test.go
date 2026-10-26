// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

// readmePrefixes are the ways README.md starts a Sightread command: the
// binary itself and the router with the tool's name or its alias.
var readmePrefixes = []string{"rhythm-sightread", "rhythm sightread", "rhythm sr"}

// readme returns README.md's text.
func readme(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// readmeCommands returns the arguments of every Sightread command line
// README.md shows, in code blocks and inline code, without trailing
// comments and without the program words. Templates ("<signal-id>",
// "a|b") are left out.
func readmeCommands(text string) [][]string {
	var out [][]string
	var seen []string
	add := func(line string) {
		line = strings.TrimSpace(line)
		if i := strings.Index(line, " #"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if strings.ContainsAny(line, "<|") || slices.Contains(seen, line) {
			return
		}
		for _, p := range readmePrefixes {
			if line == p || strings.HasPrefix(line, p+" ") {
				seen = append(seen, line)
				out = append(out, shellWords(line)[len(strings.Fields(p)):])
				return
			}
		}
	}
	fenced := false
	for line := range strings.SplitSeq(text, "\n") {
		if strings.HasPrefix(line, "```") {
			fenced = !fenced
			continue
		}
		if fenced {
			add(line)
			continue
		}
		for _, m := range inlineCode.FindAllStringSubmatch(line, -1) {
			add(m[1])
		}
	}
	return out
}

var inlineCode = regexp.MustCompile("`([^`]+)`")

// shellWords splits a command line the way a shell would for these
// examples: on spaces, with '...' and "..." kept as one word.
func shellWords(line string) []string {
	var words []string
	var cur strings.Builder
	quote, in := rune(0), false
	for _, r := range line {
		switch {
		case quote != 0 && r == quote:
			quote = 0
		case quote != 0:
			cur.WriteRune(r)
		case r == '\'' || r == '"':
			quote, in = r, true
		case r == ' ':
			if in || cur.Len() > 0 {
				words = append(words, cur.String())
				cur.Reset()
				in = false
			}
		default:
			cur.WriteRune(r)
		}
	}
	if in || cur.Len() > 0 {
		words = append(words, cur.String())
	}
	return words
}

// withHelp returns args with --help added before any "--", where the
// command still reads flags.
func withHelp(args []string) []string {
	if i := slices.Index(args, "--"); i >= 0 {
		return slices.Insert(slices.Clone(args), i, "--help")
	}
	return append(slices.Clone(args), "--help")
}

// commandShape is what --help can't tell about args: that the first word
// is a command and that a command's own words are ones it takes. It
// returns "" when args are fine.
func commandShape(args []string) string {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return ""
	}
	names := []string{"help", "version"}
	for _, c := range commands() {
		if !c.Hidden {
			names = append(names, c.Name)
		}
	}
	if !slices.Contains(names, args[0]) {
		return fmt.Sprintf("%q is not a command", args[0])
	}
	var pos []string
	for _, a := range args[1:] {
		if a == "--" {
			break
		}
		if !strings.HasPrefix(a, "-") {
			pos = append(pos, a)
		}
	}
	switch args[0] {
	case "init":
		if len(pos) > 0 && pos[0] != "ci" {
			return "init takes nothing or ci"
		}
	case "cache":
		if len(pos) == 0 || pos[0] != "prune" {
			return "cache takes prune"
		}
	case "allow":
		// A flag value such as --reason "..." is a positional word here, so
		// only the first word is checked: an action or a package reference.
		if len(pos) > 0 && !slices.Contains([]string{"list", "remove", "import"}, pos[0]) && !strings.Contains(pos[0], ":") && !slices.Contains(args, "--from") {
			return "allow takes list, remove, import or eco:name@version"
		}
	}
	return ""
}

// watchReviewFlags returns the review flags a watch line passes after
// "--", which go to the all command.
func watchReviewFlags(args []string) []string {
	if len(args) == 0 || args[0] != "watch" {
		return nil
	}
	if i := slices.Index(args, "--"); i >= 0 {
		return args[i+1:]
	}
	return nil
}

// TestREADMECommandsParse: every command README.md shows names a real
// command with flags it takes. With --help added it prints that
// command's usage and exits 0, where a mistyped flag exits 2.
func TestREADMECommandsParse(t *testing.T) {
	cmds := readmeCommands(readme(t))
	if len(cmds) < 25 {
		t.Fatalf("found only %d commands in README.md: %q", len(cmds), cmds)
	}
	cfg := t.TempDir()
	t.Chdir(t.TempDir())
	for _, args := range cmds {
		line := strings.Join(args, " ")
		if err := commandShape(args); err != "" {
			t.Errorf("%s: %s", line, err)
			continue
		}
		code, out, errOut := child(t, cfg, withHelp(args)...)
		if code != cli.ExitOK || !strings.Contains(out, "Usage:") {
			t.Errorf("%s: exit %d\n%s\n%s", line, code, out, errOut)
		}
		if review := watchReviewFlags(args); review != nil {
			code, out, errOut := child(t, cfg, withHelp(append([]string{"all"}, review...))...)
			if code != cli.ExitOK {
				t.Errorf("%s: the review flags after -- don't parse: exit %d\n%s\n%s", line, code, out, errOut)
			}
		}
	}
}

// foreignFlags are flags README.md names that belong to other programs:
// WP-CLI's --path= inside a --wp command is Sightread's --path too, so
// none is needed today. Add one here with the program it belongs to.
var foreignFlags = map[string]string{}

var readmeFlag = regexp.MustCompile("(?:^|[\\s(`\"])(--[a-z][a-z0-9-]*)")

// TestREADMEFlagsExist: every --flag README.md names is in the help of
// the tool or of one of its commands.
func TestREADMEFlagsExist(t *testing.T) {
	text := readme(t)
	cfg := t.TempDir()
	t.Chdir(t.TempDir())
	var help strings.Builder
	_, out, _ := child(t, cfg, "--help")
	help.WriteString(out)
	for _, c := range commands() {
		if c.Hidden {
			continue
		}
		code, out, errOut := child(t, cfg, c.Name, "--help")
		if code != cli.ExitOK {
			t.Fatalf("%s --help: exit %d\n%s", c.Name, code, errOut)
		}
		help.WriteString(out)
	}
	all := help.String()
	var flags []string
	for _, m := range readmeFlag.FindAllStringSubmatch(text, -1) {
		if !slices.Contains(flags, m[1]) {
			flags = append(flags, m[1])
		}
	}
	if len(flags) < 20 {
		t.Fatalf("found only %d flags in README.md: %q", len(flags), flags)
	}
	for _, f := range flags {
		if _, ok := foreignFlags[f]; ok || f == "--help" {
			continue
		}
		if !regexp.MustCompile(regexp.QuoteMeta(f) + `\b`).MatchString(all) {
			t.Errorf("README.md names %s, which no help page has", f)
		}
	}
}

var signalCount = regexp.MustCompile(`lists all (\d+) signals`)

// TestREADMESignalCount: the number of signals README.md and
// ROADMAP.md give is the catalogue's.
func TestREADMESignalCount(t *testing.T) {
	for file, re := range map[string]*regexp.Regexp{"README.md": signalCount, "ROADMAP.md": roadmapSignals} {
		data, err := os.ReadFile("../../" + file)
		if err != nil {
			t.Fatal(err)
		}
		m := re.FindStringSubmatch(string(data))
		if m == nil {
			t.Errorf("%s doesn't say how many signals there are", file)
			continue
		}
		if n, _ := strconv.Atoi(m[1]); n != len(core.Catalog) {
			t.Errorf("%s says %d signals, the catalogue has %d", file, n, len(core.Catalog))
		}
	}
}

var roadmapSignals = regexp.MustCompile(`(\d+) signals with`)

// TestREADMEExactTexts: the texts PRD 3, 18 and 23 fix word for word.
func TestREADMEExactTexts(t *testing.T) {
	text := strings.Join(strings.Fields(readme(t)), " ")
	for _, want := range []string{
		"Read the update before you install it. Sightread diffs the version you have against the one you would get from the official source and tells you, in plain words, what is new: network calls, code execution, admin users, install scripts, a new owner. It never runs the code.",
		"Sightread never runs the code it downloads. `--soundcheck` is the one exception: it installs the update on a staging copy and loads it in a browser, so the new code runs there.",
		"No risk signals found means Sightread found no known risk signal in what it could analyse. It is evidence for your review, not a guarantee that the update is safe.",
		"WordPress can install updates on its own (auto-updates, forced security releases). A gate only covers updates you run by hand or through your tooling.",
		"matches the hash and signature the npm registry publishes",
		"matches WordPress.org's own checksums (both come from WordPress.org, so this proves the copy was not changed on the way, not what the author intended)",
		"downloaded over TLS from WordPress.org; WordPress.org publishes no theme checksums",
		"pinned to commit `<sha>`; Packagist publishes no archive hash for most packages",
		"Sightread's source is MIT licensed. The `rhythm-sightread` binary links the Rhythm kit, which is AGPL-3.0-only, like the other Rhythm tools.",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("README.md lacks %q", want)
		}
	}
}

// The checks above catch a README line that went stale.
func TestStaleREADMECommandFails(t *testing.T) {
	t.Chdir(t.TempDir())
	if code, out, _ := child(t, t.TempDir(), "plugin", "akismet", "--frm", "5.3.3", "--help"); code == cli.ExitOK {
		t.Errorf("a mistyped flag passed:\n%s", out)
	}
	for _, args := range [][]string{{"plugn", "akismet"}, {"cache", "prnue"}, {"init", "cii"}, {"allow", "lst"}, {"cache"}} {
		if commandShape(args) == "" {
			t.Errorf("%v passed", args)
		}
	}
	for _, args := range [][]string{{"init", "ci"}, {"init"}, {"allow", "list"}, {"allow", "npm:sharp@0.33.5", "--reason", "x"},
		{"allow", "--from", "review.json", "--reason", "x"}, {"cache", "prune"}, {"--version"}, {"plugin", "x", "--soundcheck", "u", "--", "--echo"}} {
		if err := commandShape(args); err != "" {
			t.Errorf("%v: %s", args, err)
		}
	}
	got := readmeCommands("```sh\nrhythm sr demo   # x\nrhythm install sightread\nrhythm-sightread explain <id>\n```\nand `rhythm sightread all -o r.html` and `rhythm-sightread`\n")
	want := [][]string{{"demo"}, {"all", "-o", "r.html"}, {}}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("readmeCommands = %q, want %q", got, want)
	}
	if got := watchReviewFlags([]string{"watch", "-l", "s.yaml", "--", "--fail-on", "high"}); !slices.Equal(got, []string{"--fail-on", "high"}) {
		t.Errorf("watchReviewFlags = %q", got)
	}
}

func TestShellWords(t *testing.T) {
	got := shellWords(`a --reason 'known install script' --wp "wp --path=/srv/www" ''`)
	want := []string{"a", "--reason", "known install script", "--wp", "wp --path=/srv/www", ""}
	if !slices.Equal(got, want) {
		t.Errorf("%q", got)
	}
}
