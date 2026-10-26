// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package changelog

import (
	"bytes"
	"io"
	"regexp"
	"slices"
	"strings"
	"unicode"

	"github.com/RhythmShahriar/sightread/core"
)

// maxFile caps a readme or changelog file read from a package.
const maxFile = 1 << 20

// maxEntries caps the entries read from one file.
const maxEntries = 1000

// versionRe finds the version at the start of a heading's text: an
// optional "Version", "v" or "[" first, then numbers with at least one
// dot and an optional suffix ("1.2.3", "2.0-beta1", "1.0.0-rc.1+b5").
var versionRe = regexp.MustCompile(`^(?i:version\s+)?\[?[vV]?(\d+(?:\.\d+){1,4}(?:[-+][0-9A-Za-z][0-9A-Za-z.+-]*)?)`)

// line is one line of the input with where it sits.
type line struct {
	text       string // without the line break and a trailing \r
	start, end int    // the byte span of the line in the input, without the break
}

// lines splits data, keeping each line's span in data.
func lines(data []byte) []line {
	var out []line
	start := 0
	for start <= len(data) {
		i := bytes.IndexByte(data[start:], '\n')
		end := len(data)
		if i >= 0 {
			end = start + i
		}
		text := strings.TrimSuffix(string(data[start:end]), "\r")
		out = append(out, line{text: text, start: start, end: end})
		if i < 0 {
			break
		}
		start = end + 1
	}
	if len(out) > 0 {
		out[0].text = strings.TrimPrefix(out[0].text, "\uFEFF")
	}
	return out
}

// heading is a version heading: where its entry's text starts and how
// deep it is (markdown level, or 0 for readme forms).
type heading struct {
	idx     int // line index
	version string
	level   int
}

// headingVersion returns the version a heading's text names.
func headingVersion(text string) (string, bool) {
	m := versionRe.FindStringSubmatch(strings.TrimSpace(text))
	if m == nil {
		return "", false
	}
	return m[1], true
}

// atx reads a markdown ATX heading: its level and text.
func atx(s string) (int, string, bool) {
	t := strings.TrimLeft(s, " ")
	if len(s)-len(t) > 3 {
		return 0, "", false
	}
	n := 0
	for n < len(t) && t[n] == '#' {
		n++
	}
	if n == 0 || n > 6 || n < len(t) && t[n] != ' ' && t[n] != '\t' {
		return 0, "", false
	}
	return n, strings.TrimRight(strings.TrimSpace(t[n:]), "# "), true
}

// readmeSection reads a readme.txt "== Name ==" section heading.
func readmeSection(s string) (string, bool) {
	t := strings.TrimSpace(s)
	if len(t) < 4 || !strings.HasPrefix(t, "==") || !strings.HasSuffix(t, "==") || strings.HasPrefix(t, "===") {
		return "", false
	}
	return strings.TrimSpace(strings.Trim(t, "=")), true
}

// readmeHeading reads a version heading inside a readme's changelog:
// "= 1.2.3 =", "= 1.2.3 - 2024-05-01 =", "* 1.2.3 *" or "#### 1.2.3".
func readmeHeading(s string) (string, bool) {
	t := strings.TrimSpace(s)
	switch {
	case len(t) > 2 && t[0] == '=' && t[1] != '=' && strings.HasSuffix(t, "=") && !strings.HasSuffix(t, "=="):
		return headingVersion(strings.Trim(t, "= "))
	case len(t) > 2 && t[0] == '*' && t[1] != '*' && strings.HasSuffix(t, "*") && !strings.HasSuffix(t, "**"):
		return headingVersion(strings.Trim(t, "* "))
	}
	if _, text, ok := atx(t); ok {
		return headingVersion(text)
	}
	return "", false
}

// FromReadme reads the entries of a WordPress readme.txt's
// "== Changelog ==" section, in the order the readme lists them. Each
// entry's Text is the raw input between its heading and the next one,
// trimmed of surrounding space; it is sanitised when written. A readme
// without the section gives no entries.
func FromReadme(readme []byte) []core.ChangelogEntry { return readmeEntries(readme, true) }

// readmeEntries reads readme-style entries ("= 1.2.3 =") from the
// Changelog section, or from the whole file when section is false (a
// plugin's changelog.txt).
func readmeEntries(readme []byte, section bool) []core.ChangelogEntry {
	ls := lines(readme)
	from, to := -1, len(ls)
	if !section {
		from = 0
	}
	for i, l := range ls {
		name, ok := readmeSection(l.text)
		if !ok {
			continue
		}
		if from >= 0 && (section || i > 0) {
			to = i
			break
		}
		if n := strings.ToLower(name); n == "changelog" || n == "change log" {
			from = i + 1
		}
	}
	if from < 0 {
		return nil
	}
	var hs []heading
	for i := from; i < to; i++ {
		if v, ok := readmeHeading(ls[i].text); ok {
			hs = append(hs, heading{idx: i, version: v})
		}
	}
	return entries(readme, ls, hs, to, func(heading, int) bool { return true })
}

// FromMarkdown reads the entries of a CHANGELOG.md, HISTORY.md or
// CHANGES.md: headings "## [1.2.3] - 2024-05-01" (Keep a Changelog),
// "## 1.2.3", "### v1.2.3" and the like. An entry runs to the next
// heading at its level or above or the next version heading, so
// "### Added" stays inside it; a heading without a version
// ("## [Unreleased]") ends the entry before it.
func FromMarkdown(md []byte) []core.ChangelogEntry {
	ls := lines(md)
	var hs []heading
	inFence := false
	for i, l := range ls {
		t := strings.TrimSpace(l.text)
		if strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		level, text, ok := atx(l.text)
		if !ok {
			continue
		}
		v, _ := headingVersion(text)
		hs = append(hs, heading{idx: i, version: v, level: level})
	}
	// Every heading bounds an entry; only versioned ones start one.
	return entries(md, ls, hs, len(ls), func(next heading, level int) bool {
		return next.version != "" || next.level <= level
	})
}

// entries cuts the text of each versioned heading in hs, up to the next
// heading that ends it or end.
func entries(data []byte, ls []line, hs []heading, end int, ends func(next heading, level int) bool) []core.ChangelogEntry {
	var out []core.ChangelogEntry
	for i, h := range hs {
		if h.version == "" {
			continue
		}
		stop := end
		for _, n := range hs[i+1:] {
			if ends(n, h.level) {
				stop = n.idx
				break
			}
		}
		text := ""
		if h.idx+1 < stop {
			text = strings.TrimSpace(string(data[ls[h.idx+1].start:ls[stop-1].end]))
		}
		out = append(out, core.ChangelogEntry{Version: h.version, Text: text, Generic: Generic(text)})
		if len(out) == maxEntries {
			break
		}
	}
	return out
}

// Between returns the entries newer than from and up to to, newest
// first, by scheme. An empty from means every entry up to to; an empty
// to means no upper bound. Entries the scheme can't read are left out,
// as are repeated versions after the first.
func Between(entries []core.ChangelogEntry, from, to string, scheme core.VersionScheme) []core.ChangelogEntry {
	var out []core.ChangelogEntry
	seen := map[string]bool{}
	for _, e := range entries {
		if !scheme.Valid(e.Version) || seen[e.Version] {
			continue
		}
		if from != "" && scheme.Compare(e.Version, from) <= 0 {
			continue
		}
		if to != "" && scheme.Compare(e.Version, to) > 0 {
			continue
		}
		seen[e.Version] = true
		out = append(out, e)
	}
	slices.SortStableFunc(out, func(a, b core.ChangelogEntry) int { return scheme.Compare(b.Version, a.Version) })
	return out
}

// phrases are the boilerplate a changelog bullet may consist of, after
// lower-casing and dropping punctuation.
var phrases = []string{
	"check compatibility", "compatible with wordpress", "tested up to", "tested with", "minor fixes",
	"bug fixes", "small fixes", "performance improvements", "improvements", "maintenance release",
	"updated dependencies", "version bump", "improved compatibility", "improved performance",
	"stability improvements", "enhancements",
}

// filler are the words a boilerplate bullet may have around a phrase:
// "Check compatibility with WordPress version 6.8.2".
var filler = map[string]bool{
	"a": true, "an": true, "and": true, "the": true, "with": true, "for": true, "to": true, "of": true,
	"up": true, "wordpress": true, "wp": true, "woocommerce": true, "php": true, "version": true,
	"versions": true, "latest": true, "new": true, "release": true, "some": true, "various": true,
	"general": true, "other": true, "few": true, "minor": true, "small": true,
	"plugin": true, "theme": true, "core": true, "compatibility": true, "tested": true,
	"fix": true, "fixed": true, "update": true, "updated": true, "tweak": true, "misc": true,
	"performance": true, "stability": true, "improved": true,
}

// Generic reports whether a changelog entry says nothing a reviewer can
// check against the diff: empty, or every line only boilerplate such as
// "Check compatibility with WordPress version 6.8.2" or "Bug fixes".
// Comparing nouns with the diff is the detector's job; this is the
// phrase check only.
func Generic(text string) bool {
	for _, l := range strings.Split(text, "\n") {
		if words := normalize(l); len(words) > 0 && !boilerplate(words) {
			return false
		}
	}
	return true
}

// normalize lower-cases a line, drops list markers and punctuation and
// splits it into words. "stats.example.com" becomes one word, which no
// phrase or filler list holds.
func normalize(l string) []string {
	var b strings.Builder
	for _, r := range strings.ToLower(l) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
		case unicode.IsSpace(r):
			b.WriteByte(' ')
		}
	}
	return strings.Fields(b.String())
}

// boilerplate reports whether words hold at least one phrase and
// nothing else but filler and numbers.
func boilerplate(words []string) bool {
	s := " " + strings.Join(words, " ") + " "
	found := false
	for _, p := range phrases {
		if strings.Contains(s, " "+p+" ") {
			found = true
			s = strings.ReplaceAll(s, " "+p+" ", "  ")
		}
	}
	if !found {
		return false
	}
	for _, w := range strings.Fields(s) {
		if !filler[w] && strings.Trim(w, "0123456789") != "" {
			return false
		}
	}
	return true
}

// readmeNames and markdownNames are the files FromTree reads, in order.
var (
	readmeNames   = []string{"readme.txt", "README.txt"}
	markdownNames = []string{"CHANGELOG.md", "changelog.md", "Changelog.md", "HISTORY.md", "History.md", "CHANGES.md", "changes.md"}
)

// FromTree returns the changelog entries of a package: the readme.txt
// Changelog section when it has entries, else changelog.txt in the
// readme's format, else the first markdown
// changelog at the top of the tree. Sources fill core.Meta.Changelog
// with it; run keeps the entries Between the two sides.
func FromTree(tree *core.Tree) []core.ChangelogEntry {
	for _, n := range readmeNames {
		if data, ok := read(tree, n); ok {
			if es := FromReadme(data); len(es) > 0 {
				return es
			}
		}
	}
	// Plugins that keep a long changelog move it to changelog.txt in the
	// readme's format.
	if data, ok := read(tree, "changelog.txt"); ok {
		if es := readmeEntries(data, false); len(es) > 0 {
			return es
		}
	}
	for _, n := range markdownNames {
		if data, ok := read(tree, n); ok {
			if es := FromMarkdown(data); len(es) > 0 {
				return es
			}
		}
	}
	return nil
}

// read returns a regular file of tree up to maxFile bytes.
func read(tree *core.Tree, p string) ([]byte, bool) {
	f, ok := tree.Lookup(p)
	if !ok || !f.Mode.IsRegular() || f.Size > maxFile || tree.Blobs == nil {
		return nil, false
	}
	rc, err := tree.Blobs.Open(f.SHA256)
	if err != nil {
		return nil, false
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, maxFile))
	if err != nil {
		return nil, false
	}
	return data, true
}
