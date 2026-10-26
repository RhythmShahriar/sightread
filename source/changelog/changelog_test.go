// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package changelog

import (
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
	"github.com/RhythmShahriar/sightread/version"
)

// readme is a readme.txt in the shape WordPress.org plugins use (made
// up, after Countdown Timer Ultimate's).
const readme = `=== Countdown Timer Ultimate ===
Contributors: example
Stable tag: 2.6.8

== Description ==

= 9.9.9 =
Not a changelog heading: outside the section.

== Changelog ==

= 2.6.8 (03, June 2025) =
* Check compatibility with WordPress version 6.8.2

= 2.6.7 - 2025-05-01 =
* Added telemetry to stats.example.com
* Bug fixes

* 2.6.6 *
* Tested up to WordPress 6.7

#### 2.6.5
* [Fix] Escaped the timer title in admin/settings.php.

== Upgrade Notice ==

= 2.6.8 =
Upgrade now.
`

func versions(es []core.ChangelogEntry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Version)
	}
	return out
}

func TestFromReadme(t *testing.T) {
	es := FromReadme([]byte(readme))
	if got := versions(es); !slices.Equal(got, []string{"2.6.8", "2.6.7", "2.6.6", "2.6.5"}) {
		t.Fatalf("versions = %v", got)
	}
	if es[0].Text != "* Check compatibility with WordPress version 6.8.2" || !es[0].Generic {
		t.Errorf("2.6.8 = %+v", es[0])
	}
	if es[1].Generic || !strings.Contains(es[1].Text, "stats.example.com") {
		t.Errorf("2.6.7 = %+v", es[1])
	}
	if !es[2].Generic {
		t.Errorf("2.6.6 = %+v", es[2])
	}
	if es[3].Generic {
		t.Errorf("2.6.5 = %+v", es[3])
	}
}

func TestFromReadmeCRLFAndBOM(t *testing.T) {
	in := "\uFEFF" + strings.ReplaceAll(readme, "\n", "\r\n")
	es := FromReadme([]byte(in))
	if got := versions(es); !slices.Equal(got, []string{"2.6.8", "2.6.7", "2.6.6", "2.6.5"}) {
		t.Fatalf("versions = %v", got)
	}
	if es[0].Text != "* Check compatibility with WordPress version 6.8.2" || !es[0].Generic {
		t.Errorf("2.6.8 = %q", es[0].Text)
	}
	// A BOM before the section itself.
	if es := FromReadme([]byte("\uFEFF== Changelog ==\r\n= 1.0 =\r\n* First\r\n")); len(es) != 1 || es[0].Text != "* First" {
		t.Errorf("BOM section: %+v", es)
	}
}

func TestFromReadmeNoSection(t *testing.T) {
	if es := FromReadme([]byte("=== X ===\n\n== Description ==\n= 1.0 =\n* x\n")); es != nil {
		t.Errorf("entries without a Changelog section: %+v", es)
	}
	if es := FromReadme(nil); es != nil {
		t.Errorf("empty input: %+v", es)
	}
}

const keepAChangelog = `# Changelog
All notable changes to this project will be documented in this file.

## [Unreleased]
### Added
- Something not released

## [1.4.0] - 2026-10-01
### Added
- Post-install hook that downloads a binary.

### Fixed
- Typo.

## [1.3.0] - 2026-09-01
- Updated dependencies

` + "```" + `
## 9.9.9 inside a code block
` + "```" + `

## 1.2.0
- Version bump

### v1.1.0
Nested under 1.2.0 but a version of its own.

[1.4.0]: https://example.com/compare/v1.3.0...v1.4.0
`

func TestFromMarkdown(t *testing.T) {
	es := FromMarkdown([]byte(keepAChangelog))
	if got := versions(es); !slices.Equal(got, []string{"1.4.0", "1.3.0", "1.2.0", "1.1.0"}) {
		t.Fatalf("versions = %v", got)
	}
	if !strings.Contains(es[0].Text, "### Fixed") || strings.Contains(es[0].Text, "Unreleased") || es[0].Generic {
		t.Errorf("1.4.0 = %q", es[0].Text)
	}
	// The code block is text of 1.3.0, so it is not only boilerplate.
	if es[1].Generic || !strings.Contains(es[1].Text, "9.9.9") {
		t.Errorf("1.3.0 = %+v", es[1])
	}
	if !es[2].Generic || strings.Contains(es[2].Text, "v1.1.0") || es[2].Text != "- Version bump" {
		t.Errorf("1.2.0 = %+v", es[2])
	}
	if es := FromMarkdown([]byte("# Notes\nno versions here\n")); es != nil {
		t.Errorf("no versions: %+v", es)
	}
}

func TestGeneric(t *testing.T) {
	for text, want := range map[string]bool{
		"Check compatibility with WordPress version 6.8.2":   true,
		"* Check compatibility with WordPress version 6.8.2": true,
		"Added telemetry to stats.example.com":               false,
		"":                                                   true,
		"* Bug fixes\n* Performance improvements":            true,
		"* Bug fixes\n* New REST endpoint for exports":       false,
		"- Tested up to 6.7\r\n- Maintenance release":        true,
		"Bug fixes and a new uploader":                       false,
		"Compatible with WordPress 6.8":                      true,
		"Minor fixes in includes/class-loader.php":           false,
		"Improvements to the payment gateway":                false,
		"Updated dependencies.":                              true,
		"[Fix] Version bump":                                 true,
		"Removed the `eval` call":                            false,
		"* Improved compatibility and performance.":          true,
		"Performance and stability improvements":             true,
		"Improved performance of the REST sync":              false,
		"Enhancements to the license check":                  false,
	} {
		if got := Generic(text); got != want {
			t.Errorf("Generic(%q) = %v, want %v", text, got, want)
		}
	}
}

func TestBetween(t *testing.T) {
	es := FromReadme([]byte(readme))
	got := Between(es, "2.6.6", "2.6.8", version.WordPress)
	if !slices.Equal(versions(got), []string{"2.6.8", "2.6.7"}) {
		t.Errorf("Between = %v", versions(got))
	}
	if got := Between(es, "", "2.6.6", version.WordPress); !slices.Equal(versions(got), []string{"2.6.6", "2.6.5"}) {
		t.Errorf("from empty = %v", versions(got))
	}
	md := FromMarkdown([]byte(keepAChangelog))
	if got := Between(md, "1.1.0", "", version.NPM); !slices.Equal(versions(got), []string{"1.4.0", "1.3.0", "1.2.0"}) {
		t.Errorf("to empty = %v", versions(got))
	}
	if got := Between(es, "2.6.8", "2.6.8", version.WordPress); got != nil {
		t.Errorf("same version = %v", versions(got))
	}
}

func TestFromTree(t *testing.T) {
	tree := coretest.Tree(map[string]string{"readme.txt": readme, "CHANGELOG.md": keepAChangelog})
	if got := versions(FromTree(tree)); len(got) == 0 || got[0] != "2.6.8" {
		t.Errorf("readme first: %v", got)
	}
	tree = coretest.Tree(map[string]string{"readme.txt": "=== X ===\n", "CHANGELOG.md": keepAChangelog})
	if got := versions(FromTree(tree)); len(got) == 0 || got[0] != "1.4.0" {
		t.Errorf("markdown fallback: %v", got)
	}
	tree = coretest.Tree(map[string]string{"readme.txt": "=== X ===\n", "changelog.txt": "== Changelog ==\n= 5.3.5 =\n* Fix\n= 5.3.4 =\n* Tested up to 6.6\n"})
	if got := FromTree(tree); len(got) != 2 || got[0].Text != "* Fix" || !got[1].Generic {
		t.Errorf("changelog.txt: %+v", got)
	}
	if got := FromTree(coretest.Tree(map[string]string{"index.js": "x"})); got != nil {
		t.Errorf("no changelog: %v", got)
	}
}

func checkSubstrings(t *testing.T, in string, es []core.ChangelogEntry) {
	t.Helper()
	for _, e := range es {
		if !strings.Contains(in, e.Text) {
			t.Fatalf("entry %q text %q is not in the input", e.Version, e.Text)
		}
		if !strings.Contains(in, e.Version) {
			t.Fatalf("version %q is not in the input", e.Version)
		}
	}
}

func FuzzReadmeChangelog(f *testing.F) {
	f.Add(readme)
	f.Add("\uFEFF== Changelog ==\r\n= 1.0 =\r\n* x\r\n= 1.1 =")
	f.Add("== Changelog ==\n= 1.0 =")
	f.Fuzz(func(t *testing.T, in string) {
		checkSubstrings(t, in, FromReadme([]byte(in)))
	})
}

func FuzzMarkdownChangelog(f *testing.F) {
	f.Add(keepAChangelog)
	f.Add("## 1.0.0\n## 1.0.1\r\n- x")
	f.Add("```\n## 1.0\n")
	f.Fuzz(func(t *testing.T, in string) {
		checkSubstrings(t, in, FromMarkdown([]byte(in)))
	})
}
