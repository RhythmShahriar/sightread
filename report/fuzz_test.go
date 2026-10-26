// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package report

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// formatChecks are what each format must hold for any input, on top of
// the checks every format gets (no fake key, no raw escape, no bidi).
// A writer added later adds its entry here.
var formatChecks = map[string]func(t *testing.T, out []byte){
	core.FormatJSON: func(t *testing.T, out []byte) {
		if !json.Valid(out) {
			t.Errorf("json output does not parse:\n%s", out)
		}
	},
	core.FormatSARIF: func(t *testing.T, out []byte) {
		if !json.Valid(out) {
			t.Errorf("sarif output does not parse:\n%s", out)
		}
		var l sarifLog
		if err := json.Unmarshal(out, &l); err != nil {
			return
		}
		for _, run := range l.Runs {
			for _, res := range run.Results {
				for _, loc := range res.Locations {
					if uri := loc.PhysicalLocation.ArtifactLocation.URI; strings.Contains(uri, ":") || strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "..") {
						t.Errorf("sarif location %q is not inside the repository", uri)
					}
				}
			}
		}
	},
	core.FormatMarkdown: func(t *testing.T, out []byte) {
		prose := strings.ReplaceAll(outsideCode(string(out)), "[Signal reference]("+signalReference+")", "")
		prose = ownTags.ReplaceAllString(prose, "")
		if m := liveMarkup.FindString(prose); m != "" {
			t.Errorf("md: %q is live outside code", m)
		}
		if m := mention.FindString(prose); m != "" {
			t.Errorf("md: unescaped mention %q", m)
		}
		if len(out) > markdownMax {
			t.Errorf("md: %d characters, over %d", len(out), markdownMax)
		}
	},
	core.FormatJSONL: func(t *testing.T, out []byte) {
		for i, line := range bytes.Split(bytes.TrimSpace(out), []byte("\n")) {
			if !json.Valid(line) {
				t.Errorf("jsonl line %d does not parse: %s", i+1, line)
			}
		}
	},
}

var (
	// mention is an @ GitHub would turn into a mention.
	mention = regexp.MustCompile(`(^|[^\\A-Za-z0-9])@[A-Za-z]`)
	// liveMarkup is an unescaped HTML tag or link target in Markdown.
	// ownTags are the HTML tags the Markdown writer itself writes.
	ownTags    = regexp.MustCompile(`</?(details|summary)>`)
	liveMarkup = regexp.MustCompile(`(^|[^\\])(<[A-Za-z/!?]|\]\()`)
)

// hostileReport puts s everywhere a package controls text.
func hostileReport(s string) *core.Report {
	r := coretest.SampleReport()
	for i := range r.Updates {
		u := &r.Updates[i]
		u.Name += " " + s
		u.To.Version += " " + s
		u.To.Publisher = append(u.To.Publisher, s)
		u.To.Method = s
		u.Changelog = append(u.Changelog, core.ChangelogEntry{Version: s, Text: s})
		u.Hunks = append(u.Hunks, core.Hunk{Path: s, Lines: []string{"+" + s, " " + s}})
		u.Errors = append(u.Errors, core.ErrorEntry{Eco: u.Eco, Name: s, Message: s})
		for j := range u.Findings {
			f := &u.Findings[j]
			f.File = s + "/" + f.File // paths have separators; a key glued to more text is not a key
			f.Evidence = core.NewSnippet(s)
			f.Domains = append(f.Domains, s)
			f.Advice = s
		}
	}
	r.NotChecked = append(r.NotChecked, core.NotChecked{Name: s, Text: s, Hint: s})
	r.Warnings = append(r.Warnings, s)
	r.Notes = append(r.Notes, s)
	return r
}

// containsToken reports whether key appears in out as a token of its
// own: not glued to more letters or digits, which would make it another
// string that no secret rule (and no attacker) treats as that key.
func containsToken(out []byte, key string) bool {
	word := func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-'
	}
	for i := 0; ; {
		j := bytes.Index(out[i:], []byte(key))
		if j < 0 {
			return false
		}
		start, end := i+j, i+j+len(key)
		if (start == 0 || !word(out[start-1])) && (end == len(out) || !word(out[end])) {
			return true
		}
		i = start + 1
	}
}

// FuzzReportWriters sends hostile package text through every registered
// writer (SR-10): no raw fake key, escape byte or bidi override may come
// out. Each format must also keep its own shape.
func FuzzReportWriters(f *testing.F) {
	for _, kind := range coretest.FakeKeyKinds() {
		f.Add("token " + coretest.FakeKey(kind))
	}
	for _, s := range []string{
		"\x1b]52;c;ZXZpbA==\x07", "\u202eevil\u202c", "<script>alert(1)</script>", "</textarea><img src=x onerror=alert(1)>",
		"[login](https://evil.test)", "@octocat", "javascript:alert(1)", "| a | b |\n# title", "\xff\xfe", "ann@example.com",
		"sk_" + "live_" + "\u202e" + "Fk3sightreadTEST0nly4Fixtures", "```\n</details>", "{{.}}", "%s%n",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		r := hostileReport(s)
		for _, format := range core.Formats() {
			out := writeWith(t, format, r, testOpts)
			for _, kind := range coretest.FakeKeyKinds() {
				if key := coretest.FakeKey(kind); containsToken(out, key) {
					t.Errorf("%s: the fake %s key is in the output", format, kind)
				}
			}
			if bytes.IndexByte(out, 0x1b) >= 0 || bytes.IndexByte(out, 0x07) >= 0 {
				t.Errorf("%s: a raw control byte is in the output", format)
			}
			if strings.ContainsFunc(string(out), func(r rune) bool { return r >= 0x202A && r <= 0x202E || r >= 0x2066 && r <= 0x2069 }) {
				t.Errorf("%s: a bidi override is in the output", format)
			}
			if !utf8.Valid(out) {
				t.Errorf("%s: the output is not valid UTF-8", format)
			}
			if check, ok := formatChecks[format]; ok {
				check(t, out)
			} else {
				t.Errorf("%s: no format checks; add them to formatChecks", format)
			}
		}
	})
}

// FuzzReadReport: the reader never panics. A report it accepts writes
// and reads back to the same report.
func FuzzReadReport(f *testing.F) {
	f.Add(string(writeWith(f, core.FormatJSON, coretest.SampleReport(), testOpts)))
	f.Add(string(writeWith(f, core.FormatJSON, smallReport(), testOpts)))
	f.Add(`{"schema":"rhythm-sightread/v1","kind":"review","data":{"updates":[{"findings":[{"severity":"high"}]}]}}`)
	f.Add(`{"schema":"rhythm-sightread/v1","kind":"review","data":{"started":"2026-10-26T09:12:03+02:00"}}`)
	f.Fuzz(func(t *testing.T, doc string) {
		r, err := ReadReport(strings.NewReader(doc))
		if err != nil {
			if !strings.Contains(err.Error(), "the report ") {
				t.Errorf("error does not name the report: %v", err)
			}
			return
		}
		once := writeWith(t, core.FormatJSON, r, testOpts)
		r2, err := ReadReport(bytes.NewReader(once))
		if err != nil {
			t.Fatalf("a report this writer wrote does not read back: %v\n%s", err, once)
		}
		if twice := writeWith(t, core.FormatJSON, r2, testOpts); !bytes.Equal(once, twice) {
			t.Errorf("write, read, write is not stable:\n%s", firstLineDiff(once, twice))
		}
	})
}
