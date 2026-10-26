// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package detect

import (
	"regexp"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/RhythmShahriar/sightread/core"
)

func TestEverySignalHasExplain(t *testing.T) {
	if len(Texts()) != len(core.Catalog) {
		t.Errorf("%d explain files for %d signals", len(Texts()), len(core.Catalog))
	}
	for _, id := range core.SignalIDs() {
		e, ok := core.ExplainFor(id)
		if !ok {
			t.Errorf("%s: no explain text registered", id)
			continue
		}
		if e.Why == "" || e.HowToReview == "" || e.Advice == "" || !strings.HasSuffix(e.More, "#"+id) {
			t.Errorf("%s: incomplete: %+v", id, e)
		}
		if !strings.HasPrefix(e.HowToReview, "1. ") {
			t.Errorf("%s: review steps are not numbered: %q", id, e.HowToReview)
		}
	}
}

var (
	forbiddenTitle = regexp.MustCompile(`(?i)\b(malware|backdoor|safe)\b`)
	forbiddenWhy   = regexp.MustCompile(`(?i)\b(malware|backdoor)`)
	sentenceEnd    = regexp.MustCompile(`[.!?]["')]?(\s|$)`)
	// The Rhythm writing rules, as check-style.py applies them.
	emDash      = regexp.MustCompile("\u2014")
	commaAndBut = regexp.MustCompile(`,\s*(and|but)\b`)
)

// Titles and advice describe behaviour: never "malware", "backdoor" or
// "safe" (PRD 4 principle 5). The why text keeps to behaviour words too.
func TestExplainWording(t *testing.T) {
	for _, s := range core.Catalog {
		if m := forbiddenTitle.FindString(s.Title); m != "" {
			t.Errorf("%s: title %q says %q", s.ID, s.Title, m)
		}
	}
	for id, x := range Texts() {
		if m := forbiddenTitle.FindString(x.Advice); m != "" {
			t.Errorf("%s: advice %q says %q", id, x.Advice, m)
		}
		if m := forbiddenWhy.FindString(x.Why); m != "" {
			t.Errorf("%s: why says %q", id, m)
		}
		if n := len(sentenceEnd.FindAllString(x.Why, -1)); n < 2 || n > 4 {
			t.Errorf("%s: why has %d sentences, want 2 to 4: %q", id, n, x.Why)
		}
		fields := append([]string{x.Why, x.FalseAlarms, x.Advice}, x.HowToReview...)
		for _, in := range x.Incidents {
			fields = append(fields, in.Name, in.Line)
		}
		for _, f := range fields {
			if emDash.MatchString(f) || commaAndBut.MatchString(f) {
				t.Errorf("%s: breaks the writing rules: %q", id, f)
			}
		}
		if !strings.HasSuffix(x.Advice, ".") {
			t.Errorf("%s: advice is not a sentence: %q", id, x.Advice)
		}
	}
}

func TestExplainFlatten(t *testing.T) {
	x := Text{HowToReview: []string{"a", "b"}, Incidents: []Incident{{"X 2020", "one"}, {"Y", "two"}}}
	e := x.Explain()
	if e.HowToReview != "1. a\n2. b" || e.Incidents != "X 2020: one\nY: two" {
		t.Errorf("%+v", e)
	}
}

func TestLoadTextsErrors(t *testing.T) {
	good := func(id string) string {
		return "why: a. b.\nhow_to_review: [x]\nfalse_alarms: None.\nincidents: []\nadvice: Hold it.\nmore: " + WikiBase + "#" + id + "\n"
	}
	all := fstest.MapFS{}
	for _, id := range core.SignalIDs() {
		all[id+".yaml"] = &fstest.MapFile{Data: []byte(good(id))}
	}
	if _, err := LoadTexts(all); err != nil {
		t.Fatalf("good set: %v", err)
	}
	for _, tc := range []struct{ name, file, body, want string }{
		{"unknown key", "fresh-release.yaml", good("fresh-release") + "wyh: x\n", "field wyh not found"},
		{"unknown id", "fresh-releases.yaml", good("fresh-releases"), `"fresh-releases" is not a signal ID`},
		{"no why", "fresh-release.yaml", "how_to_review: [x]\nfalse_alarms: x\nadvice: x.\nmore: " + WikiBase + "#fresh-release\n", "why: missing"},
		{"no steps", "fresh-release.yaml", "why: a. b.\nfalse_alarms: x\nadvice: x.\nmore: " + WikiBase + "#fresh-release\n", "how_to_review: missing"},
		{"two-line advice", "fresh-release.yaml", "why: a. b.\nhow_to_review: [x]\nfalse_alarms: x\nadvice: \"a.\\nb.\"\nmore: " + WikiBase + "#fresh-release\n", "advice: want one line"},
		{"wrong anchor", "fresh-release.yaml", strings.Replace(good("fresh-release"), "#fresh-release", "#dormant-release", 1), "more: want"},
		{"half incident", "fresh-release.yaml", strings.Replace(good("fresh-release"), "incidents: []", "incidents: [{name: X}]", 1), "incidents: entry 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fsys := fstest.MapFS{}
			for k, v := range all {
				fsys[k] = v
			}
			fsys[tc.file] = &fstest.MapFile{Data: []byte(tc.body)}
			_, err := LoadTexts(fsys)
			if err == nil || !strings.Contains(err.Error(), tc.file+": ") || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %s and %q", err, tc.file, tc.want)
			}
		})
	}
	delete(all, "typosquat.yaml")
	if _, err := LoadTexts(all); err == nil || !strings.Contains(err.Error(), "typosquat.yaml: missing") {
		t.Errorf("missing file: %v", err)
	}
}
