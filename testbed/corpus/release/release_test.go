// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package release

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sha = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestParseLock(t *testing.T) {
	lock := "# header\n\nwp-plugin akismet 5.3 5.3.1 - -\nnpm @babel/core 7.23.6 7.23.7 " + sha + " " + sha + "\n"
	got, err := ParseLock(strings.NewReader(lock))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "akismet" || got[0].Pinned() || !got[1].Pinned() || got[1].Ref() != "npm:@babel/core" {
		t.Errorf("ParseLock = %+v", got)
	}
}

func TestParseLockRejects(t *testing.T) {
	for name, line := range map[string]string{
		"fields":       "wp-plugin akismet 5.3 5.3.1 -",
		"ecosystem":    "composer acme/x 1.0 1.1 - -",
		"slug":         "wp-plugin ../etc 1.0 1.1 - -",
		"slug upper":   "wp-plugin Akismet 1.0 1.1 - -",
		"npm name":     "npm ../../x 1.0 1.1 - -",
		"version":      "npm lodash 1.0/../x 1.1 - -",
		"same version": "npm lodash 1.0 1.0 - -",
		"hash":         "npm lodash 1.0 1.1 abc -",
		"upper hash":   "npm lodash 1.0 1.1 " + strings.ToUpper(sha) + " -",
		"duplicate":    "npm lodash 1.0 1.1 - -\nnpm lodash 2.0 2.1 - -",
		"empty":        "# only a comment",
	} {
		if _, err := ParseLock(strings.NewReader(line)); err == nil {
			t.Errorf("%s: %q was accepted", name, line)
		}
	}
}

// TestCommittedLock checks testbed/corpus/corpus.lock: 50 plugins and
// 50 npm packages; it survives a format round trip.
func TestCommittedLock(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "corpus.lock"))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := ParseLock(strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	n := map[string]int{}
	for _, e := range entries {
		n[e.Ecosystem]++
	}
	if n[EcoWPPlugin] != 50 || n[EcoNPM] != 50 {
		t.Errorf("the lock has %d plugins and %d npm packages, want 50 and 50", n[EcoWPPlugin], n[EcoNPM])
	}
	if again := FormatLock(Header(string(b)), entries); again != string(b) {
		t.Errorf("FormatLock(ParseLock(lock)) changed the file:\n%s", again)
	}
}

func TestURLAndCachePath(t *testing.T) {
	wp := Entry{Ecosystem: EcoWPPlugin, Name: "akismet"}
	if got := URL(wp, "5.3.1"); got != "https://downloads.wordpress.org/plugin/akismet.5.3.1.zip" {
		t.Errorf("wp URL %s", got)
	}
	scoped := Entry{Ecosystem: EcoNPM, Name: "@babel/core"}
	if got := URL(scoped, "7.23.7"); got != "https://registry.npmjs.org/@babel/core/-/core-7.23.7.tgz" {
		t.Errorf("npm URL %s", got)
	}
	p := CachePath("/c", scoped, "7.23.7")
	if filepath.ToSlash(p) != "/c/npm/@babel__core/7.23.7.tgz" {
		t.Errorf("cache path %s", p)
	}
}

func fakeRun() Run {
	e := func(eco, name string) Entry {
		return Entry{Ecosystem: eco, Name: name, From: "1.0", To: "1.1", FromSHA: sha, ToSHA: sha}
	}
	r := Run{
		Fetched: time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC),
		Ran:     time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC),
		Version: "rhythm-sightread 1.0.0", Machine: "linux/amd64",
		Timings: []Timing{
			{Case: "one 5 MB plugin, cold", Target: "under 10 s", Limit: 10, Seconds: 4.2},
			{Case: "watch over 50 sites", Target: "under 10 min", Limit: 600, Seconds: -1, Note: "no sites"},
		},
	}
	for i := 0; i < 18; i++ {
		r.Reviews = append(r.Reviews, Review{Entry: e(EcoNPM, "pkg"+string(rune('a'+i))), Verdict: "ROUTINE"})
	}
	r.Reviews = append(r.Reviews,
		Review{Entry: e(EcoWPPlugin, "jetpack"), Verdict: "REVIEW", Findings: []Finding{{ID: "outbound-new-domain", Severity: "medium"}}},
		Review{Entry: e(EcoNPM, "broken"), Verdict: "ERROR", Error: "sha256 mismatch"},
	)
	return r
}

func TestRenderSection(t *testing.T) {
	r := fakeRun()
	c := r.Count()
	if c.Total != 19 || c.Review != 1 || c.Errors != 1 || !c.TargetMet() {
		t.Fatalf("counts %+v met %v", c, c.TargetMet())
	}
	page := RenderSection(r)
	for _, want := range []string{
		"## Real releases (owner-run)",
		"Fetched 2026-10-20 by the owner",
		"| 0 | 1 | 18 | 0 | 1 | met (1 of 19 flagged, 5.3%) |",
		"| wp-plugin:jetpack | 1.0 to 1.1 | REVIEW | outbound-new-domain (medium) |",
		"- npm:broken 1.0 to 1.1: sha256 mismatch",
		"| one 5 MB plugin, cold | under 10 s | 4.2 s | met |",
		"| watch over 50 sites | under 10 min | not run | not run (no sites) |",
	} {
		if !strings.Contains(page, want) {
			t.Errorf("section misses %q\n%s", want, page)
		}
	}

	// One HOLD fails the target; so do two REVIEW in ten.
	r.Reviews[0].Verdict = "HOLD"
	if r.Count().TargetMet() || !strings.Contains(RenderSection(r), "**not met**") {
		t.Error("a HOLD on a real release met the target")
	}
	r = fakeRun()
	r.Reviews = r.Reviews[:9]
	r.Reviews = append(r.Reviews, Review{Verdict: "REVIEW"}, Review{Verdict: "REVIEW"})
	if r.Count().TargetMet() {
		t.Errorf("2 REVIEW in %d met the target", r.Count().Total)
	}
	if (Run{}).Count().TargetMet() {
		t.Error("an empty run met the target")
	}
	empty := RenderSection(Run{Reviews: []Review{{Verdict: "ERROR", Error: "not fetched"}}})
	for _, want := range []string{"Not fetched yet", "Nothing was reviewed.", "Not measured in this run."} {
		if !strings.Contains(empty, want) {
			t.Errorf("an empty run misses %q", want)
		}
	}
}

func FuzzParseLock(f *testing.F) {
	f.Add("wp-plugin akismet 5.3 5.3.1 - -\n")
	f.Add("npm @babel/core 7.23.6 7.23.7 " + sha + " " + sha + "\n")
	f.Add("# c\n\nnpm a 1 2 - -\nnpm a 1 2 - -\n")
	f.Fuzz(func(t *testing.T, lock string) {
		entries, err := ParseLock(strings.NewReader(lock))
		if err != nil {
			return
		}
		// Whatever parses stays inside the registry and the cache.
		for _, e := range entries {
			for _, v := range []string{e.From, e.To} {
				u := URL(e, v)
				if !strings.HasPrefix(u, "https://downloads.wordpress.org/plugin/") && !strings.HasPrefix(u, "https://registry.npmjs.org/") {
					t.Fatalf("URL %q left the registry", u)
				}
				p := CachePath("/cache", e, v)
				if rel, err := filepath.Rel("/cache", p); err != nil || strings.HasPrefix(rel, "..") {
					t.Fatalf("cache path %q left the cache", p)
				}
			}
		}
		again, err := ParseLock(strings.NewReader(FormatLock("# h\n", entries)))
		if err != nil || len(again) != len(entries) {
			t.Fatalf("round trip: %v, %d of %d", err, len(again), len(entries))
		}
	})
}
