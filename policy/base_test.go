// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package policy

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// gitProject makes a project folder that is the top of a git repository
// and serves files at "origin/main" through a fake git show.
func gitProject(t *testing.T, files map[string]string) (string, *fakeGit) {
	t.Helper()
	dir := inProject(t)
	if err := os.Mkdir(filepath.Join(dir, ".git"), 0o750); err != nil {
		t.Fatal(err)
	}
	g := &fakeGit{files: files}
	t.Cleanup(core.SwapGitShow(g.show))
	return dir, g
}

const baseConfig = `fail_on: medium
signals:
  severity:
    license-change: high
    eval-dynamic: medium
  domains_ok: [api.example.com]
ignore:
  - id: outbound-new-domain
    package: npm:left-pad
    reason: talks to its own API
    until: 2026-12-31
  - id: obfuscation
    reason: minified bundles
`

func TestConfigAtBaseRelaxations(t *testing.T) {
	dir, g := gitProject(t, map[string]string{"origin/main:.sightread/config.yaml": baseConfig})
	head := `fail_on: critical
min_confidence: confirmed
signals:
  severity:
    eval-dynamic: low
    remote-fetch-exec: critical
  domains_ok: [api.example.com, evil.example.net]
ignore:
  - id: outbound-new-domain
    package: npm:left-pad
    reason: reworded, still its own API
    until: 2027-12-31
  - id: obfuscation
    reason: minified bundles
  - id: remote-fetch-exec
    reason: trust me
`
	writeConfig(t, dir, head)
	s := testStore(nil)
	cfg, cp, err := s.LoadConfig(dir, "", false)
	if err != nil {
		t.Fatal(err)
	}
	notes, err := s.ConfigAtBase(cfg, cp, "origin/main")
	if err != nil {
		t.Fatal(err)
	}
	if len(g.calls) != 1 || g.calls[0] != "origin/main:.sightread/config.yaml" {
		t.Errorf("git show calls %v", g.calls)
	}
	want := []string{
		"ignore outbound-new-domain package \"npm:left-pad\" until 2027-12-31: relaxed in this change, not counted (--trust-pr-allow counts it)",
		"ignore remote-fetch-exec: relaxed in this change, not counted (--trust-pr-allow counts it)",
		"signals.severity.eval-dynamic low: relaxed in this change, not counted (--trust-pr-allow counts it)",
		"signals.severity.license-change removed: relaxed in this change, not counted (--trust-pr-allow counts it)",
		`signals.domains_ok "evil.example.net": relaxed in this change, not counted (--trust-pr-allow counts it)`,
		"min_confidence confirmed: relaxed in this change, not counted (--trust-pr-allow counts it)",
		"fail_on critical: relaxed in this change, not counted (--trust-pr-allow counts it)",
	}
	if strings.Join(notes, "\n") != strings.Join(want, "\n") {
		t.Errorf("notes:\n%s\nwant:\n%s", strings.Join(notes, "\n"), strings.Join(want, "\n"))
	}
	if len(cfg.Ignore) != 2 || cfg.Ignore[0].Until != "2026-12-31" || cfg.Ignore[1].ID != "obfuscation" {
		t.Errorf("ignore %+v", cfg.Ignore)
	}
	if cfg.Signals.Severity["eval-dynamic"] != "medium" || cfg.Signals.Severity["license-change"] != "high" ||
		cfg.Signals.Severity["remote-fetch-exec"] != "critical" {
		t.Errorf("severity %v", cfg.Signals.Severity)
	}
	if !slices.Equal(cfg.Signals.DomainsOK, []string{"api.example.com"}) {
		t.Errorf("domains_ok %v", cfg.Signals.DomainsOK)
	}
	if cfg.MinConfidence != "" || cfg.FailOn != "medium" {
		t.Errorf("min_confidence %q fail_on %q", cfg.MinConfidence, cfg.FailOn)
	}
}

func TestConfigAtBaseStricterChangeCounts(t *testing.T) {
	dir, _ := gitProject(t, map[string]string{"origin/main:.sightread/config.yaml": baseConfig})
	// Every change here makes Sightread stricter, so all of it applies.
	head := `fail_on: low
signals:
  severity:
    license-change: critical
    eval-dynamic: high
ignore:
  - id: outbound-new-domain
    package: npm:left-pad
    reason: talks to its own API
    until: 2026-11-30
`
	writeConfig(t, dir, head)
	s := testStore(nil)
	cfg, cp, err := s.LoadConfig(dir, "", false)
	if err != nil {
		t.Fatal(err)
	}
	notes, err := s.ConfigAtBase(cfg, cp, "origin/main")
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 0 {
		t.Errorf("notes for a stricter change: %q", notes)
	}
	if cfg.FailOn != "low" || cfg.Ignore[0].Until != "2026-11-30" || cfg.Signals.Severity["eval-dynamic"] != "high" {
		t.Errorf("a stricter value was changed: %+v", cfg)
	}
}

func TestConfigAtBaseNoBaseFile(t *testing.T) {
	dir, _ := gitProject(t, nil)
	writeConfig(t, dir, "ignore:\n  - id: remote-fetch-exec\n    reason: trust me\nsignals:\n  severity:\n    eval-dynamic: info\n")
	s := testStore(nil)
	cfg, cp, err := s.LoadConfig(dir, "", false)
	if err != nil {
		t.Fatal(err)
	}
	notes, err := s.ConfigAtBase(cfg, cp, "origin/main")
	if err != nil {
		t.Fatal(err)
	}
	if len(notes) != 2 || len(cfg.Ignore) != 0 || cfg.Signals.Severity["eval-dynamic"] != "high" {
		t.Errorf("a config new in this change must not relax anything: %q %+v", notes, cfg)
	}
}

func TestConfigAtBaseSkips(t *testing.T) {
	dir, g := gitProject(t, nil)
	head := "ignore:\n  - id: remote-fetch-exec\n    reason: trust me\n"
	writeConfig(t, dir, head)
	s := testStore(nil)
	cfg, cp, err := s.LoadConfig(dir, "", false)
	if err != nil {
		t.Fatal(err)
	}
	// --trust-pr-allow passes no base ref; no config means nothing to do.
	for _, c := range []struct{ path, ref string }{{cp, ""}, {"", "origin/main"}} {
		notes, err := s.ConfigAtBase(cfg, c.path, c.ref)
		if err != nil || notes != nil || len(cfg.Ignore) != 1 {
			t.Errorf("%+v: %q %v %+v", c, notes, err, cfg.Ignore)
		}
	}
	// A --config file outside the repository can't be changed by it.
	outside := filepath.Join(t.TempDir(), "sightread.yaml")
	writeFile(t, outside, head)
	if notes, err := s.ConfigAtBase(cfg, outside, "origin/main"); err != nil || notes != nil || len(cfg.Ignore) != 1 {
		t.Errorf("outside: %q %v", notes, err)
	}
	if len(g.calls) != 0 {
		t.Errorf("git show called: %v", g.calls)
	}

	t.Cleanup(core.SwapGitShow(nil))
	if _, err := s.ConfigAtBase(cfg, cp, "origin/main"); !errors.Is(err, core.ErrNotLinked) {
		t.Errorf("without git show: %v", err)
	}
}

func TestBaselineAtBase(t *testing.T) {
	r := coretest.SampleReport()
	old := *r
	old.Updates = r.Updates[:1]
	dir, g := gitProject(t, map[string]string{"origin/main:ci/baseline.json": string(reviewJSON(t, &old, false))})
	p := filepath.Join(dir, "ci", "baseline.json")
	writeFile(t, p, string(reviewJSON(t, r, false)))
	s := testStore(nil)
	set, err := s.LoadBaseline(p)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, f := range old.Updates[0].Findings {
		want[f.Fingerprint] = true
	}
	got, dropped, err := s.BaselineAtBase(set, p, "origin/main")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(want) || dropped != len(set)-len(want) || dropped == 0 {
		t.Fatalf("kept %d dropped %d, want %d kept of %d", len(got), dropped, len(want), len(set))
	}
	for fp := range want {
		if !got[fp] {
			t.Errorf("fingerprint %s from the base is gone", fp)
		}
	}

	// --trust-pr-allow: no base ref, every fingerprint counts.
	if got, dropped, _ := s.BaselineAtBase(set, p, ""); len(got) != len(set) || dropped != 0 {
		t.Error("with no base ref the baseline must be unchanged")
	}

	// A baseline the base doesn't have keeps nothing.
	g.files = nil
	if got, dropped, _ := s.BaselineAtBase(set, p, "origin/main"); len(got) != 0 || dropped != len(set) {
		t.Errorf("a baseline new in this change kept %d", len(got))
	}

	// A saved report outside the repository counts in full.
	outside := filepath.Join(t.TempDir(), "baseline.json")
	writeFile(t, outside, string(reviewJSON(t, r, false)))
	if got, _, _ := s.BaselineAtBase(set, outside, "origin/main"); len(got) != len(set) {
		t.Error("a report outside the repository must count")
	}

	t.Cleanup(core.SwapGitShow(nil))
	if _, _, err := s.BaselineAtBase(set, p, "origin/main"); !errors.Is(err, core.ErrNotLinked) {
		t.Errorf("without git show: %v", err)
	}
}
