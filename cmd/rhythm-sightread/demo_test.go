// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
	"github.com/RhythmShahriar/sightread/demo"
)

// demoPort pins the demo server to a port of this lane's range.
func demoPort(t *testing.T) {
	t.Helper()
	old := demoAddr
	demoAddr = fmt.Sprintf("127.0.0.1:%d", freeLanePort(t))
	t.Cleanup(func() { demoAddr = old })
}

// endLines are the two lines PRD 6.9 ends the demo with.
const endLines = "\n→ on your site: rhythm-sightread all /path/to/wordpress\n→ in CI: rhythm-sightread init ci\n"

// TestDemoFlow runs the demo against the fakes: exit 0, the report and
// the end lines, no file left behind without --keep and the archives
// kept with it.
func TestDemoFlow(t *testing.T) {
	w := world(t)
	demoPort(t)
	for _, p := range demo.Packages() {
		if p.Old == nil {
			continue
		}
		w.Publish(p.Eco, p.Name, p.Old.Version, p.New.Version)
		w.Install(p.Eco, p.Name, p.Old.Version)
	}
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	t.Setenv("SIGHTREAD_NPM_EXTRA_KEYS", "")
	code, out, errOut := execute(t, "demo")
	if code != cli.ExitOK || out != "fake terminal: 3 updates\n"+endLines || errOut != "" {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errOut)
	}
	if entries, _ := os.ReadDir(tmp); len(entries) != 0 {
		t.Errorf("demo left %d entries in the temp folder", len(entries))
	}
	if v := os.Getenv("SIGHTREAD_NPM_EXTRA_KEYS"); v != "" {
		t.Errorf("SIGHTREAD_NPM_EXTRA_KEYS left set to %q", v)
	}

	// -o writes the report as a review does; --open needs an HTML one.
	md := filepath.Join(t.TempDir(), "demo.md")
	if code, _, errOut := execute(t, "demo", "-o", md); code != cli.ExitOK {
		t.Fatalf("-o: exit %d %q", code, errOut)
	}
	if b, err := os.ReadFile(md); err != nil || len(b) == 0 {
		t.Errorf("-o wrote %q %v", b, err)
	}
	if code, _, errOut := execute(t, "demo", "--open"); code != cli.ExitUsage || !strings.Contains(errOut, "--open opens the HTML report") {
		t.Errorf("--open alone: exit %d %q", code, errOut)
	}
	if code, _, errOut := execute(t, "demo", "-o", "demo.txt"); code != cli.ExitUsage || !strings.Contains(errOut, `-o "demo.txt"`) {
		t.Errorf("-o demo.txt: exit %d %q", code, errOut)
	}

	code, _, errOut = execute(t, "demo", "--keep")
	kept, ok := strings.CutPrefix(strings.TrimSpace(errOut), "kept the demo archives, cache and site in ")
	if code != cli.ExitOK || !ok {
		t.Fatalf("--keep: exit %d stderr %q", code, errOut)
	}
	archives, _ := os.ReadDir(filepath.Join(kept, "archives"))
	if len(archives) != 7 {
		t.Errorf("kept %d archives, want 7", len(archives))
	}
	for _, sub := range []string{"site", "npm-keys.json"} {
		if _, err := os.Stat(filepath.Join(kept, sub)); err != nil {
			t.Errorf("--keep lost %s: %v", sub, err)
		}
	}
}

// TestDemoIntegrated runs the real pipeline against the demo server:
// one ROUTINE and two HOLDs, in under 3 seconds, with nothing sent off
// the machine (runDemo fails if anything tried). It needs every stage,
// so it runs once the lanes are linked.
func TestDemoIntegrated(t *testing.T) {
	for _, eco := range []core.Ecosystem{core.WPPlugin, core.NPM} {
		coretest.NeedSource(t, eco)
	}
	coretest.NeedInventory(t)
	coretest.NeedAnalyzer(t)
	coretest.NeedDetectors(t)
	coretest.NeedScorer(t)
	coretest.NeedWriter(t, core.FormatTerminal)
	demoPort(t)
	t.Setenv("TMPDIR", t.TempDir())
	t.Setenv("RHYTHM_CONFIG_DIR", t.TempDir())
	start := time.Now()
	code, out, errOut := execute(t, "demo", "--plain")
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("the demo took %v, over 3s", took)
	}
	if code != cli.ExitOK || !strings.HasSuffix(out, endLines) {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
	// The update table lists the worst first: one row per package.
	got := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^\s*(HOLD|REVIEW|ROUTINE|ALLOWED)\s+(\S+)\s+\d`).FindAllStringSubmatch(out, -1) {
		got[m[2]] = m[1]
	}
	want := map[string]string{"comment-guard": "ROUTINE", "share-kit": "HOLD", "date-utils-lite": "HOLD"}
	if !maps.Equal(got, want) {
		t.Errorf("verdicts %v, want %v:\n%s", got, want, out)
	}
}
