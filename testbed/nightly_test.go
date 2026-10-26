// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package testbed_test

import (
	"bytes"
	"testing"
)

// TestNightly checks the schedule and the three suites of the lane spec.
func TestNightly(t *testing.T) {
	w, raw := readWorkflow(t, "nightly.yml")
	for _, ev := range []string{"schedule", "workflow_dispatch"} {
		if _, ok := w.On[ev]; !ok {
			t.Errorf("nightly.yml doesn't run on %s", ev)
		}
	}
	for _, want := range []string{
		"make fuzz FUZZTIME=10m", "SIGHTREAD_REQUIRE_LINKED", "go test -race ./...",
		"ubuntu-latest, macos-latest, windows-latest", "make -C testbed bench", "make -C testbed reproduce",
		"docs/benchmark.md", "name: fuzz-crashers",
		// The tagged bench tests (canary, egress and the sealed Docker
		// check) and e13 on Windows run nowhere else.
		"make -C testbed test-bench", "runs-on: windows-latest", "-only e13", "-plain-http",
	} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Errorf("nightly.yml lacks %q", want)
		}
	}
	if bytes.Contains(raw, []byte("git push")) || bytes.Contains(raw, []byte("git commit")) {
		t.Error("nightly.yml commits; the benchmark page is an artifact only")
	}
}
