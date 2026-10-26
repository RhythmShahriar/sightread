// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package testbed_test

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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
		"docs/benchmark.md", "name: fuzz-crashers-",
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

// TestNightlyFuzzFits: the fuzz shards finish inside their timeout with
// every target the repository has, so a timeout never cancels the job
// before the crasher upload runs.
func TestNightlyFuzzFits(t *testing.T) {
	_, raw := readWorkflow(t, "nightly.yml")
	var job struct {
		Jobs struct {
			Fuzz struct {
				Timeout  int `yaml:"timeout-minutes"`
				Strategy struct {
					Matrix struct {
						Shard []int `yaml:"shard"`
					} `yaml:"matrix"`
				} `yaml:"strategy"`
			} `yaml:"fuzz"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &job); err != nil {
		t.Fatal(err)
	}
	shards := len(job.Jobs.Fuzz.Strategy.Matrix.Shard)
	if shards == 0 || !bytes.Contains(raw, []byte("SHARDS="+strconv.Itoa(shards))) {
		t.Fatalf("the fuzz matrix has %d shards and make fuzz doesn't get SHARDS=%d", shards, shards)
	}
	targets := 0
	err := filepath.WalkDir("..", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "testdata" || d.Name() == "packages" || d.Name() == "projects") {
			return filepath.SkipDir
		}
		if strings.HasSuffix(p, "_test.go") {
			b, err := os.ReadFile(p) //nolint:gosec // a file of this repository
			if err != nil {
				return err
			}
			targets += len(fuzzFunc.FindAll(b, -1))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Ten minutes a target plus a minute to build each, with 20 spare.
	perShard := (targets + shards - 1) / shards
	if need := perShard*11 + 20; job.Jobs.Fuzz.Timeout < need || job.Jobs.Fuzz.Timeout > 350 {
		t.Errorf("%d fuzz targets over %d shards need about %d minutes each; timeout-minutes is %d", targets, shards, need, job.Jobs.Fuzz.Timeout)
	}
}

// fuzzFunc matches a fuzz target's declaration.
var fuzzFunc = regexp.MustCompile(`(?m)^func Fuzz\w+\(\w+ \*testing\.F\)`)
