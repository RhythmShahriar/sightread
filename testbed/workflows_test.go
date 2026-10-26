// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package testbed_test

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// actionInputs are the inputs of PRD section 16. action-test.yml may
// only pass these to the Action (uses: ./), so a renamed input fails
// here before it fails in CI.
var actionInputs = []string{
	"mode", "package", "path", "working-directory", "base", "fail-on", "min-confidence",
	"allow-partial", "allow-unverified", "baseline", "trust-pr-allow", "transitive", "sarif",
	"comment", "summary", "upload", "attest", "args", "version", "verify-signature",
	"github-token", "download-url",
}

// actionOutputs are the outputs of PRD section 16.
var actionOutputs = []string{
	"exit-code", "verdict", "updates", "findings", "report", "html", "sarif-file", "summary",
	"comment-id", "version",
}

type workflow struct {
	On          map[string]any    `yaml:"on"`
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		Permissions map[string]string `yaml:"permissions"`
		Steps       []struct {
			ID   string            `yaml:"id"`
			Uses string            `yaml:"uses"`
			With map[string]string `yaml:"with"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

func readWorkflow(t *testing.T, name string) (workflow, []byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", ".github", "workflows", name))
	if err != nil {
		t.Fatal(err)
	}
	var w workflow
	if err := yaml.Unmarshal(raw, &w); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return w, raw
}

// pinned is a uses: line ci-go's pin-check accepts: a full commit SHA
// with the version in a comment.
var pinned = regexp.MustCompile(`^\s*-?\s*uses:\s*[\w.-]+/[\w./-]+@[0-9a-f]{40} # v?\d`)

// TestWorkflowsPinned is the pin-check for this lane's workflows. Every
// token also stays read-only so CI can't commit the benchmark page.
func TestWorkflowsPinned(t *testing.T) {
	for _, name := range []string{"action-test.yml", "nightly.yml"} {
		w, raw := readWorkflow(t, name)
		for i, line := range strings.Split(string(raw), "\n") {
			if !strings.Contains(line, "uses:") || strings.Contains(line, "uses: ./") {
				continue
			}
			if !pinned.MatchString(line) {
				t.Errorf("%s:%d: not pinned to a commit SHA with a version comment: %s", name, i+1, strings.TrimSpace(line))
			}
		}
		perms := []map[string]string{w.Permissions}
		for _, j := range w.Jobs {
			perms = append(perms, j.Permissions)
		}
		for _, p := range perms {
			for scope, level := range p {
				if level != "read" {
					t.Errorf("%s: permission %s: %s; these workflows only read", name, scope, level)
				}
			}
		}
	}
}

func TestPinnedPattern(t *testing.T) {
	for line, want := range map[string]bool{
		"      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1":                   true,
		"        uses: github/codeql-action/upload-sarif@9b3254085494b55a0f7c4c2b3d2d52cc712ce370 # v4.39.1": true,
		"      - uses: actions/checkout@v7":                                       false,
		"      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1": false,
		"      - uses: actions/checkout@3d3c42e # v7.0.1":                         false,
	} {
		if got := pinned.MatchString(line); got != want {
			t.Errorf("pinned(%q) = %v, want %v", line, got, want)
		}
	}
}

// outputRef finds steps.<id>.outputs.<name> in a workflow.
var outputRef = regexp.MustCompile(`steps\.([\w-]+)\.outputs\.([\w-]+)`)

// TestActionTestUsesPRDInputs checks the Action steps of action-test.yml
// against PRD 16: only its inputs, only its outputs read back, the four
// jobs of the lane spec.
func TestActionTestUsesPRDInputs(t *testing.T) {
	w, raw := readWorkflow(t, "action-test.yml")
	for _, job := range []string{"changes", "pr-allow", "tampered-release", "comment-read-only"} {
		if _, ok := w.Jobs[job]; !ok {
			t.Errorf("action-test.yml has no job %s", job)
		}
	}
	actionSteps := map[string]bool{}
	n := 0
	for name, j := range w.Jobs {
		for _, s := range j.Steps {
			if s.Uses != "./" {
				continue
			}
			n++
			actionSteps[s.ID] = true
			for k := range s.With {
				if !slices.Contains(actionInputs, k) {
					t.Errorf("job %s step %s passes %s, which PRD 16 doesn't define", name, s.ID, k)
				}
			}
		}
	}
	if n < 8 {
		t.Errorf("only %d steps run the Action", n)
	}
	for _, m := range outputRef.FindAllStringSubmatch(string(raw), -1) {
		if actionSteps[m[1]] && !slices.Contains(actionOutputs, m[2]) {
			t.Errorf("step %s reads output %s, which PRD 16 doesn't define", m[1], m[2])
		}
	}
	for _, out := range []string{"exit-code", "verdict", "findings", "report", "sarif-file", "summary", "comment-id"} {
		if !bytes.Contains(raw, []byte("outputs."+out+" }}")) {
			t.Errorf("action-test.yml never checks the %s output", out)
		}
	}
}

// TestActionTestLockfiles keeps the Action test's pull request equal to
// the testbed's b13 pair, whose outcome scenarios.yaml states.
func TestActionTestLockfiles(t *testing.T) {
	for _, side := range []string{"base", "head"} {
		a, err := os.ReadFile(filepath.Join("..", ".github", "action-test", side, "package-lock.json"))
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join("projects", "changes", side, "package-lock.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf(".github/action-test/%s/package-lock.json differs from testbed/projects/changes/%[1]s/package-lock.json", side)
		}
	}
}
