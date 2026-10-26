// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// actionFile is the repository's action.yml, from this package's folder.
var actionFile = filepath.Join("..", "..", "action.yml")

// TestActionInputsAndOutputs holds action.yml to PRD 16: every input with
// its default and every output, nothing more.
func TestActionInputsAndOutputs(t *testing.T) {
	b, err := os.ReadFile(actionFile)
	if err != nil {
		t.Fatal(err)
	}
	var a struct {
		Inputs map[string]struct {
			Default string `yaml:"default"`
		} `yaml:"inputs"`
		Outputs map[string]struct {
			Value string `yaml:"value"`
		} `yaml:"outputs"`
		Runs struct {
			Using string `yaml:"using"`
		} `yaml:"runs"`
	}
	if err := yaml.Unmarshal(b, &a); err != nil {
		t.Fatal(err)
	}
	inputs := map[string]string{
		"mode": "", "package": "", "path": ".", "working-directory": ".", "base": "", "fail-on": "high", "min-confidence": "",
		"allow-partial": "false", "allow-unverified": "false", "baseline": "", "trust-pr-allow": "false", "transitive": "false",
		"sarif": "false", "comment": "false", "summary": "true", "upload": "true", "attest": "false", "args": "", "version": "",
		"verify-signature": "true", "github-token": "${{ github.token }}", "download-url": "",
	}
	for name, def := range inputs {
		in, ok := a.Inputs[name]
		if !ok {
			t.Errorf("input %s is missing", name)
			continue
		}
		if in.Default != def {
			t.Errorf("input %s defaults to %q, want %q", name, in.Default, def)
		}
	}
	for name := range a.Inputs {
		if _, ok := inputs[name]; !ok {
			t.Errorf("input %s is not in PRD 16", name)
		}
	}
	outputs := []string{"exit-code", "verdict", "updates", "findings", "report", "html", "sarif-file", "summary", "comment-id", "version"}
	var got []string
	for name, o := range a.Outputs {
		got = append(got, name)
		if !strings.HasPrefix(o.Value, "${{ steps.") {
			t.Errorf("output %s = %q", name, o.Value)
		}
	}
	slices.Sort(got)
	slices.Sort(outputs)
	if !slices.Equal(got, outputs) {
		t.Errorf("outputs %q, want %q", got, outputs)
	}
	if a.Runs.Using != "composite" {
		t.Errorf("runs.using %q", a.Runs.Using)
	}
}

// usesLine is a step's uses: line.
var usesLine = regexp.MustCompile(`(?m)^\s*(?:-\s+)?uses:\s*(\S+)(.*)$`)

// pinned is owner/repo[/path]@<40 hex> followed by a "# vX.Y.Z" comment.
var pinned = regexp.MustCompile(`^[\w.-]+/[\w.-]+(?:/[\w./-]+)?@[0-9a-f]{40}$`)

// TestActionPins: every action the composite runs is pinned by commit
// with its version in a comment, as the pin check wants; a tag alone is
// refused.
func TestActionPins(t *testing.T) {
	b, err := os.ReadFile(actionFile)
	if err != nil {
		t.Fatal(err)
	}
	m := usesLine.FindAllStringSubmatch(string(b), -1)
	if len(m) < 5 {
		t.Fatalf("found %d uses: lines", len(m))
	}
	for _, u := range m {
		if !pinned.MatchString(u[1]) || !regexp.MustCompile(`^\s+# v\d+\.\d+\.\d+$`).MatchString(u[2]) {
			t.Errorf("not pinned by commit with its version: %s%s", u[1], u[2])
		}
	}
	for _, bad := range []string{"actions/checkout@v4", "actions/cache@v6.1.0 # v6.1.0", "x/y@1234"} {
		if pinned.MatchString(strings.Fields(bad)[0]) {
			t.Errorf("%s counts as pinned", bad)
		}
	}
}

// TestActionScriptsExist: every script action.yml calls is in scripts/
// and executable.
func TestActionScriptsExist(t *testing.T) {
	b, err := os.ReadFile(actionFile)
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`\$GITHUB_ACTION_PATH/(scripts/[\w.-]+)`).FindAllStringSubmatch(string(b), -1)
	if len(m) < 3 {
		t.Fatalf("found %d scripts", len(m))
	}
	for _, s := range m {
		fi, err := os.Stat(filepath.Join("..", "..", s[1]))
		if err != nil {
			t.Error(err)
			continue
		}
		if filepath.Separator == '/' && fi.Mode()&0o111 == 0 {
			t.Errorf("%s is not executable", s[1])
		}
	}
}
