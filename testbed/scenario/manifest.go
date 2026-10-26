// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package scenario

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Kinds of scenario.
const (
	KindBad  = "bad"
	KindGood = "good"
	KindEnv  = "env"
)

// Manifest is testbed/scenarios.yaml.
type Manifest struct {
	// Scenarios are the bad, good and environment scenarios in order.
	Scenarios []Scenario `yaml:"scenarios"`
}

// Scenario is one entry of the manifest.
type Scenario struct {
	// ID is the short id of PRD 19 (b01, g07, e04).
	ID string `yaml:"id"`
	// Kind is bad, good or env.
	Kind string `yaml:"kind"`
	// Title is the one-line description.
	Title string `yaml:"title"`
	// Package is the scenario's folder under testbed/packages; empty for
	// an environment scenario with no package of its own.
	Package string `yaml:"package,omitempty"`
	// ExtraPackages are the companion folders the registry also serves
	// (a scenario and its typosquat or transitive dependency).
	ExtraPackages []string `yaml:"extra_packages,omitempty"`
	// Command is the arguments after rhythm-sightread.
	Command []string `yaml:"command"`
	// Expect is what a correct review reports (bad), or the signals a
	// good scenario is allowed to report without being a false alarm.
	Expect Expect `yaml:"expect"`
	// Forbid lists signal ids that must never appear.
	Forbid []string `yaml:"forbid,omitempty"`
	// FailOn is the gate for this scenario; the default is medium for a
	// good scenario and high for a bad one.
	FailOn string `yaml:"fail_on,omitempty"`
	// Pending notes a detector or stage that is not merged yet; a pending
	// scenario is shown apart and does not fail the 1.0 gate.
	Pending string `yaml:"pending,omitempty"`
	// Env holds an environment scenario's own assertions, consumed by the
	// probes rather than by the report evaluation.
	Env *EnvAssert `yaml:"env,omitempty"`
}

// Expect is a scenario's expected review.
type Expect struct {
	// Verdict is HOLD, REVIEW, ROUTINE, ALLOWED or UNVERIFIED.
	Verdict string `yaml:"verdict,omitempty"`
	// Exit is the process exit code the bench expects of a bad or good
	// scenario; nil means 0. An environment scenario states its exit
	// under env.exit instead; Load rejects one here.
	Exit *int `yaml:"exit,omitempty"`
	// Signals are the findings that must be present (bad) or are allowed
	// (good), each with a minimum severity.
	Signals []ExpectSignal `yaml:"signals,omitempty"`
	// NotCheckedReasons are the reason codes the report must list under
	// Not checked.
	NotCheckedReasons []string `yaml:"not_checked_reasons,omitempty"`
	// Exact makes a good scenario's Signals the whole answer: each must
	// be present at its minimum severity and any other counted finding,
	// at any severity, is a false alarm (PRD 19: g15 gives owner-change
	// and nothing else).
	Exact bool `yaml:"exact,omitempty"`
}

// ExpectSignal names a signal and the least severe rank that counts.
type ExpectSignal struct {
	ID          string `yaml:"id"`
	MinSeverity string `yaml:"min_severity,omitempty"`
}

// WantExit is the exit code a bad or good scenario expects.
func (e Expect) WantExit() int {
	if e.Exit == nil {
		return 0
	}
	return *e.Exit
}

// EnvAssert is an environment scenario's assertions.
type EnvAssert struct {
	// Exit is the expected process exit code, when the scenario pins one.
	Exit *int `yaml:"exit,omitempty"`
	// Says is text the output must contain (case-insensitive).
	Says []string `yaml:"says,omitempty"`
	// Never is text the output must not contain.
	Never []string `yaml:"never,omitempty"`
	// Note explains what the scenario checks for the reader.
	Note string `yaml:"note,omitempty"`
}

// Load reads and validates a manifest from path.
func Load(path string) (*Manifest, error) {
	b, err := os.ReadFile(path) //nolint:gosec // our own manifest
	if err != nil {
		return nil, err
	}
	var m Manifest
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	seen := map[string]bool{}
	for _, s := range m.Scenarios {
		if s.ID == "" {
			return nil, fmt.Errorf("%s: a scenario is missing its id", path)
		}
		if seen[s.ID] {
			return nil, fmt.Errorf("%s: duplicate scenario id %q", path, s.ID)
		}
		seen[s.ID] = true
		switch s.Kind {
		case KindBad, KindGood, KindEnv:
		default:
			return nil, fmt.Errorf("%s: scenario %s has an unknown kind %q", path, s.ID, s.Kind)
		}
		if err := s.check(); err != nil {
			return nil, fmt.Errorf("%s: scenario %s %w", path, s.ID, err)
		}
	}
	return &m, nil
}

// check rejects expectations the evaluator would ignore or contradict,
// so the manifest never shows a reader an assertion that is not made.
func (s Scenario) check() error {
	if s.Expect.Exact && s.Kind != KindGood {
		return errors.New("sets exact, which only a good scenario uses")
	}
	if s.Expect.Exact && len(s.Expect.Signals) == 0 {
		return errors.New("sets exact with no signals; leave it out to allow none")
	}
	if s.Kind == KindEnv && s.Expect.Exit != nil {
		return errors.New("sets expect.exit; an environment scenario states its exit under env.exit")
	}
	return nil
}

// EffectiveFailOn returns the gate the scenario runs under.
func (s Scenario) EffectiveFailOn() string {
	if s.FailOn != "" {
		return s.FailOn
	}
	if s.Kind == KindGood {
		return "medium"
	}
	return "high"
}

// Packages returns the scenario's package folder and its companions.
func (s Scenario) Packages() []string {
	var out []string
	if s.Package != "" {
		out = append(out, s.Package)
	}
	return append(out, s.ExtraPackages...)
}
