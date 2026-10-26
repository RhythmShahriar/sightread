// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run

import (
	"cmp"
	"context"
	"fmt"
	"maps"
	"path/filepath"
	"reflect"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/RhythmShahriar/rhythm/kit/update"
	"github.com/RhythmShahriar/sightread/core"
)

// notCounted ends every note about a setting the pull request changed
// that doesn't count. It matches the policy's config notes.
const notCounted = ": relaxed in this change, not counted (--trust-pr-allow counts it)"

// configAtBaser is the policy's pull request rule for the config
// (policy.Store.ConfigAtBase): it puts back ignore entries, severities,
// domains_ok, min_confidence, fail_on and the allow files the change
// relaxed. It is not part of core.Policy, so it is asserted.
type configAtBaser interface {
	ConfigAtBase(cfg *core.Config, configPath, baseRef string) ([]string, error)
}

// baselineAtBaser keeps only the --baseline fingerprints the report
// also holds at the base ref (policy.Store.BaselineAtBase).
type baselineAtBaser interface {
	BaselineAtBase(set map[string]bool, path, baseRef string) (map[string]bool, int, error)
}

// prBaseRef is the ref the config, allow entries and baseline count
// from: the base of a `changes` run (and the Action on a pull request),
// so a pull request can't weaken the review of its own update (SR-9).
// It is empty outside changes, with --before/--after (no git) and with
// --trust-pr-allow.
func (r *reviewer) prBaseRef() string {
	c := r.req.Changes
	if c == nil || r.req.TrustPRAllow || c.Before != "" {
		return ""
	}
	return cmp.Or(c.Base, "origin/HEAD")
}

// configAtBase applies the pull request rule to the config just loaded.
// The policy restores what it knows; the keys it leaves alone that can
// still weaken the gate (osv, sources, local_files, trusted_keys,
// ecosystems, min_age) are put back here from the config at baseRef.
// A missing policy rule or git show fails the run: going on would let
// the change count its own config.
func (r *reviewer) configAtBase(policy core.Policy, baseRef, start string) error {
	if r.req.NoConfig {
		return nil
	}
	cb, ok := policy.(configAtBaser)
	if !ok {
		return fmt.Errorf("the config pull request rule (policy) %w", core.ErrNotLinked)
	}
	path := r.cfgPath
	if path == "" && r.req.ConfigFile == "" {
		// The change may have deleted the config: look for the default
		// one at the base, where it still applies.
		abs, err := filepath.Abs(start)
		if err != nil {
			return err
		}
		path = filepath.Join(abs, ".sightread", "config.yaml")
	}
	notes, err := cb.ConfigAtBase(r.cfg, path, baseRef)
	if err != nil {
		return err
	}
	base, err := r.baseConfig(path, baseRef)
	if err != nil {
		return err
	}
	if base != nil {
		notes = append(notes, keepBase(r.cfg, base)...)
	}
	for _, n := range notes {
		r.note(n)
	}
	return nil
}

// baselineAtBase drops the --baseline fingerprints the change itself
// saved, so a pull request can't hide its own findings by adding them
// to a committed baseline.
func (r *reviewer) baselineAtBase(policy core.Policy, baseRef string) error {
	bb, ok := policy.(baselineAtBaser)
	if !ok {
		return fmt.Errorf("the baseline pull request rule (policy) %w", core.ErrNotLinked)
	}
	set, dropped, err := bb.BaselineAtBase(r.baseline, r.req.Baseline, baseRef)
	if err != nil {
		return err
	}
	r.baseline = set
	if dropped > 0 {
		noun := "findings"
		if dropped == 1 {
			noun = "finding"
		}
		r.note(fmt.Sprintf("--baseline: %d %s saved in this change, not counted (--trust-pr-allow counts them)", dropped, noun))
	}
	return nil
}

// baseConfig reads the config file at baseRef. It returns nil for a
// file outside the repository, which the change can't touch, and an
// empty config for one the ref can't show or parse, so nothing the
// change adds counts.
func (r *reviewer) baseConfig(path, baseRef string) (*core.Config, error) {
	show := core.GetGitShow()
	if show == nil {
		return nil, fmt.Errorf("reading the config at %s: git show %w", baseRef, core.ErrNotLinked)
	}
	repo, err := filepath.Abs(cmp.Or(r.req.Changes.Repo, "."))
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	rel, err := filepath.Rel(repo, abs)
	if err != nil || !filepath.IsLocal(rel) {
		return nil, nil
	}
	// gitref caps git show at 60s; setup has no context of its own.
	b, err := show(context.Background(), repo, baseRef, filepath.ToSlash(rel))
	c := &core.Config{}
	if err != nil {
		r.logf("config at %s: %v", baseRef, err)
		return c, nil
	}
	if err := yaml.Unmarshal(b, c); err != nil {
		r.logf("config at %s: %v", baseRef, err)
		return &core.Config{}, nil
	}
	return c, nil
}

// keepBase puts back the keys the change set differently from base and
// returns one note per key. Only changes that could hide a finding or
// change what is fetched count: turning OSV back on, dropping a trusted
// key or adding an ecosystem is stricter and applies.
func keepBase(cfg, base *core.Config) []string {
	var notes []string
	if cfg.OSV != nil && !*cfg.OSV && (base.OSV == nil || *base.OSV) {
		cfg.OSV = base.OSV
		notes = append(notes, "osv false"+notCounted)
	}
	if !reflect.DeepEqual(cfg.Sources, base.Sources) {
		cfg.Sources = base.Sources
		notes = append(notes, "sources"+notCounted)
	}
	if !maps.Equal(cfg.LocalFiles, base.LocalFiles) {
		cfg.LocalFiles = base.LocalFiles
		notes = append(notes, "local_files"+notCounted)
	}
	var keys []string
	for _, k := range cfg.TrustedKeys {
		if slices.Contains(base.TrustedKeys, k) {
			keys = append(keys, k)
			continue
		}
		notes = append(notes, fmt.Sprintf("trusted_keys %q%s", short(k), notCounted))
	}
	cfg.TrustedKeys = keys
	// An empty list reviews every ecosystem; a list leaving out one the
	// base reviews hides that ecosystem's updates.
	if len(cfg.Ecosystems) > 0 && (len(base.Ecosystems) == 0 ||
		slices.ContainsFunc(base.Ecosystems, func(e core.Ecosystem) bool { return !slices.Contains(cfg.Ecosystems, e) })) {
		cfg.Ecosystems = base.Ecosystems
		notes = append(notes, "ecosystems"+notCounted)
	}
	if shorterAge(cfg.MinAge, base.MinAge) {
		cfg.MinAge = base.MinAge
		notes = append(notes, "min_age "+cmp.Or(cfg.MinAge, DefaultMinAge)+notCounted)
	}
	return notes
}

// shorterAge reports whether min_age a is shorter than b, each empty
// meaning DefaultMinAge. A value that doesn't parse counts as shorter,
// so a broken value in the change never wins.
func shorterAge(a, b string) bool {
	if a == "" || a == b {
		return false
	}
	da, err := update.ParseAge(a)
	if err != nil {
		return true
	}
	db, err := update.ParseAge(cmp.Or(b, DefaultMinAge))
	return err == nil && da < db
}

// short keeps a note about a long key (a whole PEM block) readable.
func short(k string) string {
	k = strings.TrimSpace(k)
	if len(k) > 24 {
		return k[:24] + "..."
	}
	return k
}
