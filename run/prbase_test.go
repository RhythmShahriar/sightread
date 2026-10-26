// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
	"github.com/RhythmShahriar/sightread/policy"
	"github.com/RhythmShahriar/sightread/run"
	"github.com/RhythmShahriar/sightread/run/runtest"
)

// prPolicy is the fake policy with the pull request rules the real one
// adds (policy.Store.ConfigAtBase and BaselineAtBase). Its ConfigAtBase
// drops ignore entries the base config lacks, as the real one does.
type prPolicy struct {
	*coretest.FakePolicy
	path         string // the config path LoadConfig returns
	baseIgnore   []string
	baseBaseline map[string]bool
	gotPath      string
	gotRef       string
}

func (p *prPolicy) LoadConfig(start, explicit string, none bool) (*core.Config, string, error) {
	c, _, err := p.FakePolicy.LoadConfig(start, explicit, none)
	return c, p.path, err
}

func (p *prPolicy) ConfigAtBase(cfg *core.Config, path, ref string) ([]string, error) {
	p.gotPath, p.gotRef = path, ref
	var kept []core.IgnoreEntry
	var notes []string
	for _, e := range cfg.Ignore {
		if slices.Contains(p.baseIgnore, e.ID) {
			kept = append(kept, e)
			continue
		}
		notes = append(notes, "ignore "+e.ID+": relaxed in this change, not counted (--trust-pr-allow counts it)")
	}
	cfg.Ignore = kept
	return notes, nil
}

func (p *prPolicy) BaselineAtBase(set map[string]bool, _, _ string) (map[string]bool, int, error) {
	kept := map[string]bool{}
	for fp := range set {
		if p.baseBaseline[fp] {
			kept[fp] = true
		}
	}
	return kept, len(set) - len(kept), nil
}

// ignoreScorer is the fake scorer plus config ignore entries, so a test
// can see whether an ignore entry hid a finding.
type ignoreScorer struct{ coretest.FakeScorer }

func (s ignoreScorer) Score(ctx context.Context, u *core.Update, cfg *core.Config, allow core.AllowSet, baseline map[string]bool) {
	for i := range u.Findings {
		u.Findings[i].Ignored = slices.ContainsFunc(cfg.Ignore, func(e core.IgnoreEntry) bool { return e.ID == u.Findings[i].ID })
	}
	s.FakeScorer.Score(ctx, u, cfg, allow, baseline)
}

// gitShow serves files at one ref from a map and records each read.
type gitShow struct {
	ref   string
	files map[string]string
	reads []string
}

func (g *gitShow) show(_ context.Context, _, ref, path string) ([]byte, error) {
	g.reads = append(g.reads, ref+":"+path)
	if s, ok := g.files[path]; ok && ref == g.ref {
		return []byte(s), nil
	}
	return nil, fmt.Errorf("fatal: path '%s' does not exist in '%s'", path, ref)
}

// prWorld is a changes run with one added npm package that has a
// medium finding, a config in the working tree and one at the base.
func prWorld(t *testing.T, head *core.Config, base string) (*runtest.World, *prPolicy, *gitShow, run.Request) {
	t.Helper()
	w := runtest.Install(t)
	w.Publish(core.NPM, "plain-crypto-js", "4.2.1")
	w.Inventory.Bumps = []core.Bump{{To: core.Installed{Ref: core.Ref{Eco: core.NPM, Name: "plain-crypto-js", Version: "4.2.1"}}}}
	w.Detector.Set("plain-crypto-js", "npm-install-script-new")
	repo := t.TempDir()
	w.Policy.Config = head
	p := &prPolicy{FakePolicy: w.Policy, path: filepath.Join(repo, ".sightread", "config.yaml")}
	t.Cleanup(core.SwapPolicy(p))
	t.Cleanup(core.SwapScorer(ignoreScorer{}))
	g := &gitShow{ref: "main", files: map[string]string{}}
	if base != "" {
		g.files[".sightread/config.yaml"] = base
	}
	t.Cleanup(core.SwapGitShow(g.show))
	req := request(t, "changes")
	req.ConfigStart = repo
	req.Changes = &core.ChangesRequest{Repo: repo, Base: "main"}
	return w, p, g, req
}

// weakHead relaxes every key the pull request rule covers.
func weakHead() *core.Config {
	off := false
	return &core.Config{
		Ignore:      []core.IgnoreEntry{{ID: "npm-install-script-new", Reason: "trust me"}},
		OSV:         &off,
		Sources:     core.SourcesConfig{NPM: core.NPMSourceConfig{Registry: "https://mirror.example"}},
		LocalFiles:  map[string]string{"premium": "vendor/premium-{version}.zip"},
		TrustedKeys: []string{"new-key"},
		Ecosystems:  []core.Ecosystem{core.WPPlugin},
		MinAge:      "1h",
	}
}

const relaxed = ": relaxed in this change, not counted (--trust-pr-allow counts it)"

// TestPRConfigNotCounted: a pull request that adds an ignore entry,
// turns OSV off, moves sources, adds local files or a trusted key,
// narrows ecosystems or shortens min_age doesn't weaken the review of
// its own update. The finding stays counted and each key gets a note.
func TestPRConfigNotCounted(t *testing.T) {
	_, p, g, req := prWorld(t, weakHead(), "trusted_keys: [old-key]\nmin_age: 72h\n")
	rep := review(t, req)
	if got := names(rep); !reflect.DeepEqual(got, []string{"plain-crypto-js →4.2.1 review"}) {
		t.Fatalf("updates %q: the PR's ignore entry hid the finding", got)
	}
	want := []string{
		"ignore npm-install-script-new" + relaxed,
		"osv false" + relaxed,
		"sources" + relaxed,
		"local_files" + relaxed,
		`trusted_keys "new-key"` + relaxed,
		"ecosystems" + relaxed,
		"min_age 72h" + relaxed,
	}
	for _, n := range want {
		if !slices.Contains(rep.Notes, n) {
			t.Errorf("no note %q in %q", n, rep.Notes)
		}
	}
	if p.gotRef != "main" || p.gotPath != p.path {
		t.Errorf("ConfigAtBase(%q, %q)", p.gotPath, p.gotRef)
	}
	if !reflect.DeepEqual(g.reads, []string{"main:.sightread/config.yaml"}) {
		t.Errorf("git show reads %q", g.reads)
	}
}

// TestPRConfigStricter: a change that only tightens the config applies
// in full and leaves no note.
func TestPRConfigStricter(t *testing.T) {
	on := true
	head := &core.Config{OSV: &on, TrustedKeys: []string{"a"}, MinAge: "7d",
		Ecosystems: []core.Ecosystem{core.NPM, core.WPPlugin}}
	_, _, _, req := prWorld(t, head, "trusted_keys: [a, b]\nmin_age: 72h\necosystems: [npm]\n")
	rep := review(t, req)
	for _, n := range rep.Notes {
		if strings.HasSuffix(n, relaxed) {
			t.Errorf("stricter config noted %q", n)
		}
	}
}

// TestPRConfigTrusted: with --trust-pr-allow, or with --before/--after
// (no git), the working tree config counts and nothing is read at a ref.
func TestPRConfigTrusted(t *testing.T) {
	for _, c := range []struct {
		name string
		edit func(*run.Request)
	}{
		{"trust-pr-allow", func(q *run.Request) { q.TrustPRAllow = true }},
		{"before-after", func(q *run.Request) { q.Changes = &core.ChangesRequest{Before: "a.json", After: "b.json"} }},
		{"no-config", func(q *run.Request) { q.NoConfig = true }},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, p, g, req := prWorld(t, weakHead(), "")
			c.edit(&req)
			rep := review(t, req)
			// The fake LoadConfig returns the config even with
			// --no-config, so the ignore entry applies in every case.
			if got := names(rep); !reflect.DeepEqual(got, []string{"plain-crypto-js →4.2.1 routine"}) {
				t.Errorf("updates %q", got)
			}
			if len(g.reads) != 0 || p.gotRef != "" {
				t.Errorf("read at a ref: %q %q", g.reads, p.gotRef)
			}
		})
	}
}

// TestPRConfigBaseMissing: a config the base can't show counts as
// empty, so everything the change adds is not counted; a config the
// change deleted is still looked for at the base.
func TestPRConfigBaseMissing(t *testing.T) {
	_, _, _, req := prWorld(t, weakHead(), "")
	rep := review(t, req)
	if !slices.Contains(rep.Notes, "osv false"+relaxed) {
		t.Errorf("notes %q", rep.Notes)
	}

	_, p, g, req := prWorld(t, nil, "fail_on: high\n")
	p.path = "" // no config in the working tree
	review(t, req)
	if want := filepath.Join(req.ConfigStart, ".sightread", "config.yaml"); p.gotPath != want {
		t.Errorf("ConfigAtBase path %q, want %q", p.gotPath, want)
	}
	if !reflect.DeepEqual(g.reads, []string{"main:.sightread/config.yaml"}) {
		t.Errorf("git show reads %q", g.reads)
	}
}

// TestPRConfigOutsideRepo: a --config file outside the repository is
// not part of the change, so it counts as written.
func TestPRConfigOutsideRepo(t *testing.T) {
	_, p, g, req := prWorld(t, weakHead(), "")
	p.path = filepath.Join(t.TempDir(), "ci.yaml")
	rep := review(t, req)
	if slices.Contains(rep.Notes, "osv false"+relaxed) || len(g.reads) != 0 {
		t.Errorf("outside config read at base: notes %q reads %q", rep.Notes, g.reads)
	}
}

// TestPRBaselineNotCounted: fingerprints the change added to a
// committed baseline don't hide findings.
func TestPRBaselineNotCounted(t *testing.T) {
	w, p, _, req := prWorld(t, nil, "")
	fp := core.Fingerprint(core.NPM, "plain-crypto-js", "4.2.1", "npm-install-script-new", "main.php", core.NewSnippet("npm-install-script-new"))
	w.Policy.Baselines = map[string]map[string]bool{"base.json": {fp: true}}
	req.Baseline = "base.json"
	rep := review(t, req)
	if got := names(rep); !reflect.DeepEqual(got, []string{"plain-crypto-js →4.2.1 review"}) {
		t.Errorf("updates %q: the PR's baseline hid the finding", got)
	}
	if want := "--baseline: 1 finding saved in this change, not counted (--trust-pr-allow counts them)"; !slices.Contains(rep.Notes, want) {
		t.Errorf("notes %q", rep.Notes)
	}

	p.baseBaseline = map[string]bool{fp: true}
	rep = review(t, req)
	if got := names(rep); !reflect.DeepEqual(got, []string{"plain-crypto-js →4.2.1 routine"}) {
		t.Errorf("updates %q: a base baseline entry must count", got)
	}
}

// TestPRRuleNotLinked: a policy without the pull request rule stops the
// run instead of counting the change's own config.
func TestPRRuleNotLinked(t *testing.T) {
	w, _, _, req := prWorld(t, nil, "")
	w.Policy.Install(t) // the plain fake has no ConfigAtBase
	_, err := run.Review(context.Background(), req)
	if !errors.Is(err, core.ErrNotLinked) {
		t.Fatalf("err %v, want ErrNotLinked", err)
	}
}

// TestPRConfigLinkedPolicy is TestPRConfigNotCounted with the real
// policy reading a real config file: the change's ignore entry, OSV off,
// mirror and shorter min_age don't count; the base's values come back.
func TestPRConfigLinkedPolicy(t *testing.T) {
	_, _, g, req := prWorld(t, nil, "min_age: 72h\n")
	repo := req.Changes.Repo
	head := "ignore:\n  - id: npm-install-script-new\n    reason: trust me\nosv: false\n" +
		"sources:\n  npm:\n    registry: https://mirror.example\nmin_age: 1h\n"
	for _, dir := range []string{".git", ".sightread"} {
		if err := os.MkdirAll(filepath.Join(repo, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, ".sightread", "config.yaml"), []byte(head), 0o600); err != nil {
		t.Fatal(err)
	}
	store := policy.New()
	store.Stderr = io.Discard
	t.Cleanup(core.SwapPolicy(store))
	rep := review(t, req)
	if got := names(rep); !reflect.DeepEqual(got, []string{"plain-crypto-js →4.2.1 review"}) {
		t.Fatalf("updates %q: the PR's ignore entry hid the finding", got)
	}
	for _, key := range []string{"ignore npm-install-script-new", "osv", "sources", "min_age"} {
		if !slices.ContainsFunc(rep.Notes, func(n string) bool { return strings.HasPrefix(n, key) && strings.HasSuffix(n, relaxed) }) {
			t.Errorf("no %q note in %q", key, rep.Notes)
		}
	}
	if !slices.Contains(g.reads, "main:.sightread/config.yaml") {
		t.Errorf("git show reads %q", g.reads)
	}
}

// pathScorer records the config path the run names to the scorer.
type pathScorer struct {
	coretest.FakeScorer
	path *string
}

func (s pathScorer) SetConfigPath(p string) { *s.path = p }

// TestScorerConfigPath: the scorer's notes name the --config file as
// typed, and the usual file (empty) without --config.
func TestScorerConfigPath(t *testing.T) {
	for _, file := range []string{"ci/sightread.yaml", ""} {
		w := runtest.Install(t)
		w.Publish(core.NPM, "a", "1.0.0", "1.1.0")
		w.Install(core.NPM, "a", "1.0.0")
		got := "unset"
		t.Cleanup(core.SwapScorer(pathScorer{path: &got}))
		req := request(t, "npm")
		req.ConfigFile = file
		review(t, req)
		if got != file {
			t.Errorf("--config %q: scorer got %q", file, got)
		}
	}
}
