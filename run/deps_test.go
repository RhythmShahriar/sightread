// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run_test

import (
	"context"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
	"github.com/RhythmShahriar/sightread/run/runtest"
)

// TestNewDependencyInfo: a dependency new in the candidate is looked up
// (version within its range, age, install script, popularity); one the
// old version had is not.
func TestNewDependencyInfo(t *testing.T) {
	w := runtest.Install(t)
	published := time.Date(2026, 3, 31, 1, 0, 0, 0, time.UTC)
	w.Publish(core.NPM, "axios", "1.14.0", "1.14.1")
	w.Publish(core.NPM, "plain-crypto-js", "4.2.0", "4.2.1", "5.0.0")
	w.Publish(core.NPM, "follow-redirects", "1.15.0")
	src := w.Sources[core.NPM]
	src.Metas[core.Ref{Eco: core.NPM, Name: "axios", Version: "1.14.0"}] = &core.Meta{Deps: map[string]string{"follow-redirects": "^1.15.0"}}
	src.Metas[core.Ref{Eco: core.NPM, Name: "axios", Version: "1.14.1"}] = &core.Meta{Deps: map[string]string{
		"follow-redirects": "^1.15.0", "plain-crypto-js": "^4.2.0"}}
	src.Metas[core.Ref{Eco: core.NPM, Name: "plain-crypto-js", Version: "4.2.1"}] = &core.Meta{Published: published, HasInstallScript: true}
	w.Install(core.NPM, "axios", "1.14.0")
	req := request(t, "npm")
	req.Eco = core.NPM
	review(t, req)
	s := w.Detector.Subjects()
	if len(s) != 1 {
		t.Fatalf("%d subjects", len(s))
	}
	info := s[0].New.DepInfo
	if len(info) != 1 || info["plain-crypto-js"] == nil {
		t.Fatalf("dep info %+v", info)
	}
	if d := info["plain-crypto-js"]; d.Version != "4.2.1" || !d.Published.Equal(published) || !d.HasInstallScript || d.Popular {
		t.Errorf("plain-crypto-js %+v", d)
	}
	if h := s[0].New.History; len(h) != 1 || h[0].Version != "1.14.0" {
		t.Errorf("history %+v", h)
	}
}

// TestNearPopularMaintainers: a new dependency one edit from a popular
// name carries its maintainers, and the popular package's maintainers
// are looked up beside it; a new dependency near nothing popular looks
// up nothing more.
func TestNearPopularMaintainers(t *testing.T) {
	w := runtest.Install(t)
	ann := []core.Person{{Name: "ann", Login: "ann"}}
	w.Publish(core.NPM, "app", "1.0.0", "1.1.0")
	w.Publish(core.NPM, "axiox", "1.0.0")
	w.Publish(core.NPM, "axios", "1.7.0")
	w.Publish(core.NPM, "zzz-unique", "1.0.0")
	src := w.Sources[core.NPM]
	src.Metas[core.Ref{Eco: core.NPM, Name: "app", Version: "1.1.0"}] = &core.Meta{Deps: map[string]string{"axiox": "^1.0.0"},
		DevDeps: map[string]string{"zzz-unique": "^1.0.0"}}
	src.Metas[core.Ref{Eco: core.NPM, Name: "axiox", Version: "1.0.0"}] = &core.Meta{Maintainers: ann}
	src.Metas[core.Ref{Eco: core.NPM, Name: "axios", Version: "1.7.0"}] = &core.Meta{Maintainers: ann}
	src.Metas[core.Ref{Eco: core.NPM, Name: "zzz-unique", Version: "1.0.0"}] = &core.Meta{Maintainers: ann}
	w.Install(core.NPM, "app", "1.0.0")
	req := request(t, "npm")
	req.Eco = core.NPM
	review(t, req)
	info := w.Detector.Subjects()[0].New.DepInfo
	if d := info["axiox"]; d == nil || len(d.Maintainers) != 1 || d.Popular {
		t.Errorf("axiox %+v", d)
	}
	if d := info["axios"]; d == nil || !d.Popular || len(d.Maintainers) != 1 || d.Version != "1.7.0" {
		t.Errorf("axios %+v", d)
	}
	if d := info["zzz-unique"]; d == nil || len(info) != 3 {
		t.Errorf("dev dependency or extra lookups: %+v", info)
	}
}

// TestGitTagBudget: the tag check runs only for an update that already
// has owner-change, npm-install-script-new or provenance-dropped;
// its git-tag-missing finding is added.
func TestGitTagBudget(t *testing.T) {
	for _, c := range []struct {
		ids     []string
		checked bool
	}{{[]string{"outbound-new-domain"}, false}, {[]string{"owner-change"}, true}, {[]string{"provenance-dropped"}, true}} {
		w := runtest.Install(t)
		w.Publish(core.NPM, "pkg", "1.0.0", "1.1.0")
		w.Sources[core.NPM].Metas[core.Ref{Eco: core.NPM, Name: "pkg", Version: "1.1.0"}] = &core.Meta{Repository: "https://github.com/acme/pkg"}
		w.Install(core.NPM, "pkg", "1.0.0")
		tags := &tagChecker{}
		t.Cleanup(core.SwapTagChecker(func(*core.Env) core.TagChecker { return tags }))
		w.Detector.Set("pkg", c.ids...)
		gitTag := &gitTagDetector{}
		t.Cleanup(core.SwapDetectors(w.Detector, gitTag))
		req := request(t, "npm")
		req.Eco = core.NPM
		rep := review(t, req)
		if tags.calls != map[bool]int{false: 0, true: 1}[c.checked] {
			t.Errorf("%v: %d tag checks", c.ids, tags.calls)
		}
		has := false
		for _, f := range rep.Updates[0].Findings {
			has = has || f.ID == "git-tag-missing"
		}
		if has != c.checked {
			t.Errorf("%v: git-tag-missing %v", c.ids, has)
		}
	}
}

type tagChecker struct{ calls int }

func (c *tagChecker) TagExists(context.Context, string, string, string) (bool, error) {
	c.calls++
	return false, nil
}

// gitTagDetector emits git-tag-missing when the run filled GitTag false.
type gitTagDetector struct{}

func (gitTagDetector) Info() core.DetectorInfo {
	return core.DetectorInfo{Name: "git-tag", Signals: []string{"git-tag-missing"}}
}

func (gitTagDetector) Detect(_ context.Context, s *core.Subject, emit func(core.Finding)) {
	if s.New.GitTag != nil && !*s.New.GitTag {
		emit(core.Finding{ID: "git-tag-missing", Evidence: core.NewSnippet("no tag v1.1.0")})
	}
}

// planGetter records the api.github.com plan run hands the Getter.
type planGetter struct {
	*coretest.FakeGetter
	mu    sync.Mutex
	plans []int
}

func (g *planGetter) ExpectGitHub(n int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.plans = append(g.plans, n)
}

// TestGitHubPlan: Composer updates (both sides may be GitHub zipballs)
// and each git tag check are added to the plan; an update that needs
// neither plans nothing.
func TestGitHubPlan(t *testing.T) {
	w := runtest.Install(t)
	g := &planGetter{FakeGetter: w.Getter}
	t.Cleanup(core.SwapGetter(func(core.GetterConfig) (core.Getter, error) { return g, nil }))
	w.Publish(core.Composer, "monolog/monolog", "3.0.0", "3.1.0")
	w.Install(core.Composer, "monolog/monolog", "3.0.0")
	w.Publish(core.NPM, "pkg", "1.0.0", "1.1.0")
	w.Sources[core.NPM].Metas[core.Ref{Eco: core.NPM, Name: "pkg", Version: "1.1.0"}] = &core.Meta{Repository: "https://github.com/acme/pkg"}
	w.Install(core.NPM, "pkg", "1.0.0")
	w.Detector.Set("pkg", "owner-change")
	t.Cleanup(core.SwapTagChecker(func(*core.Env) core.TagChecker { return &tagChecker{} }))
	review(t, request(t, "all"))
	if !slices.Equal(g.plans, []int{2, 5}) {
		t.Errorf("plans %v, want [2 5]", g.plans)
	}

	w = runtest.Install(t)
	g = &planGetter{FakeGetter: w.Getter}
	t.Cleanup(core.SwapGetter(func(core.GetterConfig) (core.Getter, error) { return g, nil }))
	w.Publish(core.WPPlugin, "akismet", "5.3.3", "5.3.5")
	w.Install(core.WPPlugin, "akismet", "5.3.3")
	review(t, request(t, "all"))
	if len(g.plans) != 0 {
		t.Errorf("a WordPress update planned %v", g.plans)
	}
}
