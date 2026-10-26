// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package runtest installs a fake of every stage the review pipeline
// uses, so the run package and the commands can be tested end to end
// before the other lanes are linked. It builds on coretest and adds what
// the pipeline needs beyond it: a version scheme, a source that records
// every name it is asked about, a detector with findings per package and
// an OSV fake.
//
// It is imported by tests only.
package runtest

import (
	"context"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// World is the set of fakes one test runs against.
type World struct {
	Sources    map[core.Ecosystem]*Source
	Inventory  *coretest.FakeInventory
	Policy     *coretest.FakePolicy
	Analyzer   *coretest.FakeAnalyzer
	Detector   *Detector
	Advisories *Advisories
	Packs      *coretest.FakeDataPacks
	Blobs      core.BlobStore
	Getter     *coretest.FakeGetter
	// Writers are fake writers for every output format; each writes one
	// line naming its format and the number of updates.
	Writers map[string]*coretest.FakeWriter
}

// Install registers a fresh World for the test and restores the real
// registrations when it ends. Tests that install a World must not run in
// parallel: the registries are process-wide.
func Install(t testing.TB) *World {
	t.Helper()
	w := &World{
		Sources:    map[core.Ecosystem]*Source{},
		Inventory:  &coretest.FakeInventory{Site: &core.Site{Kind: "wordpress"}},
		Policy:     &coretest.FakePolicy{},
		Analyzer:   &coretest.FakeAnalyzer{},
		Detector:   &Detector{ByName: map[string][]core.Finding{}},
		Advisories: &Advisories{},
		Packs: &coretest.FakeDataPacks{PackList: nil, PopularNames: map[core.Ecosystem][]string{
			core.NPM: {"react", "lodash", "axios"}}},
		Blobs:   coretest.MemBlobs(),
		Getter:  &coretest.FakeGetter{},
		Writers: map[string]*coretest.FakeWriter{},
	}
	for _, eco := range core.Ecosystems() {
		s := &Source{FakeSource: &coretest.FakeSource{Ecosystem: eco, Published: map[string][]string{},
			Metas: map[core.Ref]*core.Meta{}, Trees: map[core.Ref]map[string]string{}, Integrity: map[core.Ref]core.Integrity{}},
			TagMap: map[string]map[string]string{}}
		w.Sources[eco] = s
		t.Cleanup(core.SwapSource(eco, func(*core.Env) core.Source { return s }))
		t.Cleanup(core.SwapVersionScheme(eco, Scheme{}))
	}
	w.Inventory.Install(t)
	w.Policy.Install(t)
	w.Analyzer.Install(t)
	w.Packs.Install(t)
	w.Getter.Install(t)
	coretest.FakeDiffer{}.Install(t)
	coretest.FakeScorer{}.Install(t)
	t.Cleanup(core.SwapDetectors(w.Detector))
	t.Cleanup(core.SwapAdvisories(func(*core.Env) core.Advisories { return w.Advisories }))
	t.Cleanup(core.SwapTagChecker(func(*core.Env) core.TagChecker { return nil }))
	t.Cleanup(core.SwapBlobStore(func(string) (core.BlobStore, error) { return w.Blobs, nil }))
	for _, f := range []string{core.FormatTerminal, core.FormatJSON, core.FormatJSONL, core.FormatSARIF, core.FormatMarkdown, core.FormatHTML} {
		fw := &coretest.FakeWriter{Name: f}
		fw.Install(t)
		w.Writers[f] = fw
	}
	return w
}

// Publish adds versions of a package to its ecosystem's source, each
// with a one-file tree whose content names the version.
func (w *World) Publish(eco core.Ecosystem, name string, versions ...string) {
	s := w.Sources[eco]
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Published[name] = append(s.Published[name], versions...)
	for _, v := range versions {
		ref := core.Ref{Eco: eco, Name: name, Version: v}
		s.Trees[ref] = map[string]string{"main.php": "<?php // " + name + " " + v + "\n"}
	}
}

// Install adds an installed package to the inventory's site.
func (w *World) Install(eco core.Ecosystem, name, version string) *core.Installed {
	w.Inventory.Site.Installed = append(w.Inventory.Site.Installed, core.Installed{Ref: core.Ref{Eco: eco, Name: name, Version: version}})
	return &w.Inventory.Site.Installed[len(w.Inventory.Site.Installed)-1]
}

// Source is a FakeSource that records every package name it is asked
// about, counts fetches, can wait before answering and has dist-tags.
type Source struct {
	*coretest.FakeSource
	TagMap map[string]map[string]string // name to tag to version
	// Delay, when set, is how long each Meta and Fetch waits, so tests
	// can mix up the order workers finish in.
	Delay func() time.Duration
	// Drift, when set, is what VerifyLocal returns instead of comparing.
	Drift *core.Drift
	// TreeMeta, when set, fills a Meta from its tree as the real sources
	// do (changelog, composer.json, readme contributors). Fetch calls it
	// and so does run for a tree it had cached.
	TreeMeta func(m *core.Meta, t *core.Tree)

	mu      sync.Mutex
	names   []string
	fetches int
}

// Names returns every package name the source was asked about, in order.
func (s *Source) Names() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.names)
}

// Fetches returns how many archives the source was asked to fetch.
func (s *Source) Fetches() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetches
}

func (s *Source) record(name string, fetch bool) {
	s.mu.Lock()
	s.names = append(s.names, name)
	if fetch {
		s.fetches++
	}
	d := s.Delay
	s.mu.Unlock()
	if d != nil {
		time.Sleep(d())
	}
}

// Versions records name and returns the published versions.
func (s *Source) Versions(ctx context.Context, name string) ([]string, error) {
	s.record(name, false)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.FakeSource.Versions(ctx, name)
}

// Meta records the name and returns the canned metadata.
func (s *Source) Meta(ctx context.Context, ref core.Ref) (*core.Meta, error) {
	s.record(ref.Name, false)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.FakeSource.Meta(ctx, ref)
}

// Fetch records the name, counts the fetch and builds the canned tree.
func (s *Source) Fetch(ctx context.Context, m *core.Meta) (*core.Tree, core.Integrity, error) {
	s.record(m.Ref.Name, true)
	if err := ctx.Err(); err != nil {
		return nil, core.Integrity{}, err
	}
	s.mu.Lock()
	t, in, err := s.FakeSource.Fetch(ctx, m)
	s.mu.Unlock()
	if err == nil {
		s.MetaFromTree(m, t)
	}
	return t, in, err
}

// MetaFromTree runs TreeMeta, when set.
func (s *Source) MetaFromTree(m *core.Meta, t *core.Tree) {
	s.mu.Lock()
	f := s.TreeMeta
	s.mu.Unlock()
	if f != nil {
		f(m, t)
	}
}

// Tags returns the package's dist-tags.
func (s *Source) Tags(_ context.Context, name string) (map[string]string, error) {
	s.record(name, false)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.TagMap[name], nil
}

// VerifyLocal compares a local tree with the canned tree of ref, or
// returns Drift when set.
func (s *Source) VerifyLocal(ctx context.Context, ref core.Ref, local *core.Tree) (core.Drift, error) {
	s.record(ref.Name, false)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Drift != nil {
		return *s.Drift, nil
	}
	files, ok := s.Trees[ref]
	if !ok {
		return core.Drift{}, nil
	}
	return coretest.FakeDiffer{}.Drift(ctx, local, coretest.Tree(files)), nil
}

// Detector emits canned findings for the packages named in ByName.
type Detector struct {
	mu     sync.Mutex
	ByName map[string][]core.Finding
	seen   []*core.Subject
}

// Info names the detector.
func (d *Detector) Info() core.DetectorInfo { return core.DetectorInfo{Name: "runtest"} }

// Detect emits the findings of the subject's package.
func (d *Detector) Detect(_ context.Context, s *core.Subject, emit func(core.Finding)) {
	d.mu.Lock()
	d.seen = append(d.seen, s)
	fs := slices.Clone(d.ByName[s.Update.Name])
	d.mu.Unlock()
	for _, f := range fs {
		emit(f)
	}
}

// Set gives a package findings, by signal ID with the catalogue's
// severity.
func (d *Detector) Set(name string, ids ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.ByName[name] = nil
	for _, id := range ids {
		d.ByName[name] = append(d.ByName[name], core.Finding{ID: id, File: "main.php", Line: 1, Evidence: core.NewSnippet(id)})
	}
}

// Subjects returns every subject the detector saw.
func (d *Detector) Subjects() []*core.Subject {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.seen)
}

// Advisories is an OSV fake that records the refs it is asked about.
type Advisories struct {
	mu   sync.Mutex
	asks []core.Ref
	By   map[core.Ref][]core.Advisory
}

// Query records refs and returns the canned advisories.
func (a *Advisories) Query(_ context.Context, refs []core.Ref) (map[core.Ref][]core.Advisory, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asks = append(a.asks, refs...)
	return a.By, nil
}

// Asked returns every ref queried so far.
func (a *Advisories) Asked() []core.Ref {
	a.mu.Lock()
	defer a.mu.Unlock()
	return slices.Clone(a.asks)
}

// Scheme is a version scheme for tests: dot-separated numbers compared
// numerically, with a "-suffix" marking a prerelease that sorts before
// its release. A constraint is an exact version, "^X..." (same first
// number, not lower) or ">=X...".
type Scheme struct{}

// Valid reports whether v is dot-separated numbers with an optional
// "-suffix".
func (Scheme) Valid(v string) bool {
	main, _, _ := strings.Cut(v, "-")
	if main == "" {
		return false
	}
	for _, p := range strings.Split(main, ".") {
		if _, err := strconv.Atoi(p); err != nil {
			return false
		}
	}
	return true
}

// Compare orders a and b.
func (Scheme) Compare(a, b string) int {
	am, apre, _ := strings.Cut(a, "-")
	bm, bpre, _ := strings.Cut(b, "-")
	ap, bp := strings.Split(am, "."), strings.Split(bm, ".")
	for i := 0; i < max(len(ap), len(bp)); i++ {
		var x, y int
		if i < len(ap) {
			x, _ = strconv.Atoi(ap[i])
		}
		if i < len(bp) {
			y, _ = strconv.Atoi(bp[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case apre == bpre:
		return 0
	case apre == "":
		return 1
	case bpre == "":
		return -1
	}
	return strings.Compare(apre, bpre)
}

// Prerelease reports whether v has a "-suffix".
func (Scheme) Prerelease(v string) bool { return strings.Contains(v, "-") }

// Satisfies checks v against an exact, ^ or >= constraint.
func (s Scheme) Satisfies(v, c string) (bool, error) {
	switch {
	case strings.HasPrefix(c, "^"):
		base := c[1:]
		major := func(x string) string { m, _, _ := strings.Cut(x, "."); return m }
		return major(v) == major(base) && s.Compare(v, base) >= 0, nil
	case strings.HasPrefix(c, ">="):
		return s.Compare(v, c[2:]) >= 0, nil
	}
	return s.Compare(v, c) == 0, nil
}
