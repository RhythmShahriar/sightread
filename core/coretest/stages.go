// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package coretest

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

// FakeSource is a core.Source over canned data. Its fields can't be
// named Eco and Versions as the source methods are, so they are
// Ecosystem and Published.
type FakeSource struct {
	Ecosystem core.Ecosystem
	Published map[string][]string // name to versions, oldest first
	Metas     map[core.Ref]*core.Meta
	Trees     map[core.Ref]map[string]string
	// Integrity per version; a version without one is ByChecksums.
	Integrity map[core.Ref]core.Integrity
}

// Eco returns the source's ecosystem.
func (s *FakeSource) Eco() core.Ecosystem { return s.Ecosystem }

// Versions returns the published versions of name, or an E2 error.
func (s *FakeSource) Versions(_ context.Context, name string) ([]string, error) {
	vs, ok := s.Published[name]
	if !ok {
		return nil, &core.Error{Code: core.EUnknownPackage, Exit: cli.ExitUsage,
			What: fmt.Sprintf("the fake %s source has no package %q", s.Ecosystem, name)}
	}
	return slices.Clone(vs), nil
}

// Meta returns the canned metadata of ref, or an E3 error. A version
// with a tree but no Meta gets a bare one.
func (s *FakeSource) Meta(_ context.Context, ref core.Ref) (*core.Meta, error) {
	if m, ok := s.Metas[ref]; ok {
		c := *m
		c.Ref = ref
		return &c, nil
	}
	if _, ok := s.Trees[ref]; ok {
		return &core.Meta{Ref: ref}, nil
	}
	return nil, &core.Error{Code: core.EVersionMissing, Exit: cli.ExitUsage,
		What: fmt.Sprintf("%s has no version %s on the fake source", ref.Name, ref.Version)}
}

// Fetch builds the canned tree of m.Ref.
func (s *FakeSource) Fetch(_ context.Context, m *core.Meta) (*core.Tree, core.Integrity, error) {
	files, ok := s.Trees[m.Ref]
	if !ok {
		return nil, core.Integrity{}, fmt.Errorf("fake source: no tree for %s", m.Ref)
	}
	in, ok := s.Integrity[m.Ref]
	if !ok {
		in = core.Integrity{By: core.ByChecksums, Method: "fake checksums"}
	}
	return Tree(files), in, nil
}

// Install registers s as its ecosystem's source for the test.
func (s *FakeSource) Install(t testing.TB) {
	t.Helper()
	t.Cleanup(core.SwapSource(s.Ecosystem, func(*core.Env) core.Source { return s }))
}

// FakeInventory is a core.Inventory over canned data.
type FakeInventory struct {
	Site       *core.Site
	Bumps      []core.Bump
	NotChecked []core.NotChecked
	// Dirs maps a folder LocalTree is asked for to its files.
	Dirs map[string]map[string]string
	Err  error
}

// Read returns Site with Root set to the request's.
func (f *FakeInventory) Read(_ context.Context, req core.InventoryRequest) (*core.Site, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	s := core.Site{}
	if f.Site != nil {
		s = *f.Site
	}
	s.Root = req.Root
	return &s, nil
}

// Changes returns Bumps and NotChecked.
func (f *FakeInventory) Changes(context.Context, core.ChangesRequest) ([]core.Bump, []core.NotChecked, error) {
	return f.Bumps, f.NotChecked, f.Err
}

// LocalTree builds the tree of Dirs[dir].
func (f *FakeInventory) LocalTree(_ context.Context, dir string, _ core.BlobStore, _ core.Limits) (*core.Tree, error) {
	files, ok := f.Dirs[dir]
	if !ok {
		return nil, fmt.Errorf("fake inventory: no folder %s", dir)
	}
	return Tree(files), nil
}

// Install registers f as the inventory for the test.
func (f *FakeInventory) Install(t testing.TB) {
	t.Helper()
	t.Cleanup(core.SwapInventory(f))
}

// FakeDiffer compares trees by path and hash only: no hunks, no line
// counts, no renames.
type FakeDiffer struct{}

// Diff lists added, removed and modified files.
func (FakeDiffer) Diff(_ context.Context, old, new *core.Tree) (*core.Diff, error) {
	d := &core.Diff{Old: old, New: new}
	oldFiles, newFiles := byPath(old), byPath(new)
	for _, p := range slices.Sorted(maps.Keys(union(oldFiles, newFiles))) {
		o, inOld := oldFiles[p]
		n, inNew := newFiles[p]
		switch {
		case inOld && !inNew:
			d.Changes = append(d.Changes, core.FileChange{Kind: core.Removed, Old: o})
			d.Stats.FilesRemoved++
		case !inOld && inNew:
			d.Changes = append(d.Changes, core.FileChange{Kind: core.Added, New: n})
			d.Stats.FilesAdded++
		case o.SHA256 != n.SHA256:
			d.Changes = append(d.Changes, core.FileChange{Kind: core.Modified, Old: o, New: n})
			d.Stats.FilesChanged++
		}
	}
	if old != nil {
		d.Stats.BytesFrom = old.Bytes
	}
	if new != nil {
		d.Stats.BytesTo = new.Bytes
	}
	return d, nil
}

// Hunks returns none: the fake works at the file level.
func (FakeDiffer) Hunks(context.Context, *core.Diff, string, int) ([]core.Hunk, error) {
	return nil, nil
}

// Drift compares an installed tree with the official one by hash.
func (FakeDiffer) Drift(_ context.Context, local, official *core.Tree) core.Drift {
	var d core.Drift
	l, o := byPath(local), byPath(official)
	for _, p := range slices.Sorted(maps.Keys(o)) {
		switch lf, ok := l[p]; {
		case !ok:
			d.Missing = append(d.Missing, p)
		case lf.SHA256 == o[p].SHA256:
			d.Matched = append(d.Matched, p)
		default:
			d.Differ = append(d.Differ, p)
		}
	}
	for _, p := range slices.Sorted(maps.Keys(l)) {
		if _, ok := o[p]; !ok {
			d.Extra = append(d.Extra, p)
		}
	}
	d.Official = len(o) > 0 && 2*len(d.Matched) >= len(o)
	return d
}

// Install registers the fake differ for the test.
func (f FakeDiffer) Install(t testing.TB) {
	t.Helper()
	t.Cleanup(core.SwapDiffer(f))
}

func byPath(t *core.Tree) map[string]*core.File {
	m := map[string]*core.File{}
	if t == nil {
		return m
	}
	for i := range t.Files {
		m[t.Files[i].Path] = &t.Files[i]
	}
	return m
}

func union(a, b map[string]*core.File) map[string]bool {
	m := map[string]bool{}
	for k := range a {
		m[k] = true
	}
	for k := range b {
		m[k] = true
	}
	return m
}

// FakeAnalyzer returns canned features. ByTree, when it has the tree,
// wins over ByPath, so a test can give the old and new versions of one
// path different features.
type FakeAnalyzer struct {
	ByPath map[string][]core.Feature
	ByTree map[*core.Tree]map[string][]core.Feature
	ByText map[string][]core.Feature // AnalyzeText, keyed by the source text
	// Unanalysed lists paths reported as not analysed, with the reason.
	Unanalysed map[string]string
}

// Analyze returns the canned features of the asked paths that are in t.
func (a *FakeAnalyzer) Analyze(ctx context.Context, t *core.Tree, paths []string, _ core.Limits) (*core.FeatureSet, error) {
	s := core.NewFeatureSet()
	canned := a.ByPath
	if m, ok := a.ByTree[t]; ok {
		canned = m
	}
	for _, p := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, ok := t.Lookup(p); !ok {
			continue
		}
		if why, ok := a.Unanalysed[p]; ok {
			s.Unanalysed = append(s.Unanalysed, core.Unanalysed{Path: p, Reason: why})
			continue
		}
		for _, f := range canned[p] {
			if f.Ev.Path == "" {
				f.Ev.Path = p
			}
			s.Add(f)
		}
	}
	return s, nil
}

// AnalyzeText returns ByText[src].
func (a *FakeAnalyzer) AnalyzeText(_ context.Context, _ core.FileKind, p string, src []byte) (*core.FeatureSet, error) {
	s := core.NewFeatureSet()
	for _, f := range a.ByText[string(src)] {
		if f.Ev.Path == "" {
			f.Ev.Path = p
		}
		s.Add(f)
	}
	return s, nil
}

// Install registers a as the analyzer for the test.
func (a *FakeAnalyzer) Install(t testing.TB) {
	t.Helper()
	t.Cleanup(core.SwapAnalyzer(a))
}

// Features builds a feature set.
func Features(fs ...core.Feature) *core.FeatureSet {
	s := core.NewFeatureSet()
	for _, f := range fs {
		s.Add(f)
	}
	return s
}

// Feat builds a feature in code context. attrs are key, value pairs.
func Feat(kind core.FeatureKind, key, p string, line int, attrs ...string) core.Feature {
	if len(attrs)%2 != 0 {
		panic("coretest.Feat: attrs must be key, value pairs")
	}
	f := core.Feature{Kind: kind, Key: key, Context: core.CtxCode,
		Ev: core.Evidence{Path: p, Line: line, EndLine: line, Snippet: core.NewSnippet(string(kind) + " " + key)}}
	if len(attrs) > 0 {
		f.Attrs = map[string]string{}
		for i := 0; i+1 < len(attrs); i += 2 {
			f.Attrs[attrs[i]] = attrs[i+1]
		}
	}
	return f
}
