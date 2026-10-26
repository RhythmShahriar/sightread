// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package wporg

import (
	"context"

	"github.com/RhythmShahriar/sightread/archive"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/fetch"
)

func init() {
	core.RegisterSource(core.WPPlugin, func(env *core.Env) core.Source { return NewPlugin(env) })
}

// Plugin is the WordPress.org plugin source: the info API for versions
// and owners, the release zip, the per-file checksums WordPress.org
// publishes for every release and the SVN tag's committer. It implements
// core.Source, core.LocalVerifier and core.TagSource.
type Plugin struct{ s *site }

// NewPlugin returns the plugin source for env.
func NewPlugin(env *core.Env) *Plugin { return &Plugin{s: newSite(env, core.WPPlugin)} }

// Eco returns core.WPPlugin.
func (p *Plugin) Eco() core.Ecosystem { return core.WPPlugin }

// Versions lists slug's releases, oldest first. An unknown slug is E2;
// a closed plugin has none.
func (p *Plugin) Versions(ctx context.Context, slug string) ([]string, error) {
	in, err := p.s.info(ctx, slug)
	if err != nil {
		return nil, err
	}
	return versions(in), nil
}

// Meta describes slug at ref.Version (the current release when empty).
// A version the API does not list is E3. A closed plugin gets a Meta
// with Closed set and nothing to download.
func (p *Plugin) Meta(ctx context.Context, ref core.Ref) (*core.Meta, error) {
	m, _, err := p.s.meta(ctx, ref)
	return m, err
}

// Fetch downloads the release zip, unpacks it under the slug's folder
// and checks every file against WordPress.org's checksums. WordPress.org
// may rebuild a zip with other bytes and the same files, so the tree is
// identified by its manifest hash.
func (p *Plugin) Fetch(ctx context.Context, m *core.Meta) (*core.Tree, core.Integrity, error) {
	if m.Closed {
		return nil, core.Integrity{}, p.s.closedError(m)
	}
	slug, v := m.Ref.Name, m.Ref.Version
	tree, err := p.s.download(ctx, m)
	if err != nil {
		return nil, core.Integrity{}, err
	}
	want, reason, err := p.s.checksums(ctx, slug, v)
	if err != nil {
		return nil, core.Integrity{}, p.s.pkg(slug, v).Wrap(err)
	}
	in := core.Integrity{By: core.ByNone, Method: MethodChecksumsNone, Detail: reason}
	if want != nil {
		in = verifyTree(tree, want)
	}
	return tree, in, nil
}

// download fetches and indexes m's zip, stripping the slug's folder,
// gives the tree its manifest hash and reads the changelog and the
// readme's contributors into m.
func (s *site) download(ctx context.Context, m *core.Meta) (*core.Tree, error) {
	slug, v := m.Ref.Name, m.Ref.Version
	d, err := s.env.Get.Download(ctx, m.Archive.URL, s.lim.Download, s.env.Blobs)
	if err != nil {
		return nil, s.pkg(slug, v).Wrap(err)
	}
	tree, err := archive.ReadZipDownload(ctx, d, s.env.Blobs, s.lim, archive.StripFolder(slug))
	if err != nil {
		return nil, s.pkg(slug, v).Wrap(err)
	}
	tree.HashKind = core.HashManifest
	tree.SHA256 = core.ManifestHash(tree.Files)
	metaFromTree(m, tree)
	return tree, nil
}

// MetaFromTree fills what m takes from the release's own files (the
// changelog and the readme's contributors), for a tree the caller had
// cached instead of fetching it.
func (p *Plugin) MetaFromTree(m *core.Meta, tree *core.Tree) { metaFromTree(m, tree) }

// VerifyLocal compares an installed copy with WordPress.org's checksums
// of the installed version. Fewer than half the files matching makes the
// copy not the plugin WordPress.org knows (Drift.Official false); so
// does a version WordPress.org has no checksums for. Checksums that
// can't be had right now are E5.
func (p *Plugin) VerifyLocal(ctx context.Context, ref core.Ref, local *core.Tree) (core.Drift, error) {
	want, reason, err := p.s.checksums(ctx, ref.Name, ref.Version)
	switch {
	case err != nil:
		return core.Drift{}, p.s.pkg(ref.Name, ref.Version).Wrap(err)
	case want == nil && reason == reasonNoChecksums:
		return drift(local, sums{}), nil
	case want == nil:
		return core.Drift{}, fetch.Unverified(p.s.command, ref.Name, ref.Version, reason)
	}
	if d := core.GetDiffer(); d != nil {
		return d.Drift(ctx, local, officialTree(want, local)), nil
	}
	return drift(local, want), nil
}

// Tags returns {"latest": the info API version}.
func (p *Plugin) Tags(ctx context.Context, slug string) (map[string]string, error) {
	return p.s.tags(ctx, slug)
}

// The interfaces Plugin promises.
var (
	_ core.Source        = (*Plugin)(nil)
	_ core.LocalVerifier = (*Plugin)(nil)
	_ core.TagSource     = (*Plugin)(nil)
)
