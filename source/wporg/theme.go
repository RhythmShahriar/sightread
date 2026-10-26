// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package wporg

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/RhythmShahriar/sightread/archive"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/fetch"
)

func init() {
	core.RegisterSource(core.WPTheme, func(env *core.Env) core.Source { return NewTheme(env) })
}

// The Integrity.Method texts of a theme (PRD 18 item 4).
const (
	MethodTLS       = "downloaded over TLS from WordPress.org; WordPress.org publishes no theme checksums"
	MethodSVN       = "every file matches themes.svn.wordpress.org"
	MethodSVNFailed = "does not match the theme's files on themes.svn.wordpress.org"
)

// svnJobs is how many SVN files --svn-check fetches at once, the same as
// the Getter's per-host limit.
const svnJobs = 4

// Theme is the WordPress.org theme source. WordPress.org publishes no
// checksums for themes, so a theme is verified by TLS only, or with
// --svn-check by comparing every file with themes.svn.wordpress.org. It
// implements core.Source, core.LocalVerifier and core.TagSource.
type Theme struct{ s *site }

// NewTheme returns the theme source for env.
func NewTheme(env *core.Env) *Theme { return &Theme{s: newSite(env, core.WPTheme)} }

// Eco returns core.WPTheme.
func (t *Theme) Eco() core.Ecosystem { return core.WPTheme }

// Versions lists slug's releases, oldest first. An unknown slug is E2.
func (t *Theme) Versions(ctx context.Context, slug string) ([]string, error) {
	in, err := t.s.info(ctx, slug)
	if err != nil {
		return nil, err
	}
	return versions(in), nil
}

// Meta describes slug at ref.Version (the current release when empty).
// The theme's author login stands in for the contributors a plugin has.
func (t *Theme) Meta(ctx context.Context, ref core.Ref) (*core.Meta, error) {
	m, _, err := t.s.meta(ctx, ref)
	return m, err
}

// Fetch downloads the release zip and unpacks it under the slug's
// folder. With --svn-check every file is compared with the SVN copy of
// the release.
func (t *Theme) Fetch(ctx context.Context, m *core.Meta) (*core.Tree, core.Integrity, error) {
	if m.Closed {
		return nil, core.Integrity{}, t.s.closedError(m)
	}
	tree, err := t.s.download(ctx, m)
	if err != nil {
		return nil, core.Integrity{}, err
	}
	in := core.Integrity{By: core.ByTLS, Method: MethodTLS}
	if t.s.env.Options.SVNCheck {
		if in, err = t.s.svnCheck(ctx, m.Ref.Name, m.Ref.Version, tree); err != nil {
			return nil, core.Integrity{}, err
		}
	}
	return tree, in, nil
}

// MetaFromTree fills what m takes from the release's own files (the
// changelog and the readme's contributors), for a tree the caller had
// cached instead of fetching it.
func (t *Theme) MetaFromTree(m *core.Meta, tree *core.Tree) { metaFromTree(m, tree) }

// VerifyLocal compares an installed copy with the release zip of the
// installed version (PRD 6.1). WordPress.org publishes no theme
// checksums, so the zip itself, verified by TLS, is the official copy.
// Fewer than half the files matching makes the copy not the theme
// WordPress.org knows (Drift.Official false). A version or zip that
// can't be had is the error a fetch of it gives.
func (t *Theme) VerifyLocal(ctx context.Context, ref core.Ref, local *core.Tree) (core.Drift, error) {
	differ := core.GetDiffer()
	if differ == nil {
		// package diff holds the one drift rule (which files a site may
		// change); without it there is nothing to compare by.
		return core.Drift{}, fmt.Errorf("drift: differ %w", core.ErrNotLinked)
	}
	m, _, err := t.s.meta(ctx, ref)
	if err != nil {
		return core.Drift{}, err
	}
	if m.Closed {
		return core.Drift{}, t.s.closedError(m)
	}
	official, err := t.s.download(ctx, m)
	if err != nil {
		return core.Drift{}, err
	}
	return differ.Drift(ctx, local, official), nil
}

// Tags returns {"latest": the info API version}.
func (t *Theme) Tags(ctx context.Context, slug string) (map[string]string, error) {
	return t.s.tags(ctx, slug)
}

// The interfaces Theme promises.
var (
	_ core.Source        = (*Theme)(nil)
	_ core.LocalVerifier = (*Theme)(nil)
	_ core.TagSource     = (*Theme)(nil)
)

// errSVNLimit is an SVN copy bigger than the limits allow.
var errSVNLimit = errors.New("the SVN copy is over the archive limits")

// svnCheck compares tree with the SVN folder of slug at v. A listing
// that names a path outside the folder fails the check and nothing more
// is fetched; a check that can't finish (a limit, the network) leaves
// the theme verified by TLS and says why in Detail.
func (s *site) svnCheck(ctx context.Context, slug, v string, tree *core.Tree) (core.Integrity, error) {
	tls := func(err error) core.Integrity {
		return core.Integrity{By: core.ByTLS, Method: MethodTLS, Detail: "--svn-check could not finish: " + short(err)}
	}
	files, refused, err := s.svnList(ctx, slug, v)
	switch {
	case ctx.Err() != nil:
		return core.Integrity{}, ctx.Err()
	case len(refused) > 0:
		slices.Sort(refused)
		return core.Integrity{By: core.ByFailed, Method: MethodSVNFailed, Mismatch: refused,
			Detail: "the SVN listing names a path outside the theme folder; nothing was fetched from it"}, nil
	case err != nil:
		return tls(err), nil
	}
	got, err := s.svnHashes(ctx, slug, v, files)
	switch {
	case ctx.Err() != nil:
		return core.Integrity{}, ctx.Err()
	case err != nil:
		return tls(err), nil
	}
	var bad []string
	for _, f := range tree.Files {
		if h, ok := got[f.Path]; !ok || !f.Mode.IsRegular() || h != f.SHA256 {
			bad = append(bad, f.Path)
		}
	}
	cut := slices.ContainsFunc(tree.Issues, func(i core.ArchiveIssue) bool { return i.Kind == core.IssueLimit })
	have := byPath(tree)
	for _, p := range slices.Sorted(maps.Keys(got)) {
		if _, ok := have[p]; !ok && !cut {
			bad = append(bad, p)
		}
	}
	slices.Sort(bad)
	switch {
	case len(bad) > 0:
		return core.Integrity{By: core.ByFailed, Method: MethodSVNFailed, Mismatch: bad,
			Detail: fmt.Sprintf("%d %s from themes.svn.wordpress.org", len(bad), plural(len(bad), "file differs", "files differ"))}, nil
	case cut:
		return core.Integrity{By: core.ByTLS, Method: MethodTLS,
			Detail: "--svn-check could not finish: the archive hit a limit, so not every file could be checked"}, nil
	}
	return core.Integrity{By: core.BySVN, Method: MethodSVN}, nil
}

// svnFile is one file of an SVN listing, by its validated path inside
// the folder.
type svnFile struct {
	Path string
	Size int64
}

// svnList walks the SVN folder of slug at v one depth 1 PROPFIND per
// folder. Every name is checked with archive.ValidateName and must sit
// directly in the folder it was listed for; a name that doesn't is
// returned in refused and the walk stops. The walk stops too past
// lim.Entries entries or lim.Uncompressed declared bytes.
func (s *site) svnList(ctx context.Context, slug, v string) (files []svnFile, refused []string, err error) {
	root := s.svnFolder(slug, v)
	queue := []string{""}
	var entries int
	var declared int64
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		u := root + escapePath(dir)
		parsed, err := url.Parse(u)
		if err != nil {
			return nil, nil, err
		}
		body, err := s.propfind(ctx, u, 1)
		if err != nil {
			return nil, nil, err
		}
		list, err := parseMultistatus(body)
		if err != nil {
			return nil, nil, err
		}
		for _, e := range list {
			if e.Path+"/" == parsed.Path {
				continue // the folder itself, written without its slash
			}
			rest, ok := strings.CutPrefix(e.Path, parsed.Path)
			if !ok {
				refused = append(refused, clip(e.Path))
				continue
			}
			rest = strings.TrimSuffix(rest, "/")
			if rest == "" {
				continue // the folder itself
			}
			name, _, valid := archive.ValidateName(dir + rest)
			if strings.Contains(rest, "/") || !valid {
				refused = append(refused, clip(dir+rest))
				continue
			}
			if entries++; entries > s.lim.Entries {
				return nil, nil, fmt.Errorf("%w: more than %d entries", errSVNLimit, s.lim.Entries)
			}
			if e.Dir {
				queue = append(queue, name+"/")
				continue
			}
			if declared += max(e.Size, 0); declared > s.lim.Uncompressed {
				return nil, nil, fmt.Errorf("%w: over %s", errSVNLimit, fetch.Size(s.lim.Uncompressed))
			}
			files = append(files, svnFile{Path: name, Size: e.Size})
		}
		if len(refused) > 0 {
			return nil, refused, nil
		}
	}
	return files, nil, nil
}

// svnHashes fetches every file into the blob store, a few at a time,
// and returns their SHA-256 by path. Each is capped at lim.EntryStored
// and all of them at lim.Uncompressed, on bytes actually read.
func (s *site) svnHashes(ctx context.Context, slug, v string, files []svnFile) (map[string][32]byte, error) {
	root := s.svnFolder(slug, v)
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(svnJobs)
	var mu sync.Mutex
	var total int64
	out := make(map[string][32]byte, len(files))
	for _, f := range files {
		g.Go(func() error {
			d, err := s.env.Get.Download(ctx, root+escapePath(f.Path), s.lim.EntryStored, s.env.Blobs)
			if err != nil {
				return err
			}
			mu.Lock()
			defer mu.Unlock()
			if total += d.Size; total > s.lim.Uncompressed {
				return fmt.Errorf("%w: over %s", errSVNLimit, fetch.Size(s.lim.Uncompressed))
			}
			out[f.Path] = d.SHA256
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return out, nil
}

// escapePath escapes each segment of a slash-separated path.
func escapePath(p string) string {
	segs := strings.Split(p, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}
