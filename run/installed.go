// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run

import (
	"cmp"
	"context"
	"slices"
	"strings"
	"sync"

	"github.com/RhythmShahriar/sightread/core"
	"golang.org/x/sync/errgroup"
)

// InstalledStatus is what a package's source says today about a version
// a site runs: who can publish the package and whether it was closed.
// watch compares it between runs, so an owner change or a WordPress.org
// closure reaches people even when no new version came out.
type InstalledStatus struct {
	Site string // fleet site name; "" for a single site
	Ref  core.Ref
	// Owners are the maintainers, committers and contributors the source
	// lists, lower case, sorted and unique; nil when it lists none.
	Owners       []string
	Closed       bool
	ClosedReason string
}

// Installed reads every site of req (req.Sites, or req.Inventory when
// there are none) and asks each package's source about the installed
// version: one Meta request per distinct package and version, on
// --jobs workers. Private packages and transitive Composer and npm
// dependencies (unless --transitive) are left out. A site that can't be
// read or a package the source can't describe is skipped (and logged
// with -v); the error is for a run that can't start at all.
func Installed(ctx context.Context, req Request) ([]InstalledStatus, error) {
	r := &reviewer{req: req}
	if err := r.setup(); err != nil {
		return nil, err
	}
	sites := req.Sites
	if len(sites) == 0 {
		sites = []Site{{Inventory: req.Inventory}}
	}
	type member struct {
		site string
		ref  core.Ref
	}
	var members []member
	refs := map[core.Ref]bool{}
	for _, s := range sites {
		ir := s.Inventory
		if len(ir.Ecosystems) == 0 {
			ir.Ecosystems = req.Inventory.Ecosystems
		}
		ir.Transitive = req.Transitive
		if ir.MaxDepth == 0 {
			ir.MaxDepth = 6
		}
		site, _, err := r.readSite(ctx, ir)
		if err != nil {
			r.logf("site %s: %v", s.Name, err)
			continue
		}
		for _, inst := range site.Installed {
			ref := inst.Ref
			if inst.Private || ref.Version == "" || !Selected(ref.Eco, ref.Name, req.Only, req.Skip) ||
				(!isWP(ref.Eco) && !inst.Direct && !req.Transitive) {
				continue
			}
			members = append(members, member{site: s.Name, ref: ref})
			refs[ref] = true
		}
	}

	metas := map[core.Ref]*core.Meta{}
	var mu sync.Mutex
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(r.jobs())
	for ref := range refs {
		g.Go(func() error {
			src := core.SourceFor(ref.Eco, r.env)
			if src == nil {
				return nil
			}
			m, err := src.Meta(gctx, ref)
			if err != nil {
				r.logf("%s: %v", ref, err)
				return nil
			}
			if isWP(ref.Eco) && m.Latest != "" && m.Latest != ref.Version && !m.Closed {
				// WordPress.org lists the contributors of the current
				// release only and gives an older version none (its
				// readme is not read here). Who can publish today is
				// what watch compares.
				cur := ref
				cur.Version = m.Latest
				if lm, err := src.Meta(gctx, cur); err == nil {
					c := *m
					c.Contributors, c.AuthorProfile = lm.Contributors, lm.AuthorProfile
					m = &c
				}
			}
			mu.Lock()
			metas[ref] = m
			mu.Unlock()
			return nil
		})
	}
	_ = g.Wait() // workers never fail; a context error leaves metas short

	var out []InstalledStatus
	for _, m := range members {
		meta := metas[m.ref]
		if meta == nil {
			continue
		}
		out = append(out, InstalledStatus{Site: m.site, Ref: m.ref, Owners: owners(meta), Closed: meta.Closed, ClosedReason: meta.ClosedReason})
	}
	slices.SortFunc(out, func(a, b InstalledStatus) int {
		return strings.Compare(a.Site+"\x00"+a.Ref.String(), b.Site+"\x00"+b.Ref.String())
	})
	return out, ctx.Err()
}

// owners lists who can publish the package as m describes it: the
// maintainers (by login, else name) and the WordPress.org contributors.
func owners(m *core.Meta) []string {
	var out []string
	for _, p := range m.Maintainers {
		if id := strings.ToLower(strings.TrimSpace(cmp.Or(p.Login, p.Name))); id != "" {
			out = append(out, id)
		}
	}
	for _, c := range m.Contributors {
		if id := strings.ToLower(strings.TrimSpace(c)); id != "" {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
