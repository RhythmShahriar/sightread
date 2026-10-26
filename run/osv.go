// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run

import (
	"context"

	"github.com/RhythmShahriar/sightread/core"
)

// advisories asks OSV once for every public npm and Composer version
// the run reviews, both sides, so known-malicious and known-vulnerable
// can compare them. Private names are never sent (SR-8): a private
// target, or one read from a local file, is left out.
func (r *reviewer) advisories(ctx context.Context, targets []*target, rep *core.Report) {
	if r.req.NoOSV {
		return
	}
	a := core.AdvisoriesFor(r.env)
	if a == nil {
		return
	}
	seen := map[core.Ref]bool{}
	var refs []core.Ref
	add := func(ref core.Ref) {
		if ref.Version != "" && !seen[ref] {
			seen[ref] = true
			refs = append(refs, ref)
		}
	}
	for _, t := range targets {
		if !t.picked || t.private || (t.eco != core.NPM && t.eco != core.Composer) {
			continue
		}
		if t.toFile == "" {
			add(core.Ref{Eco: t.eco, Name: t.name, Version: t.cand.Version})
		}
		if t.fromFile == "" && t.localFrom == "" {
			add(core.Ref{Eco: t.eco, Name: t.name, Version: t.fromVersion})
		}
	}
	if len(refs) == 0 {
		return
	}
	got, err := a.Query(ctx, refs)
	if err != nil {
		r.logf("osv: %v", err)
		rep.Warnings = append(rep.Warnings, "couldn't look up OSV advisories ("+firstLine(err)+"): known-malicious and known-vulnerable were not checked")
		return
	}
	r.osv = got
}
