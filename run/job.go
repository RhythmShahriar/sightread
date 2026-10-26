// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run

import (
	"cmp"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

// pick chooses t's candidate, or marks it as nothing to review.
func (r *reviewer) pick(ctx context.Context, t *target) error {
	if t.toFixed != "" {
		t.cand, t.picked = candidate{Version: t.toFixed}, true
		if t.toFile == "" {
			// A lockfile change names its version; the list still feeds
			// History.
			if src := core.SourceFor(t.eco, r.env); src != nil {
				t.versions, _ = src.Versions(ctx, t.name)
			}
		}
		return nil
	}
	src := core.SourceFor(t.eco, r.env)
	if src == nil {
		return fmt.Errorf("%s source %w", t.eco, core.ErrNotLinked)
	}
	res, err := pickCandidate(ctx, src, pickInput{Command: r.req.Command, Eco: t.eco, Name: t.name, From: t.fromVersion,
		Constraint: t.constraint, To: r.req.To, Pre: r.req.Pre, Downgrade: r.req.AllowDowngrade, Explicit: r.req.To != ""})
	if err != nil {
		return err
	}
	t.cand, t.versions = res.cand, res.versions
	switch {
	case res.upToDate:
		t.skip = true
		if t.explicit {
			r.note(upToDateNote(t))
		}
	case res.older:
		t.skip = true
	default:
		t.picked = true
	}
	return nil
}

func upToDateNote(t *target) string {
	v := t.cand.Version
	switch v {
	case t.cand.Latest:
		return fmt.Sprintf("%s %s is already the latest%s", t.name, v, NothingToCompare)
	case t.cand.Wanted:
		return fmt.Sprintf("%s %s is already the newest %s allows%s", t.name, v, t.constraint, NothingToCompare)
	}
	return fmt.Sprintf("%s %s is the installed version%s", t.name, v, NothingToCompare)
}

// failure turns a package's error into its report entries (PRD 5.5 and
// section 10): too big is Not checked too-large, an unknown WordPress.org
// slug is not-wporg, anything else fetch-failed plus an error entry
// carrying its code.
func (r *reviewer) failure(t *target, err error) *result {
	r.logf("%s:%s: %v", t.eco, t.name, err)
	res := &result{}
	nc := core.NotChecked{Eco: t.eco, Name: t.name, Version: t.fromVersion}
	code := core.CodeOf(err)
	switch {
	case errors.Is(err, core.ErrTooLarge) || code == core.ETooLarge:
		nc.Reason, nc.Text, nc.Hint = core.TooLarge, firstLine(err), "raise --max-size"
	case code == core.EUnknownPackage && isWP(t.eco):
		nc.Reason, nc.Text, nc.Hint = core.NotWPOrg, "not on WordPress.org (slug unknown)", "give the vendor's zip with --to-file"
	default:
		nc.Reason, nc.Text, nc.Hint = core.FetchFailed, "could not download ("+firstLine(err)+")", "run again; -v shows the request"
		if code != "" {
			res.errs = append(res.errs, core.ErrorEntry{Eco: t.eco, Name: t.name, Code: code, Message: firstLine(err)})
		}
	}
	res.notChecked = append(res.notChecked, nc)
	return res
}

// side is one fetched version.
type side struct {
	meta   *core.Meta
	tree   *core.Tree
	in     core.Integrity
	cached bool
	info   core.Side
}

// review reviews one picked target. It returns nil when the run was
// stopped while it worked, so the target is listed as not reviewed.
func (r *reviewer) review(ctx context.Context, t *target) *result {
	res := &result{}
	fail := func(err error) *result {
		if ctx.Err() != nil {
			return nil
		}
		f := r.failure(t, err)
		f.notChecked = append(res.notChecked, f.notChecked...)
		return f
	}
	src := core.SourceFor(t.eco, r.env)
	official := t.toFile == "" || (t.fromVersion != "" && t.fromFile == "" && t.localFrom == "")
	if src == nil && official {
		return fail(fmt.Errorf("%s source %w", t.eco, core.ErrNotLinked))
	}
	u := &core.Update{Eco: t.eco, Name: t.name}

	drift, keep := r.drift(ctx, src, t, res)
	if len(t.members) > 0 && len(keep) == 0 {
		return res // every installed copy is something else than the official package
	}
	t.members = keep
	for _, m := range t.members {
		if m.site != "" {
			u.Sites = append(u.Sites, m.site)
		}
	}
	if inst := t.installed(); inst != nil {
		u.Installed = core.InstalledInfo{Path: inst.Path, Lockfile: inst.Lockfile, LockLine: inst.LockLine}
	}
	if drift != nil {
		u.Installed.Drift = len(drift.Differ)+len(drift.Missing) > 0
		u.Installed.DriftFiles = append(slices.Clone(drift.Differ), drift.Missing...)
	}

	var old *side
	if t.fromVersion != "" || t.fromFile != "" || t.localFrom != "" {
		var err error
		if old, err = r.side(ctx, src, t, false); err != nil {
			return fail(err)
		}
		u.From = old.info
	}
	cur, err := r.side(ctx, src, t, true)
	if err != nil {
		return fail(err)
	}
	u.To = cur.info
	u.To.Latest = t.cand.Latest != "" && cur.info.Version == t.cand.Latest
	u.To.Wanted = t.cand.Wanted != "" && cur.info.Version == t.cand.Wanted
	u.To.Constraint = t.constraint
	u.FromCache = cur.cached && (old == nil || old.cached)
	u.Changelog = cur.meta.Changelog

	if !r.req.AllowUnverified && (cur.in.Partial() || old != nil && old.in.Partial()) {
		// PRD 5.6: not diffed unless --allow-unverified.
		for _, s := range []*side{old, cur} {
			if s != nil && s.in.Partial() {
				u.Errors = append(u.Errors, core.ErrorEntry{Eco: t.eco, Name: t.name, Code: core.EUnverifiable,
					Message: fmt.Sprintf("couldn't verify %s %s: %s", t.name, s.info.Version, cmp.Or(s.in.Detail, "nothing to check it against"))})
			}
		}
		r.scorer.Score(ctx, u, r.cfg, r.allow, r.baseline)
		r.finish(u)
		res.update = u
		return res
	}

	r.publicCheck(ctx, t, cur.meta)
	if adv, ok := r.osv[core.Ref{Eco: t.eco, Name: t.name, Version: cur.info.Version}]; ok && cur.meta.Advisories == nil {
		cur.meta.Advisories = adv
	}
	if old != nil {
		if adv, ok := r.osv[core.Ref{Eco: t.eco, Name: t.name, Version: old.info.Version}]; ok && old.meta.Advisories == nil {
			old.meta.Advisories = adv
		}
	}
	r.depInfo(ctx, src, t, old, cur)
	r.history(t, old, cur)

	var oldTree *core.Tree
	if old != nil {
		oldTree = old.tree
	}
	d, err := r.differ.Diff(ctx, oldTree, cur.tree)
	if err != nil {
		return fail(err)
	}
	u.Diff = d.Stats
	oldPaths, newPaths := changedPaths(d)
	var oldFeat, newFeat *core.FeatureSet
	if oldTree != nil {
		if oldFeat, err = r.analyzer.Analyze(ctx, oldTree, oldPaths, r.env.Limits); err != nil {
			return fail(err)
		}
	}
	if newFeat, err = r.analyzer.Analyze(ctx, cur.tree, newPaths, r.env.Limits); err != nil {
		return fail(err)
	}
	s := &core.Subject{Update: core.Ref{Eco: t.eco, Name: t.name, Version: cur.info.Version}, New: cur.meta, NewTree: cur.tree,
		NewIntegrity: cur.in, OldLock: t.oldLock, NewLock: t.newLock, Diff: d, OldFeatures: oldFeat, NewFeatures: newFeat,
		Drift: drift, Config: r.cfg, Now: r.req.now()}
	if old != nil {
		s.Old, s.OldTree, s.OldIntegrity = old.meta, old.tree, old.in
	}
	findings, errs := r.detect(ctx, s)
	if r.tagCheck(ctx, t, cur.meta, findings) {
		again, more := r.detect(ctx, s)
		errs = append(errs, more...)
		for _, f := range again {
			if f.ID == "git-tag-missing" {
				findings = append(findings, f)
			}
		}
	}
	for _, e := range errs {
		u.Errors = append(u.Errors, core.ErrorEntry{Eco: t.eco, Name: t.name, Message: e})
	}
	u.Findings = findings
	if ctx.Err() != nil {
		return nil
	}
	r.scorer.Score(ctx, u, r.cfg, r.allow, r.baseline)
	r.filter(u)
	u.Hunks = r.hunks(ctx, d, u)
	r.finish(u)
	res.update = u
	return res
}

// finish hands a finished update to --jsonl.
func (r *reviewer) finish(u *core.Update) {
	if r.req.OnUpdate == nil {
		return
	}
	r.onUpdate.Lock()
	defer r.onUpdate.Unlock()
	if !r.stopped.Load() {
		r.req.OnUpdate(*u)
	}
}

// drift compares each member's installed copy with the official copy of
// the installed version. A copy that is not the official package at all
// becomes Not checked not-wporg; members returns those left. The drift of
// the first member is the Subject's.
func (r *reviewer) drift(ctx context.Context, src core.Source, t *target, res *result) (*core.Drift, []member) {
	lv, ok := src.(core.LocalVerifier)
	if !ok || r.inv == nil || t.fromVersion == "" || t.fromFile != "" || t.localFrom != "" {
		return nil, t.members
	}
	var first *core.Drift
	var keep []member
	for _, m := range t.members {
		if m.installed == nil || m.installed.Path == "" || m.root == "" {
			keep = append(keep, m)
			continue
		}
		local, err := r.inv.LocalTree(ctx, joinRoot(m.root, m.installed.Path), r.blobs, r.env.Limits)
		if err != nil {
			r.logf("%s:%s: drift: %v", t.eco, t.name, err)
			keep = append(keep, m)
			continue
		}
		d, err := lv.VerifyLocal(ctx, core.Ref{Eco: t.eco, Name: t.name, Version: t.fromVersion}, local)
		if err != nil {
			r.logf("%s:%s: drift: %v", t.eco, t.name, err)
			keep = append(keep, m)
			continue
		}
		if !d.Official {
			nc := core.NotChecked{Eco: t.eco, Name: t.name, Version: t.fromVersion, Reason: core.NotWPOrg,
				Text: "not on " + sourceName(t.eco) + " (no files match the " + sourceName(t.eco) + " copy)", Hint: "give the vendor's zip with --to-file"}
			if m.site != "" {
				nc.Text += " (site " + m.site + ")"
			}
			res.notChecked = append(res.notChecked, nc)
			continue
		}
		if first == nil {
			first = &d
		}
		keep = append(keep, m)
	}
	return first, keep
}

// side fetches or reads one version of t: new picks the candidate.
func (r *reviewer) side(ctx context.Context, src core.Source, t *target, isNew bool) (*side, error) {
	version, file, dir := t.fromVersion, t.fromFile, t.localFrom
	if isNew {
		version, file, dir = t.cand.Version, t.toFile, ""
	}
	ref := core.Ref{Eco: t.eco, Name: t.name, Version: version}
	if file != "" || dir != "" {
		tree, err := r.readLocal(ctx, cmp.Or(file, dir), dir != "")
		if err != nil {
			return nil, err
		}
		what := "local file"
		if dir != "" {
			what = "installed copy"
		}
		in := core.Integrity{By: core.ByNone, Method: what + "; nothing to check it against", Detail: what}
		return &side{meta: &core.Meta{Ref: ref}, tree: tree, in: in, info: r.sideInfo(ref, nil, tree, in, what)}, nil
	}
	m, err := src.Meta(ctx, ref)
	if err != nil {
		return nil, err
	}
	tree, in, cached, err := r.fetch(ctx, src, m)
	if err != nil {
		return nil, err
	}
	return &side{meta: m, tree: tree, in: in, cached: cached, info: r.sideInfo(ref, m, tree, in, "")}, nil
}

// readLocal reads --to-file, --from-file or an installed folder.
func (r *reviewer) readLocal(ctx context.Context, path string, folder bool) (*core.Tree, error) {
	if !folder {
		fi, err := os.Stat(path)
		if err != nil {
			return nil, &core.Error{Code: core.EBadFlag, Exit: cli.ExitUsage, Command: r.req.Command,
				What: fmt.Sprintf("can't read %s (%v)", path, errors.Unwrap(err)), Err: err}
		}
		folder = fi.IsDir()
	}
	if folder {
		if r.inv == nil {
			return nil, fmt.Errorf("inventory %w", core.ErrNotLinked)
		}
		return r.inv.LocalTree(ctx, path, r.blobs, r.env.Limits)
	}
	return core.ReadLocalArchive(ctx, path, r.blobs, r.env.Limits)
}

// fetch returns the verified tree of m from the archive index, or
// downloads, verifies and indexes it.
func (r *reviewer) fetch(ctx context.Context, src core.Source, m *core.Meta) (*core.Tree, core.Integrity, bool, error) {
	if t, in, ok := loadIndex(r.cache, m.Ref, r.blobs); ok {
		r.logf("%s: from the archive cache", m.Ref)
		return t, in, true, nil
	}
	t, in, err := src.Fetch(ctx, m)
	if err != nil {
		return nil, in, false, err
	}
	if err := adoptBlobs(ctx, t, r.blobs); err != nil {
		return nil, in, false, err
	}
	// A failed or unverified result isn't kept: the next run checks the
	// source again instead of trusting a bad or partial answer.
	if in.By != core.ByFailed && in.By != core.ByNone {
		if err := saveIndex(r.cache, m.Ref, t, in, r.req.now()); err != nil {
			r.logf("%s: archive index: %v", m.Ref, err)
		}
	}
	return t, in, false, nil
}

// sideInfo is the report's view of one version.
func (r *reviewer) sideInfo(ref core.Ref, m *core.Meta, t *core.Tree, in core.Integrity, local string) core.Side {
	s := core.Side{Version: ref.Version, SHA256: hex.EncodeToString(t.SHA256[:]), HashKind: t.HashKind,
		Verified: in.By, Method: in.Method, Source: local}
	if m == nil {
		return s
	}
	s.URL, s.Released = m.Archive.URL, m.Published
	if s.Source = sourceName(ref.Eco); m.Private {
		s.Source = cmp.Or(hostOf(m.Archive.URL), "private registry")
	}
	if p := m.Publisher; p != nil {
		s.Publisher = []string{cmp.Or(p.Login, p.Name)}
	}
	return s
}

// changedPaths lists what the analyzer reads: changed and removed files
// of the old tree, changed and added files of the new one (PRD 13).
func changedPaths(d *core.Diff) (old, cur []string) {
	if d.Old == nil && d.New != nil {
		for _, f := range d.New.Files {
			cur = append(cur, f.Path)
		}
		return nil, cur
	}
	for _, c := range d.Changes {
		if c.Old != nil && c.Kind != core.Added {
			old = append(old, c.Old.Path)
		}
		if c.New != nil && c.Kind != core.Removed {
			cur = append(cur, c.New.Path)
		}
	}
	return old, cur
}

// detect runs every detector on s. A detector that panics is reported
// as an error of the update, so its signals are known to be unchecked.
func (r *reviewer) detect(ctx context.Context, s *core.Subject) (out []core.Finding, errs []string) {
	for _, d := range core.Detectors() {
		func() {
			defer func() {
				if p := recover(); p != nil {
					errs = append(errs, fmt.Sprintf("detector %s failed (%v); its signals were not checked", d.Info().Name, p))
				}
			}()
			d.Detect(ctx, s, func(f core.Finding) { out = append(out, f) })
		}()
	}
	return out, errs
}

// tagCheck fills Meta.GitTag when the update already looks like a
// takeover. Each check costs GitHub API requests, so it runs only then
// (the rate budget rule of PRD 12.1). It reports whether it filled it.
func (r *reviewer) tagCheck(ctx context.Context, t *target, m *core.Meta, findings []core.Finding) bool {
	if t.eco != core.NPM || m.GitTag != nil || m.Repository == "" || t.private {
		return false
	}
	if !slices.ContainsFunc(findings, func(f core.Finding) bool {
		return f.ID == "owner-change" || f.ID == "npm-install-script-new" || f.ID == "provenance-dropped"
	}) {
		return false
	}
	tc := core.TagCheckerFor(r.env)
	if tc == nil {
		return false
	}
	ok, err := tc.TagExists(ctx, m.Repository, m.Ref.Version, t.name)
	if err != nil {
		r.logf("%s: git tag check: %v", m.Ref, err)
		return false
	}
	m.GitTag = &ok
	return true
}

// filter applies --id, --exclude-id and --severity after scoring. The
// unignorable signals always stay: they say the bytes are not the ones
// published or reviewed.
func (r *reviewer) filter(u *core.Update) {
	q := r.req
	if len(q.IDs) == 0 && len(q.ExcludeIDs) == 0 && q.Severity <= cli.SeverityInfo {
		return
	}
	n := len(u.Findings)
	kept := u.Findings[:0]
	for _, f := range u.Findings {
		keep := (len(q.IDs) == 0 || MatchAny(q.IDs, f.ID)) && !MatchAny(q.ExcludeIDs, f.ID) && f.Severity >= q.Severity
		if keep || core.Unignorable(f.ID) {
			kept = append(kept, f)
		}
	}
	if u.Findings = kept; len(kept) != n {
		reverdict(u)
	}
}

// reverdict sets the verdict of PRD 5.6 again after filter dropped
// findings. The scorer can't be asked twice: its context rules would
// raise a finding a second time.
func reverdict(u *core.Update) {
	worst, allowed := cli.SeverityNone, 0
	for i := range u.Findings {
		f := &u.Findings[i]
		if f.Allowed != nil {
			allowed++
		}
		if f.Counted() && f.Severity > worst {
			worst = f.Severity
		}
	}
	switch {
	case u.From.Verified == core.ByNone || u.To.Verified == core.ByNone:
		u.Verdict = core.Unverified
	case worst == cli.SeverityCritical:
		u.Verdict = core.Hold
	case worst >= cli.SeverityMedium:
		u.Verdict = core.Review
	case allowed > 0 && allowed == len(u.Findings):
		u.Verdict = core.Allowed
	default:
		u.Verdict = core.Routine
	}
}

// hunks returns the hunks of the files counted findings point at, or of
// every changed file with --diff or an HTML report.
func (r *reviewer) hunks(ctx context.Context, d *core.Diff, u *core.Update) []core.Hunk {
	paths := map[string]bool{}
	for _, f := range u.Findings {
		if f.File != "" && f.Counted() {
			paths[f.File] = true
		}
	}
	if r.req.AllHunks {
		for _, c := range d.Changes {
			if c.New != nil {
				paths[c.New.Path] = true
			} else if c.Old != nil {
				paths[c.Old.Path] = true
			}
		}
	}
	var out []core.Hunk
	for _, p := range slices.Sorted(maps.Keys(paths)) {
		hs, err := r.differ.Hunks(ctx, d, p, hunkContext)
		if err != nil {
			r.logf("%s:%s: hunks of %s: %v", u.Eco, u.Name, p, err)
			continue
		}
		out = append(out, hs...)
	}
	return out
}

// depInfo looks up each dependency new in this version: its age, its
// install scripts and whether its name is popular, for dependency-new
// and typosquat.
func (r *reviewer) depInfo(ctx context.Context, src core.Source, t *target, old, cur *side) {
	if src == nil || (t.eco != core.NPM && t.eco != core.Composer) || len(cur.meta.Deps) == 0 {
		return
	}
	var before map[string]string
	if old != nil {
		before = old.meta.Deps
	}
	var added []string
	for name := range cur.meta.Deps {
		if _, ok := before[name]; !ok {
			added = append(added, name)
		}
	}
	slices.Sort(added)
	if len(added) > MaxNewDeps {
		r.logf("%s:%s: %d new dependencies, looking up the first %d", t.eco, t.name, len(added), MaxNewDeps)
		added = added[:MaxNewDeps]
	}
	vs := core.Versions(t.eco)
	var names core.NameIndex
	if dp := core.GetDataPacks(); dp != nil {
		names = dp.Names()
	}
	for _, name := range added {
		if ctx.Err() != nil {
			return
		}
		info := &core.DepInfo{Name: name}
		if names != nil {
			info.Popular = names.Popular(t.eco, name)
		}
		if cur.meta.DepInfo == nil {
			cur.meta.DepInfo = map[string]*core.DepInfo{}
		}
		cur.meta.DepInfo[name] = info
		versions, err := src.Versions(ctx, name)
		if err != nil || vs == nil {
			r.logf("%s:%s: dependency %s: %v", t.eco, t.name, name, err)
			continue
		}
		v := core.Newest(vs, versions, cur.meta.Deps[name], false)
		if v == "" {
			v = core.Newest(vs, versions, "", false)
		}
		if v == "" {
			continue
		}
		m, err := src.Meta(ctx, core.Ref{Eco: t.eco, Name: name, Version: v})
		if err != nil {
			r.logf("%s:%s: dependency %s %s: %v", t.eco, t.name, name, v, err)
			continue
		}
		info.Version, info.Published, info.HasInstallScript = v, m.Published, m.HasInstallScript
	}
}

// history fills the releases before the candidate when the source left
// them out, from the version list and what this run already knows.
func (r *reviewer) history(t *target, old, cur *side) {
	vs := core.Versions(t.eco)
	if len(cur.meta.History) > 0 || len(t.versions) == 0 || vs == nil || !vs.Valid(cur.info.Version) {
		return
	}
	var before []string
	for _, v := range t.versions {
		if vs.Valid(v) && vs.Compare(v, cur.info.Version) < 0 {
			before = append(before, v)
		}
	}
	before = sortNewestFirst(vs, before)
	for _, v := range before[:min(len(before), 10)] {
		rel := core.Release{Version: v}
		if old != nil && v == old.info.Version {
			rel.Published, rel.Size = old.meta.Published, old.tree.Bytes
		}
		cur.meta.History = append(cur.meta.History, rel)
	}
}

// publicCheck is --check-confusion for a private package reviewed
// through its own registry: the public registry is asked for the name
// and a higher public version is recorded for dependency-confusion.
func (r *reviewer) publicCheck(ctx context.Context, t *target, m *core.Meta) {
	if !r.req.Options.CheckConfusion || !t.private && !m.Private {
		return
	}
	if v := r.publicShadow(ctx, t.eco, t.name, m.Ref.Version); v != "" {
		m.PublicShadow = v
	}
}

// publicShadow asks the public registry of eco for name and returns its
// newest version when it is above version. Only --check-confusion calls
// it: without that flag no private name leaves the machine (SR-8).
func (r *reviewer) publicShadow(ctx context.Context, eco core.Ecosystem, name, version string) string {
	if eco != core.NPM && eco != core.Composer {
		return ""
	}
	env := *r.env
	env.Bases = map[string]string{}
	for k, v := range r.env.Bases {
		if !strings.HasPrefix(k, core.BaseNPMScope) && !strings.HasPrefix(k, core.BaseComposerRepo) {
			env.Bases[k] = v
		}
	}
	pub, vs := core.SourceFor(eco, &env), core.Versions(eco)
	if pub == nil || vs == nil {
		return ""
	}
	versions, err := pub.Versions(ctx, name)
	if err != nil {
		return ""
	}
	newest := core.Newest(vs, versions, "", false)
	if newest == "" || version != "" && vs.Valid(version) && vs.Compare(newest, version) <= 0 {
		return ""
	}
	return newest
}

// joinRoot joins a site root and an installed path the inventory wrote
// with slashes.
func joinRoot(root, rel string) string { return filepath.Join(root, filepath.FromSlash(rel)) }
