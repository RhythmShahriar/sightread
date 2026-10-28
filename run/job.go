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
	"github.com/RhythmShahriar/rhythm/kit/secrets"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/source/changelog"
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
	if r.req.Rereview {
		return r.pickPrevious(ctx, src, t)
	}
	res, err := pickCandidate(ctx, src, pickInput{Command: r.req.Command, Eco: t.eco, Name: t.name, From: t.fromVersion,
		Constraint: t.constraint, To: r.req.To, Pre: r.req.Pre, Downgrade: r.req.AllowDowngrade, Explicit: r.req.To != ""})
	if err != nil {
		return err
	}
	t.cand, t.versions = res.cand, res.versions
	switch {
	case res.upToDate && r.sameWorthChecking(t):
		// Nothing to diff. The source may still serve other bytes under
		// the installed version now: reviewSame checks that.
		t.picked, t.same = true, true
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

// pickPrevious is --rereview: the candidate is the installed version and
// the from side the newest release before it, so the signals of the
// current data run over code the site already runs. A package with no
// earlier release has nothing to compare and is left out.
func (r *reviewer) pickPrevious(ctx context.Context, src core.Source, t *target) error {
	vs := core.Versions(t.eco)
	if vs == nil {
		return fmt.Errorf("%s version scheme %w", t.eco, core.ErrNotLinked)
	}
	installed := t.fromVersion
	if installed == "" || !vs.Valid(installed) {
		t.skip = true
		return nil
	}
	versions, err := src.Versions(ctx, t.name)
	if err != nil {
		return withCommand(err, r.req.Command)
	}
	prev := ""
	for _, v := range versions {
		if !vs.Valid(v) || vs.Compare(v, installed) >= 0 || (vs.Prerelease(v) && !r.req.Pre && !vs.Prerelease(installed)) {
			continue
		}
		if prev == "" || vs.Compare(v, prev) > 0 {
			prev = v
		}
	}
	if prev == "" || !slices.Contains(versions, installed) {
		t.skip = true
		return nil
	}
	t.versions, t.cand = versions, candidate{Version: installed}
	t.fromVersion, t.rereview, t.picked = prev, true, true
	return nil
}

// sameWorthChecking reports whether an installed version that is
// already the candidate still needs its source: its lock entry records
// an integrity or a commit, or an allow entry records a hash for it.
// Either shows a version republished in place, which the source alone
// can tell. A version with neither costs no request.
func (r *reviewer) sameWorthChecking(t *target) bool {
	if t.fromVersion == "" || t.fromVersion != t.cand.Version || t.fromFile != "" || t.toFile != "" || t.localFrom != "" {
		return false
	}
	if l := t.oldLock; l != nil && (l.Integrity != "" || l.Reference != "") {
		return true
	}
	return r.allowed(t)
}

// allowed reports whether an allow entry that counts names t's
// candidate version, whatever hash it records.
func (r *reviewer) allowed(t *target) bool {
	if r.allow == nil {
		return false
	}
	// No hash matches "", so any counted entry for the version comes
	// back as the match or the conflict.
	match, counted, conflict := r.allow.Match(t.eco, t.name, t.cand.Version, "")
	return match != nil && counted || conflict != nil
}

// archiveSignals are what an archive shows without a diff: entries
// that point outside it, links, collisions and limits it hit. An update
// that is not diffed still reports them.
var archiveSignals = map[string]bool{"unanalysed": true, "archive-path-escape": true, "archive-link": true, "archive-collision": true}

// sameSignals are what reviewSame reports: the version's bytes, as the
// lockfile, the allow entries and the source's own hashes recorded them.
// The scorer adds approved-version-changed.
var sameSignals = map[string]bool{"version-republished": true, "integrity-mismatch": true}

// reviewSame checks an installed version that is already the candidate.
// There is nothing to diff. The source must still serve what was
// recorded for it: a lock integrity or commit other than the source's is
// version-republished (PRD 11) and other bytes under an allowed version
// are approved-version-changed (SR-9). The archive is fetched only when
// an allow entry needs its hash. When everything matches the run says
// the version is up to date, as before.
func (r *reviewer) reviewSame(ctx context.Context, src core.Source, t *target) *result {
	res := &result{}
	fail := func(err error) *result {
		if ctx.Err() != nil {
			return nil
		}
		return r.failure(t, err)
	}
	ref := core.Ref{Eco: t.eco, Name: t.name, Version: t.cand.Version}
	m, err := src.Meta(ctx, ref)
	if err != nil {
		return fail(err)
	}
	u := &core.Update{Eco: t.eco, Name: t.name}
	for _, mb := range t.members {
		if mb.site != "" {
			u.Sites = append(u.Sites, mb.site)
		}
	}
	u.Installed = t.installedInfo()
	s := &core.Subject{Update: ref, Old: m, New: m, OldLock: t.oldLock, Config: r.cfg, Now: r.req.now()}
	u.To = core.Side{Version: ref.Version, URL: m.Archive.URL, Released: m.Published, Source: sourceName(t.eco)}
	if r.allowed(t) {
		tree, in, cached, err := r.fetch(ctx, src, m)
		if err != nil {
			return fail(err)
		}
		s.NewTree, s.NewIntegrity = tree, in
		u.To, u.FromCache = r.sideInfo(ref, m, tree, in, ""), cached
	}
	u.To.Latest = t.cand.Latest != "" && ref.Version == t.cand.Latest
	u.To.Wanted = t.cand.Wanted != "" && ref.Version == t.cand.Wanted
	u.To.Constraint = t.constraint
	u.From = core.Side{Version: ref.Version, Source: u.To.Source}
	findings, errs := r.detectOnly(ctx, s, sameSignals)
	u.Findings = findings
	if ctx.Err() != nil {
		return nil
	}
	r.scorer.Score(ctx, u, r.cfg, r.allow, r.baseline)
	if len(u.Findings) == 0 {
		if t.explicit {
			r.note(upToDateNote(t))
		}
		return res
	}
	for _, e := range errs {
		u.Errors = append(u.Errors, core.ErrorEntry{Eco: t.eco, Name: t.name, Message: e})
	}
	r.filter(u)
	r.finish(u)
	res.update = u
	return res
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
	if t.toFile != "" && core.CodeOf(err) == core.EUnknownPackage {
		err = installedSideUnknown(err)
	}
	r.problem(err)
	res := &result{}
	nc := core.NotChecked{Eco: t.eco, Name: t.name, Version: t.fromVersion, To: t.toVersion()}
	code := core.CodeOf(err)
	switch {
	case errors.Is(err, core.ErrTooLarge) || code == core.ETooLarge:
		nc.Reason, nc.Text, nc.Hint = core.TooLarge, firstLine(err), "raise --max-size"
	case code == core.EUnknownPackage && isWP(t.eco) && t.toFile != "":
		nc.Reason, nc.Text, nc.Hint = core.NotWPOrg, "not on WordPress.org (slug unknown)", InstalledSideHint
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

// InstalledSideHint is the fix line of E2 when --to-file already gives
// the new side: only the installed side was looked up on WordPress.org.
const InstalledSideHint = "--from is looked up on wordpress.org: give the installed copy with --from-file <zip>, or --path <site> without --from"

// installedSideUnknown is err (E2) with InstalledSideHint in place of
// the source's --to-file hint. A "did you mean" suggestion is kept.
func installedSideUnknown(err error) error {
	var e *core.Error
	if !errors.As(err, &e) {
		return err
	}
	c := *e
	c.Hint = []string{InstalledSideHint}
	if len(e.Hint) > 0 && strings.HasPrefix(e.Hint[0], "did you mean ") {
		if i := strings.Index(e.Hint[0], "? "); i >= 0 {
			c.Hint = []string{e.Hint[0][:i+2] + InstalledSideHint}
		}
	}
	return &c
}

// UnverifiedHint is the fix line of E5 (PRD section 10).
const UnverifiedHint = "not diffed; run again later, or --allow-unverified to review it anyway (the report marks it unverified)"

// LocalUnverifiedHint is the fix line of E5 for a side read from disk:
// running again later can never verify it.
const LocalUnverifiedHint = "not diffed; a local file has nothing to check it against: " +
	"add --allow-unverified to review it (the report marks it unverified)"

// unverifiedHint is the E5 fix line for side s.
func unverifiedHint(s core.Side) string {
	if s.Local() {
		return LocalUnverifiedHint
	}
	return UnverifiedHint
}

// problem hands a coded error to Request.OnProblem, its text masked
// like everything else a package or registry can put into output.
func (r *reviewer) problem(err error) {
	var e *core.Error
	if r.req.OnProblem == nil || !errors.As(err, &e) || e.Code == "" {
		return
	}
	c := *e
	// A source names its own review command ("npm"); the message names
	// the one the user ran ("changes"). A tool-wide error keeps none.
	if c.Command != "" && r.req.Command != "" {
		c.Command = r.req.Command
	}
	c.What = secrets.Redact(c.What)
	c.Hint = make([]string, len(e.Hint))
	for i, h := range e.Hint {
		c.Hint[i] = secrets.Redact(h)
	}
	r.req.OnProblem(&c)
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
	if t.same {
		return r.reviewSame(ctx, src, t)
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
	u.Installed = t.installedInfo()
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
	// A release's changelog lists every version; the update is only the
	// entries newer than the installed side, up to the candidate.
	if scheme := core.Versions(t.eco); scheme != nil {
		from := ""
		if old != nil {
			from = old.info.Version
			if !scheme.Valid(from) {
				// A local file may have no version (core.LocalVersion): the newest one
				// its own changelog lists is where the update starts.
				from = newestEntry(old.meta.Changelog, scheme)
			}
		}
		to := cur.info.Version
		if !scheme.Valid(to) {
			to = "" // a local candidate: every entry above from
		}
		cur.meta.Changelog = changelog.Between(cur.meta.Changelog, from, to, scheme)
	}
	u.Changelog = cur.meta.Changelog

	if !r.req.AllowUnverified && (cur.in.Partial() || old != nil && old.in.Partial()) {
		// PRD 5.6: not diffed unless --allow-unverified.
		for _, s := range []*side{old, cur} {
			if s != nil && s.in.Partial() {
				msg := fmt.Sprintf("couldn't verify %s %s: %s", t.name, s.info.Version, cmp.Or(s.in.Detail, "nothing to check it against"))
				u.Errors = append(u.Errors, core.ErrorEntry{Eco: t.eco, Name: t.name, Code: core.EUnverifiable, Message: msg})
				r.problem(&core.Error{Code: core.EUnverifiable, Exit: cli.ExitUnavailable, Command: r.req.Command, What: msg,
					Hint: []string{unverifiedHint(s.info)}})
			}
		}
		// Not diffed. What the archive itself showed still counts: a
		// limit hit makes the package unanalysed, never clean (PRD 18);
		// hostile entries are named whatever the diff says.
		s := &core.Subject{Update: core.Ref{Eco: t.eco, Name: t.name, Version: cur.info.Version}, New: cur.meta,
			NewTree: cur.tree, NewIntegrity: cur.in, Config: r.cfg, Now: r.req.now()}
		if old != nil {
			s.Old, s.OldTree, s.OldIntegrity = old.meta, old.tree, old.in
		}
		u.Findings, _ = r.detectOnly(ctx, s, archiveSignals)
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
		r.req.OnUpdate(*u, r.target)
	}
}

// drift compares each member's installed copy with the official copy of
// the installed version. A copy that is not the official package at all
// becomes Not checked not-wporg; members returns those left. The drift of
// the first member is the Subject's.
func (r *reviewer) drift(ctx context.Context, src core.Source, t *target, res *result) (*core.Drift, []member) {
	lv, ok := src.(core.LocalVerifier)
	// A rereview's from side is the release before the installed one, so
	// the installed copy is not a copy of it.
	if !ok || r.inv == nil || t.fromVersion == "" || t.fromFile != "" || t.localFrom != "" || t.rereview {
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
		if tv, ok := r.inv.(core.TreeVersioner); ok && ref.Version == core.LocalVersion {
			// --to or --from named no version: the one the files
			// declare names the side, as on the site after an install.
			ref.Version = cmp.Or(tv.TreeVersion(t.eco, t.name, tree), core.LocalVersion)
		}
		what := core.SourceLocalFile
		if dir != "" {
			what = core.SourceInstalledCopy
		}
		in := core.Integrity{By: core.ByNone, Method: what + "; nothing to check it against", Detail: what}
		// The changelog, composer.json and readme facts come from the
		// files themselves, as for a fetched release, so a local review
		// reads the same changelog and install hooks.
		m := &core.Meta{Ref: ref}
		if mf, ok := src.(treeMeta); ok {
			mf.MetaFromTree(m, tree)
		}
		return &side{meta: m, tree: tree, in: in, info: r.sideInfo(ref, nil, tree, in, what)}, nil
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

// treeMeta is a source that reads part of a Meta from the release's own
// files (every source of Sightread's own).
type treeMeta interface {
	MetaFromTree(m *core.Meta, t *core.Tree)
}

// fetch returns the verified tree of m from the archive index, or
// downloads, verifies and indexes it.
func (r *reviewer) fetch(ctx context.Context, src core.Source, m *core.Meta) (*core.Tree, core.Integrity, bool, error) {
	// --svn-check asks for a stronger check than a theme cached by TLS
	// alone had, so that cache entry is not enough: the theme is fetched
	// and checked again (and the upgraded result saved).
	svn := r.req.Options.SVNCheck && m.Ref.Eco == core.WPTheme
	if t, in, ok := loadIndex(r.cache, m.Ref, r.blobs); ok && (!svn || in.By == core.BySVN) {
		r.logf("%s: from the archive cache", m.Ref)
		// Fetch fills part of m from the archive's files (changelog,
		// composer.json, readme contributors); a cached tree must give
		// the same, or a second run would report differently.
		if mf, ok := src.(treeMeta); ok {
			mf.MetaFromTree(m, t)
		}
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
	// An --svn-check that could not finish leaves TLS with a reason
	// that belongs to this run only, so that result isn't kept either.
	if in.By != core.ByFailed && in.By != core.ByNone && (!svn || in.By == core.BySVN) {
		if err := saveIndex(r.cache, m.Ref, t, in, r.req.now()); err != nil {
			r.logf("%s: archive index: %v", m.Ref, err)
		}
	}
	return t, in, false, nil
}

// sideHash is the sha256 the report gives a tree. A manifest hash
// stands for the files read, so a tree with none, or one an archive
// limit cut short, has no hash worth showing: "" rather than the hash
// of an empty or partial list. An archive hash is of the bytes
// downloaded and stays.
func sideHash(t *core.Tree) string {
	if t.HashKind == core.HashManifest {
		if len(t.Files) == 0 || slices.ContainsFunc(t.Issues, func(i core.ArchiveIssue) bool { return i.Kind == core.IssueLimit }) {
			return ""
		}
	}
	return hex.EncodeToString(t.SHA256[:])
}

// sideInfo is the report's view of one version.
func (r *reviewer) sideInfo(ref core.Ref, m *core.Meta, t *core.Tree, in core.Integrity, local string) core.Side {
	s := core.Side{Version: ref.Version, SHA256: sideHash(t), HashKind: t.HashKind,
		Verified: in.By, Method: in.Method, Source: local}
	if in.By == core.ByTLS && in.Detail != "" {
		// A check that could not finish (--svn-check) says why next to
		// the method that stood in for it.
		s.Method += " (" + in.Detail + ")"
	}
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
	return r.detectWith(ctx, s, core.Detectors())
}

// detectOnly runs the detectors that can emit one of signals and keeps
// only those findings. It is for a subject with no diff and no features
// (a version checked against itself, or one that is not diffed), which
// the code detectors have nothing to read in. A detector that lists no
// signals runs too, its findings filtered the same way.
func (r *reviewer) detectOnly(ctx context.Context, s *core.Subject, signals map[string]bool) ([]core.Finding, []string) {
	var ds []core.Detector
	for _, d := range core.Detectors() {
		ids := d.Info().Signals
		if len(ids) == 0 || slices.ContainsFunc(ids, func(id string) bool { return signals[id] }) {
			ds = append(ds, d)
		}
	}
	all, errs := r.detectWith(ctx, s, ds)
	var out []core.Finding
	for _, f := range all {
		if signals[f.ID] {
			out = append(out, f)
		}
	}
	return out, errs
}

func (r *reviewer) detectWith(ctx context.Context, s *core.Subject, ds []core.Detector) (out []core.Finding, errs []string) {
	for _, d := range ds {
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
	r.expectGitHub(githubRequestsPerTagCheck)
	ok, err := tc.TagExists(ctx, m.Repository, m.Ref.Version, t.name)
	if err != nil {
		r.logf("%s: git tag check: %v", m.Ref, err)
		return false
	}
	m.GitTag = &ok
	return true
}

// filter applies --id, --exclude-id and --severity after scoring. It
// moves the findings it drops to u.Hidden instead of deleting them: they
// are a display choice, so they still set the verdict Score gave and
// still count for --fail-on. The unignorable signals always stay: they
// say the bytes are not the ones published or reviewed.
func (r *reviewer) filter(u *core.Update) {
	q := r.req
	if len(q.IDs) == 0 && len(q.ExcludeIDs) == 0 && q.Severity <= cli.SeverityInfo {
		return
	}
	var kept, hidden []core.Finding
	for _, f := range u.Findings {
		keep := (len(q.IDs) == 0 || MatchAny(q.IDs, f.ID)) && !MatchAny(q.ExcludeIDs, f.ID) && f.Severity >= q.Severity
		if keep || core.Unignorable(f.ID) {
			kept = append(kept, f)
		} else {
			hidden = append(hidden, f)
		}
	}
	u.Findings, u.Hidden = kept, hidden
}

// hiddenNote is the report note for findings filter left out, naming
// the flags that hid them so the reader knows how to see them again.
func hiddenNote(q *Request, n int) string {
	var by []string
	if q.Severity > cli.SeverityInfo {
		by = append(by, "--severity "+q.Severity.String())
	}
	if len(q.IDs) > 0 {
		by = append(by, "--id")
	}
	if len(q.ExcludeIDs) > 0 {
		by = append(by, "--exclude-id")
	}
	what := "findings are"
	if n == 1 {
		what = "finding is"
	}
	return fmt.Sprintf("%d %s hidden by %s (they still count for the verdict and --fail-on)", n, what, joinOr(by))
}

// joinOr writes "a", "a or b" or "a, b or c".
func joinOr(parts []string) string {
	if len(parts) < 2 {
		return strings.Join(parts, "")
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " or " + parts[len(parts)-1]
}

// notCountedNote is the report note for findings --baseline or a config
// ignore set aside, "" when there are none. It says how many and why,
// so a report they leave without counted findings never reads as clean,
// and warns when one of them is critical or high.
func notCountedNote(s core.Summary) string {
	n := s.Baselined + s.Ignored
	if n == 0 {
		return ""
	}
	var why []string
	if s.Baselined > 0 {
		why = append(why, fmt.Sprintf("%d in the --baseline report", s.Baselined))
	}
	if s.Ignored > 0 {
		why = append(why, fmt.Sprintf("%d ignored by config", s.Ignored))
	}
	what := fmt.Sprintf("%d findings were", n)
	if n == 1 {
		what = "1 finding was"
	}
	note := fmt.Sprintf("%s not counted (%s)", what, joinAnd(why))
	switch sev := s.NotCountedSevere; {
	case sev == 1 && n == 1:
		note += "; it is critical or high, so check it before you update"
	case sev > 0:
		note += fmt.Sprintf("; %d of them critical or high, so check them before you update", sev)
	default:
		note += "; the verdicts leave them out"
	}
	return note
}

// joinAnd lists parts as "a", "a and b" or "a, b and c".
func joinAnd(parts []string) string {
	if len(parts) < 2 {
		return strings.Join(parts, "")
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
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
// install scripts, its maintainers and whether its name is popular, for
// dependency-new and typosquat. For a new name close to a popular one
// it also records the popular package's maintainers, so a sibling
// package its own maintainers publish is not called a typosquat.
func (r *reviewer) depInfo(ctx context.Context, src core.Source, t *target, old, cur *side) {
	if src == nil || (t.eco != core.NPM && t.eco != core.Composer) {
		return
	}
	var names core.NameIndex
	if dp := core.GetDataPacks(); dp != nil {
		names = dp.Names()
	}
	if old == nil {
		// An added package: typosquat checks its own name.
		r.nearInfo(ctx, src, t, cur, names, t.name, cur.meta.Maintainers)
	}
	var beforeDeps, beforeDev map[string]string
	if old != nil {
		beforeDeps, beforeDev = old.meta.Deps, old.meta.DevDeps
	}
	constraint := map[string]string{}
	for name, c := range cur.meta.Deps {
		if _, ok := beforeDeps[name]; !ok {
			constraint[name] = c
		}
	}
	for name, c := range cur.meta.DevDeps {
		_, wasDev := beforeDev[name]
		_, wasRuntime := beforeDeps[name]
		if _, isRuntime := cur.meta.Deps[name]; !wasDev && !wasRuntime && !isRuntime {
			constraint[name] = c
		}
	}
	added := slices.Sorted(maps.Keys(constraint))
	if len(added) > MaxNewDeps {
		r.logf("%s:%s: %d new dependencies, looking up the first %d", t.eco, t.name, len(added), MaxNewDeps)
		added = added[:MaxNewDeps]
	}
	for _, name := range added {
		if ctx.Err() != nil {
			return
		}
		info := r.lookupDep(ctx, src, t, name, constraint[name])
		if names != nil {
			info.Popular = info.Popular || names.Popular(t.eco, name)
		}
		if cur.meta.DepInfo == nil {
			cur.meta.DepInfo = map[string]*core.DepInfo{}
		}
		cur.meta.DepInfo[name] = info
		if !info.Popular {
			r.nearInfo(ctx, src, t, cur, names, name, info.Maintainers)
		}
	}
}

// lookupDep returns what the registry says about the newest version of
// name that meets constraint (the newest at all when none does).
func (r *reviewer) lookupDep(ctx context.Context, src core.Source, t *target, name, constraint string) *core.DepInfo {
	info := &core.DepInfo{Name: name}
	vs := core.Versions(t.eco)
	versions, err := src.Versions(ctx, name)
	if err != nil || vs == nil {
		r.logf("%s:%s: dependency %s: %v", t.eco, t.name, name, err)
		return info
	}
	v := core.Newest(vs, versions, constraint, false)
	if v == "" {
		v = core.Newest(vs, versions, "", false)
	}
	if v == "" {
		return info
	}
	m, err := src.Meta(ctx, core.Ref{Eco: t.eco, Name: name, Version: v})
	if err != nil {
		r.logf("%s:%s: dependency %s %s: %v", t.eco, t.name, name, v, err)
		return info
	}
	info.Version, info.Published, info.HasInstallScript = v, m.Published, m.HasInstallScript
	info.Maintainers = slices.Clone(m.Maintainers)
	return info
}

// maxNearLookups bounds the popular packages looked up for one new
// name: the typosquat evidence names at most three.
const maxNearLookups = 3

// nearInfo records, for each popular name close to name, the popular
// package's maintainers in cur's DepInfo (Popular set). Nothing is
// looked up when name has no maintainers to compare.
func (r *reviewer) nearInfo(ctx context.Context, src core.Source, t *target, cur *side, names core.NameIndex, name string, own []core.Person) {
	if names == nil || len(own) == 0 {
		return
	}
	near := names.Near(t.eco, name)
	for _, p := range near[:min(len(near), maxNearLookups)] {
		if ctx.Err() != nil {
			return
		}
		if _, ok := cur.meta.DepInfo[p]; ok {
			continue
		}
		info := r.lookupDep(ctx, src, t, p, "")
		info.Popular = true
		if cur.meta.DepInfo == nil {
			cur.meta.DepInfo = map[string]*core.DepInfo{}
		}
		cur.meta.DepInfo[p] = info
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

// newestEntry is the highest version entries list, or "".
func newestEntry(entries []core.ChangelogEntry, scheme core.VersionScheme) string {
	v := ""
	for _, e := range entries {
		if scheme.Valid(e.Version) && (v == "" || scheme.Compare(e.Version, v) > 0) {
			v = e.Version
		}
	}
	return v
}
