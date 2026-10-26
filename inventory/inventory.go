// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/inventory/gitref"
)

func init() { core.SetInventory(&Reader{}) }

// Reader is the inventory stage: it implements core.Inventory. The zero
// value reads with the default Options.
type Reader struct {
	// Options configure the lockfile readers. Private scopes and
	// repositories from config are applied by run, which knows the
	// config; the reader only marks entries Private.
	Options Options
}

// The site kinds of core.Site.Kind.
const (
	KindWordPress = "wordpress"
	KindComposer  = "composer"
	KindNPM       = "npm"
	KindMixed     = "mixed"
)

// Read finds what req.Root holds: a WordPress site (at the root or up to
// req.MaxDepth folders down; read through req.WP or req.TunerReport
// instead when set), composer.lock and the npm lockfile at the root, or
// the lockfiles req.Lockfiles names. req.Ecosystems narrows what is read;
// without req.Transitive only packages the manifest names are kept for
// Composer and npm.
//
// The site is shaped for review: npm and Composer entries from git,
// paths or tarballs are left out of Installed (they are Not checked
// vcs). Private entries stay in Installed without a private Not
// checked entry, since run decides from the config whether a private
// registry serves them. Installed.Path and Lockfile are relative to
// req.Root and slash separated.
//
// Nothing found is E1 for plugins, themes or everything and E4 when
// only npm or Composer was asked for.
func (rd *Reader) Read(ctx context.Context, req core.InventoryRequest) (*core.Site, error) {
	root := req.Root
	if root == "" {
		root = "."
	}
	sel := selection(req.Ecosystems)
	site := &core.Site{Root: root}
	var kinds []string
	remoteWP := len(req.WP) > 0 || req.TunerReport != ""
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		if !remoteWP || !sel.wp {
			why := "no such folder"
			if err == nil {
				why = "not a folder"
			} else if !errors.Is(err, fs.ErrNotExist) {
				why = errText(err)
			}
			return nil, nothingFound(sel, root, why, req.MaxDepth)
		}
	}
	if sel.wp {
		wp, err := rd.readWP(ctx, req, root)
		if err != nil {
			return nil, err
		}
		if wp != nil {
			kinds = append(kinds, KindWordPress)
			site.WordPress = wp.WordPress
			site.Warnings = append(site.Warnings, wp.Warnings...)
			for _, in := range wp.Installed {
				if sel.has(in.Ref.Eco) {
					site.Installed = append(site.Installed, in)
				}
			}
			for _, nc := range wp.NotChecked {
				if nc.Eco == "" || sel.has(nc.Eco) {
					site.NotChecked = append(site.NotChecked, nc)
				}
			}
		}
	}
	lockSets, err := rd.readLocks(req, root, sel, site)
	if err != nil {
		return nil, err
	}
	for _, ls := range lockSets {
		if !slices.Contains(kinds, ls.kind) {
			kinds = append(kinds, ls.kind)
		}
		addPackages(site, ls.pkgs, req.Transitive)
	}
	switch len(kinds) {
	case 0:
		if len(site.NotChecked) > 0 {
			// Only bun.lockb was there: it is listed, so the run says why.
			site.Kind = KindNPM
			return site, nil
		}
		return nil, nothingFound(sel, root, "", req.MaxDepth)
	case 1:
		site.Kind = kinds[0]
	default:
		site.Kind = KindMixed
	}
	return site, nil
}

// Changes reads what a lockfile change moves (ReadChanges).
func (rd *Reader) Changes(ctx context.Context, req core.ChangesRequest) (*core.ChangeSet, error) {
	return ReadChanges(ctx, req, ChangesOptions{Options: rd.Options})
}

// ResolveBase is the ref Changes compares repo with when the request
// names none (gitref.ResolveBase), so run can read the allow entries
// and the config at that same ref.
func (rd *Reader) ResolveBase(ctx context.Context, repo string) (string, error) {
	return gitref.ResolveBase(ctx, repo, nil)
}

// LocalTree reads an installed folder into a tree (see LocalTree).
func (rd *Reader) LocalTree(ctx context.Context, dir string, blobs core.BlobStore, lim core.Limits) (*core.Tree, error) {
	return LocalTree(ctx, dir, blobs, lim)
}

// ecoSelection is which ecosystems a Read covers.
type ecoSelection struct {
	plugin, theme, wp, composer, npm bool
	only                             core.Ecosystem // the one ecosystem asked for, or ""
}

// selection reads req.Ecosystems; empty means all of them.
func selection(ecos []core.Ecosystem) ecoSelection {
	if len(ecos) == 0 {
		return ecoSelection{plugin: true, theme: true, wp: true, composer: true, npm: true}
	}
	var s ecoSelection
	for _, e := range ecos {
		switch e {
		case core.WPPlugin:
			s.plugin = true
		case core.WPTheme:
			s.theme = true
		case core.Composer:
			s.composer = true
		case core.NPM:
			s.npm = true
		}
	}
	s.wp = s.plugin || s.theme
	if len(ecos) == 1 {
		s.only = ecos[0]
	}
	return s
}

// has reports whether eco is selected.
func (s ecoSelection) has(eco core.Ecosystem) bool {
	switch eco {
	case core.WPPlugin:
		return s.plugin
	case core.WPTheme:
		return s.theme
	case core.Composer:
		return s.composer
	case core.NPM:
		return s.npm
	}
	return false
}

// readWP reads the WordPress part: through the --wp command, a Tuner
// report or the first WordPress root found under root. It returns nil
// when there is no site on disk.
func (rd *Reader) readWP(ctx context.Context, req core.InventoryRequest, root string) (*core.Site, error) {
	switch {
	case len(req.WP) > 0:
		return ReadWP(ctx, req.WP, WPOptions{})
	case req.TunerReport != "":
		return ReadTuner(req.TunerReport)
	}
	roots, err := FindWordPress(ctx, root, req.MaxDepth)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, nil // root was checked; an unreadable root has no site
	}
	if len(roots) == 0 {
		return nil, nil
	}
	// The shallowest root is the site; a copy further down (a backup,
	// a staging folder) is named so the user can point at it.
	slices.SortStableFunc(roots, func(a, b string) int {
		return strings.Count(a, string(filepath.Separator)) - strings.Count(b, string(filepath.Separator))
	})
	site, err := ReadWordPress(ctx, roots[0])
	if err != nil {
		return nil, err
	}
	prefix := relSlash(root, roots[0])
	for i := range site.Installed {
		site.Installed[i].Path = joinRel(prefix, site.Installed[i].Path)
		site.Installed[i].Lockfile = joinRel(prefix, site.Installed[i].Lockfile)
	}
	if len(roots) > 1 {
		var others []string
		for _, r := range roots[1:] {
			others = append(others, relSlash(root, r))
		}
		site.Warnings = append(site.Warnings, fmt.Sprintf("found %d WordPress sites under %s: read %s, not %s; name one with --path to read another",
			len(roots), root, displayRel(prefix), strings.Join(others, ", ")))
	}
	return site, nil
}

// lockSet is one lockfile read for a site.
type lockSet struct {
	kind string // KindComposer or KindNPM
	pkgs *Packages
}

// readLocks reads the lockfiles at root (or those req.Lockfiles names)
// for the selected ecosystems. bun.lockb is E8 when npm alone was asked
// for and Not checked unsupported-lock otherwise.
func (rd *Reader) readLocks(req core.InventoryRequest, root string, sel ecoSelection, site *core.Site) ([]lockSet, error) {
	type want struct{ dir, name string }
	var wants []want
	if len(req.Lockfiles) > 0 {
		for _, l := range req.Lockfiles {
			rel, err := repoRel(root, l)
			if err != nil {
				return nil, &core.Error{Code: core.EBadFlag, Exit: 2, What: fmt.Sprintf("lockfile %s: %s", l, err)}
			}
			base := path.Base(rel)
			if base != bunBinaryLock && lockKind(rel) == "" {
				return nil, unsupportedLock(l)
			}
			wants = append(wants, want{path.Dir(rel), base})
		}
	} else {
		if sel.composer && isFile(filepath.Join(root, ComposerLock)) {
			wants = append(wants, want{".", ComposerLock})
		}
		if sel.npm {
			name, err := FindNPMLock(root)
			switch {
			case err == nil:
				wants = append(wants, want{".", name})
			case !errors.Is(err, ErrNoLockfile):
				wants = append(wants, want{".", bunBinaryLock})
			}
		}
	}
	var out []lockSet
	for _, w := range wants {
		kind := lockKind(w.name)
		if w.name == bunBinaryLock {
			kind = KindNPM
		}
		if !sel.has(core.Ecosystem(kind)) {
			continue
		}
		dir := filepath.Join(root, filepath.FromSlash(w.dir))
		var p *Packages
		var err error
		switch {
		case w.name == bunBinaryLock && sel.only != core.NPM:
			site.NotChecked = append(site.NotChecked, bunLockbNotChecked(joinRel(w.dir, bunBinaryLock)))
			continue
		case w.name == bunBinaryLock:
			e := bunLockbCoreError()
			e.Command = ""
			return nil, e
		case kind == KindComposer:
			p, err = ReadComposer(dir, rd.Options)
		default:
			p, err = readNPMFile(dir, w.name, rd.Options)
		}
		if err != nil {
			return nil, lockError(joinRel(w.dir, w.name), err)
		}
		if w.dir != "." {
			rebase(p, w.dir)
		}
		out = append(out, lockSet{kind: kind, pkgs: p})
	}
	return out, nil
}

// addPackages adds one lockfile's packages to the site, shaped for
// review (see Read).
func addPackages(site *core.Site, p *Packages, transitive bool) {
	site.Warnings = append(site.Warnings, p.Warnings...)
	key := func(name, version string) string { return name + "@" + version }
	kept := map[string]bool{}
	offRegistry := map[string]bool{}
	for _, in := range p.Installed {
		k := key(in.Ref.Name, in.Ref.Version)
		if !transitive && !in.Direct {
			continue
		}
		if !onRegistry(&in) {
			offRegistry[k] = true
			continue
		}
		kept[k] = true
		site.Installed = append(site.Installed, in)
	}
	for _, nc := range p.NotChecked {
		k := key(nc.Name, nc.Version)
		switch {
		case !kept[k] && !offRegistry[k]:
			// a transitive package left out without --transitive
		case nc.Reason == core.Private && kept[k]:
			// run lists it unless a configured registry serves it
		default:
			site.NotChecked = append(site.NotChecked, nc)
		}
	}
}

// rebase makes a lockfile's paths relative to the site root when the
// lockfile sits in the folder dir below it.
func rebase(p *Packages, dir string) {
	p.Lockfile = joinRel(dir, p.Lockfile)
	for i := range p.Installed {
		p.Installed[i].Lockfile = joinRel(dir, p.Installed[i].Lockfile)
		if p.Installed[i].Path != "" {
			p.Installed[i].Path = joinRel(dir, p.Installed[i].Path)
		}
	}
}

// relSlash is target relative to base, slash separated ("." for base).
func relSlash(base, target string) string {
	r, err := filepath.Rel(base, target)
	if err != nil {
		return filepath.ToSlash(target)
	}
	return filepath.ToSlash(r)
}

// joinRel joins slash paths, dropping a "." prefix.
func joinRel(prefix, p string) string {
	if prefix == "." || prefix == "" {
		return p
	}
	if p == "" {
		return prefix
	}
	return prefix + "/" + p
}

// displayRel names a folder relative to the root for a message.
func displayRel(rel string) string {
	if rel == "." {
		return "the folder itself"
	}
	return rel
}

// The E1 hints (PRD 10; --from <version> because the version is not
// known when nothing was found).
const (
	wpHint  = `name the site with --path /var/www/site, read it with --wp "wp --path=..." or give the version: --from <version>`
	allHint = `name the site or project folder, read a site with --wp "wp --path=..." or give a Tuner report with --from-tuner <report.json>`
)

// nothingFound is E1 or E4 for a folder without anything the request
// asked for. why replaces the usual reason when root itself can't be
// read; depth is the WordPress search depth (0 for the default).
func nothingFound(sel ecoSelection, root, why string, depth int) error {
	if depth <= 0 {
		depth = DefaultMaxDepth
	}
	wpOnly := sel.wp && !sel.composer && !sel.npm
	if !sel.wp && sel.composer != sel.npm {
		looked := NPMLockfiles
		if sel.composer {
			looked = []string{ComposerLock}
		}
		e := noLockfileError("", root, looked)
		if why != "" {
			e.What = fmt.Sprintf("no lockfile in %s (%s)", root, why)
		}
		return e
	}
	e := &core.Error{Code: core.ENothingInstalled, Exit: 2, Hint: []string{allHint}}
	switch {
	case wpOnly && why != "":
		e.What = fmt.Sprintf("no WordPress site under %s (%s)", root, why)
	case wpOnly:
		e.What = fmt.Sprintf("no WordPress site under %s (looked %d folders down for wp-includes/version.php and wp-content)", root, depth)
	case why != "":
		e.What = fmt.Sprintf("nothing installed found under %s (%s)", root, why)
	default:
		e.What = fmt.Sprintf("nothing installed found under %s (looked for a WordPress site up to %d folders down, composer.lock and npm lockfiles)", root, depth)
	}
	if wpOnly {
		e.Hint = []string{wpHint}
	}
	return e
}
