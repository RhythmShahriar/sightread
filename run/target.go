// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run

import (
	"cmp"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

// target is one package to review, before and after its candidate is
// picked.
type target struct {
	eco         core.Ecosystem
	name        string
	fromVersion string // "" for a package a lockfile change adds
	constraint  string
	explicit    bool     // named on the command line
	members     []member // where it is installed; several for a fleet
	toFixed     string   // the version to review when it isn't picked (changes, --to-file)
	oldLock     *core.Installed
	newLock     *core.Installed
	toFile      string
	fromFile    string
	localFrom   string // the installed folder as the from side (premium plugin with --to-file)
	private     bool   // reviewed through a configured private registry
	rereview    bool   // --rereview: the installed version against the release before it
	same        bool   // the candidate is the installed version: only its bytes are checked

	versions []string // the source's version list, kept for History
	cand     candidate
	picked   bool    // there is an update to review
	skip     bool    // nothing to review: up to date, or the default is older
	failed   *result // picking failed; the entries to report instead
}

// member is one site a target is installed on.
type member struct {
	site      string // fleet site name; "" outside a fleet
	root      string // absolute site or project folder
	installed *core.Installed
}

// result is what reviewing one target left.
type result struct {
	update     *core.Update
	notChecked []core.NotChecked
	errs       []core.ErrorEntry
}

// installed returns the first member's installed entry, or nil.
func (t *target) installed() *core.Installed {
	for _, m := range t.members {
		if m.installed != nil {
			return m.installed
		}
	}
	return nil
}

func (r *reviewer) resolve(ctx context.Context, rep *core.Report) ([]*target, error) {
	if r.req.To == ToInstalled && (r.req.Changes != nil || len(r.req.Names) == 0) {
		return nil, &core.Error{Code: core.EBadFlag, Exit: cli.ExitUsage, Command: r.req.Command,
			What: "--to installed reviews one named package against --from",
			Hint: []string{fmt.Sprintf("name it: %s plugin <slug> --to installed --from <version>", cli.Name())}}
	}
	switch {
	case r.req.Changes != nil:
		return r.resolveChanges(ctx, rep)
	case len(r.req.Sites) > 0:
		return r.resolveSites(ctx, rep)
	case len(r.req.Names) > 0:
		return r.resolveNamed(ctx, rep)
	}
	return r.resolveSite(ctx, rep)
}

// readSite reads one site's inventory.
func (r *reviewer) readSite(ctx context.Context, req core.InventoryRequest) (*core.Site, string, error) {
	if r.inv == nil {
		return nil, "", fmt.Errorf("inventory %w", core.ErrNotLinked)
	}
	root, err := filepath.Abs(cmp.Or(req.Root, "."))
	if err != nil {
		return nil, "", err
	}
	req.Root = root
	req.Command, req.Log, req.Sources = r.req.Command, r.req.Log, &r.cfg.Sources
	site, err := r.inv.Read(ctx, req)
	if err != nil {
		return nil, root, withCommand(err, r.req.Command)
	}
	return site, root, nil
}

// resolveNamed reviews the packages named on the command line.
func (r *reviewer) resolveNamed(ctx context.Context, rep *core.Report) ([]*target, error) {
	q := r.req
	if len(q.Names) > 1 && (q.From != "" || q.FromFile != "" || q.ToFile != "") {
		return nil, &core.Error{Code: core.EBadFlag, Exit: cli.ExitUsage,
			What: "--from, --from-file and --to-file name one version, so give one package with them"}
	}
	for _, n := range q.Names {
		if _, err := core.ParseRef(string(q.Eco) + ":" + n); err != nil {
			return nil, &core.Error{Code: core.EUnknownPackage, Exit: cli.ExitUsage, Command: q.Command,
				What: strings.TrimPrefix(err.Error(), "package ")}
		}
	}
	installedTo := q.To == ToInstalled
	if installedTo && (q.From == "" || q.FromFile != "" || q.ToFile != "") {
		return nil, toInstalledNeedsFrom(q.Command, q.Eco, q.Names[0])
	}
	var site *core.Site
	root := ""
	if installedTo || (q.From == "" && q.FromFile == "") {
		ir := q.Inventory
		ir.Ecosystems = []core.Ecosystem{q.Eco}
		ir.Transitive = true // a named package may be a transitive one
		var err error
		if site, root, err = r.readSite(ctx, ir); err != nil {
			return nil, err
		}
		r.siteInfo(rep, site, root)
		rep.Warnings = append(rep.Warnings, site.Warnings...)
	}
	var out []*target
	for _, name := range q.Names {
		t := &target{eco: q.Eco, name: name, explicit: true, toFile: q.ToFile, fromFile: q.FromFile}
		switch {
		case installedTo:
			// The installed version is the candidate and --from the
			// older side: "is what I run already suspicious?" (PRD 5.3).
			inst := findInstalled(site, q.Eco, name)
			if inst == nil {
				if nc, listed := findNotChecked(site, q.Eco, name); listed {
					rep.NotChecked = append(rep.NotChecked, nc)
					continue
				}
				return nil, notInstalled(q.Command, q.Eco, name, root)
			}
			if inst.Private && !r.routable(inst) {
				rep.NotChecked = append(rep.NotChecked, r.privateEntry(ctx, inst))
				continue
			}
			if err := fromOlderThanInstalled(q.Command, q.Eco, q.From, inst.Ref.Version); err != nil {
				return nil, err
			}
			t.fromVersion, t.toFixed = q.From, inst.Ref.Version
			t.constraint, t.private = inst.Constraint, inst.Private
		case q.FromFile != "":
			t.fromVersion = cmp.Or(q.From, core.LocalVersion)
		case q.From != "":
			t.fromVersion = q.From
		default:
			inst := findInstalled(site, q.Eco, name)
			nc, listed := findNotChecked(site, q.Eco, name)
			switch {
			case inst == nil && listed && q.ToFile != "" && isWP(q.Eco):
				// A premium plugin: review the vendor's zip against the
				// copy on disk.
				t.fromVersion = nc.Version
				t.localFrom = filepath.Join(root, wpFolder(q.Eco), name)
			case inst == nil && listed:
				rep.NotChecked = append(rep.NotChecked, nc)
				continue
			case inst == nil:
				return nil, notInstalled(q.Command, q.Eco, name, root)
			case inst.Private && isWP(q.Eco) && q.ToFile != "":
				t.fromVersion = inst.Ref.Version
				t.localFrom = filepath.Join(root, filepath.FromSlash(inst.Path))
			case inst.Private && !r.routable(inst):
				rep.NotChecked = append(rep.NotChecked, r.privateEntry(ctx, inst))
				continue
			default:
				t.fromVersion, t.constraint, t.private = inst.Ref.Version, inst.Constraint, inst.Private
				t.members = []member{{root: root, installed: inst}}
				if inst.Lockfile != "" {
					t.oldLock = inst
				}
			}
		}
		if q.ToFile != "" {
			t.toFixed = localVersion(q.To)
		}
		out = append(out, t)
	}
	return out, nil
}

// resolveSite reviews every available update a folder holds (all; also
// composer and npm without names).
func (r *reviewer) resolveSite(ctx context.Context, rep *core.Report) ([]*target, error) {
	ir := r.req.Inventory
	if r.req.Eco != "" {
		ir.Ecosystems = []core.Ecosystem{r.req.Eco}
	} else if ir.MaxDepth == 0 {
		ir.MaxDepth = 6 // find a WordPress root below, as Tuner --discover does
	}
	site, root, err := r.readSite(ctx, ir)
	if err != nil {
		return nil, err
	}
	r.siteInfo(rep, site, root)
	byKey := map[string]*target{}
	var out []*target
	r.addSite(ctx, rep, site, member{root: root}, byKey, &out)
	return out, nil
}

// resolveSites reviews every site of a fleet file once per update:
// identical update pairs on several sites become one target with a
// member per site, so a shared plugin is fetched and analysed once.
func (r *reviewer) resolveSites(ctx context.Context, rep *core.Report) ([]*target, error) {
	rep.Target.Kind = "fleet"
	byKey := map[string]*target{}
	var out []*target
	for _, s := range r.req.Sites {
		rep.Target.Sites = append(rep.Target.Sites, s.Name)
		ir := s.Inventory
		if len(ir.Ecosystems) == 0 {
			ir.Ecosystems = r.req.Inventory.Ecosystems
		}
		ir.Transitive = r.req.Transitive
		if ir.MaxDepth == 0 {
			ir.MaxDepth = 6
		}
		site, root, err := r.readSite(ctx, ir)
		if err != nil {
			rep.NotChecked = append(rep.NotChecked, core.NotChecked{Name: s.Name, Reason: core.FetchFailed,
				Text: "couldn't read site " + s.Name + ": " + firstLine(err), Hint: "check its path, wp or tuner_report in the sites file"})
			continue
		}
		r.addSite(ctx, rep, site, member{site: s.Name, root: root}, byKey, &out)
	}
	return out, nil
}

// addSite turns a site's installed packages into targets, merging ones
// already seen on another site.
func (r *reviewer) addSite(ctx context.Context, rep *core.Report, site *core.Site, m member, byKey map[string]*target, out *[]*target) {
	for _, nc := range site.NotChecked {
		if !Selected(nc.Eco, nc.Name, r.req.Only, r.req.Skip) {
			continue
		}
		if m.site != "" {
			nc.Text += " (site " + m.site + ")"
		}
		if nc.Reason == core.NotWPOrg && isWP(nc.Eco) {
			if t := r.localFileTarget(nc, site, m); t != nil {
				*out = append(*out, t)
				continue
			}
		}
		rep.NotChecked = append(rep.NotChecked, nc)
	}
	rep.Warnings = append(rep.Warnings, site.Warnings...)
	for i := range site.Installed {
		inst := &site.Installed[i]
		eco, name := inst.Ref.Eco, inst.Ref.Name
		if r.req.Eco != "" && eco != r.req.Eco || !Selected(eco, name, r.req.Only, r.req.Skip) {
			continue
		}
		if inst.Private {
			switch {
			case isWP(eco):
				continue // the inventory lists it as not-wporg; local_files handled above
			case !r.routable(inst):
				rep.NotChecked = append(rep.NotChecked, r.privateEntry(ctx, inst))
				continue
			}
		}
		mm := m
		mm.installed = inst
		key := strings.Join([]string{string(eco), name, inst.Ref.Version, inst.Constraint}, "\x00")
		if t, ok := byKey[key]; ok && m.site != "" {
			t.members = append(t.members, mm)
			continue
		}
		t := &target{eco: eco, name: name, fromVersion: inst.Ref.Version, constraint: inst.Constraint,
			members: []member{mm}, private: inst.Private}
		if inst.Lockfile != "" {
			t.oldLock = inst
		}
		byKey[key] = t
		*out = append(*out, t)
	}
}

// resolveChanges reviews every package a lockfile change moves.
func (r *reviewer) resolveChanges(ctx context.Context, rep *core.Report) ([]*target, error) {
	if r.inv == nil {
		return nil, fmt.Errorf("inventory %w", core.ErrNotLinked)
	}
	cr := *r.req.Changes
	repo, err := filepath.Abs(cmp.Or(cr.Repo, "."))
	if err != nil {
		return nil, err
	}
	cr.Repo = repo
	cr.Sources = &r.cfg.Sources
	cs, err := r.inv.Changes(ctx, cr)
	if err != nil {
		return nil, withCommand(err, r.req.Command)
	}
	bumps := cs.Bumps
	rep.Target = core.Target{Path: repo, Kind: "changes"}
	rep.Warnings = append(rep.Warnings, cs.Warnings...)
	for _, nc := range cs.NotChecked {
		if Selected(nc.Eco, nc.Name, r.req.Only, r.req.Skip) {
			rep.NotChecked = append(rep.NotChecked, nc)
		}
	}
	var out []*target
	for i := range bumps {
		b := bumps[i]
		to := b.To
		eco, name := to.Ref.Eco, to.Ref.Name
		if !Selected(eco, name, r.req.Only, r.req.Skip) {
			continue
		}
		if to.Private && !r.routable(&to) {
			rep.NotChecked = append(rep.NotChecked, r.privateEntry(ctx, &to))
			continue
		}
		t := &target{eco: eco, name: name, constraint: to.Constraint, toFixed: to.Ref.Version,
			newLock: &to, private: to.Private, oldLock: b.From}
		if b.From != nil {
			t.fromVersion = b.From.Ref.Version
			t.members = []member{{root: repo, installed: b.From}}
		}
		out = append(out, t)
	}
	return out, nil
}

// siteInfo records what one target folder is in the report header.
func (r *reviewer) siteInfo(rep *core.Report, site *core.Site, root string) {
	rep.Target = core.Target{Path: root, Kind: site.Kind, WordPress: site.WordPress}
}

// routable reports whether a private package goes to a registry the
// config names, so it can be reviewed there without its name reaching a
// public host.
func (r *reviewer) routable(inst *core.Installed) bool {
	switch inst.Ref.Eco {
	case core.NPM:
		scope, _, ok := strings.Cut(inst.Ref.Name, "/")
		if !ok || !strings.HasPrefix(scope, "@") {
			return false
		}
		_, ok = r.cfg.Sources.NPM.Scopes[scope]
		return ok
	case core.Composer:
		host := hostOf(inst.Resolved)
		for _, repo := range r.cfg.Sources.Composer.Repositories {
			if host != "" && hostOf(repo) == host {
				return true
			}
		}
	}
	return false
}

// privateEntry is the Not checked entry of a private package no
// configured registry serves. With --check-confusion it also asks the
// public registry whether the name exists there.
func (r *reviewer) privateEntry(ctx context.Context, inst *core.Installed) core.NotChecked {
	if r.req.Options.CheckConfusion {
		if v := r.publicShadow(ctx, inst.Ref.Eco, inst.Ref.Name, inst.Ref.Version); v != "" {
			r.warn(fmt.Sprintf("dependency-confusion: %s is private here and %s publishes %s, a higher version",
				inst.Ref.Unversioned(), sourceName(inst.Ref.Eco), v))
		}
	}
	return core.NotChecked{Eco: inst.Ref.Eco, Name: inst.Ref.Name, Version: inst.Ref.Version, Reason: core.Private,
		Text: "private registry or repository", Hint: "set the registry in .sightread/config.yaml sources"}
}

// localFileTarget reviews a premium plugin against the newest vendor
// zip config local_files points at, or returns nil to leave it not
// checked.
func (r *reviewer) localFileTarget(nc core.NotChecked, site *core.Site, m member) *target {
	path, version := r.localFile(nc.Eco, nc.Name, nc.Version)
	if path == "" {
		return nil
	}
	dir := filepath.Join(m.root, wpFolder(nc.Eco), nc.Name)
	if inst := findInstalled(site, nc.Eco, nc.Name); inst != nil && inst.Path != "" {
		dir = filepath.Join(m.root, filepath.FromSlash(inst.Path))
	}
	return &target{eco: nc.Eco, name: nc.Name, fromVersion: nc.Version, toFile: path, toFixed: version, localFrom: dir}
}

// localFile finds the newest file matching config local_files for name
// whose {version} is above installed, by the WordPress version scheme.
func (r *reviewer) localFile(eco core.Ecosystem, name, installed string) (path, version string) {
	tmpl := r.cfg.LocalFiles[name]
	if tmpl == "" {
		tmpl = r.cfg.LocalFiles[string(eco)+":"+name]
	}
	before, after, ok := strings.Cut(tmpl, "{version}")
	vs := core.Versions(eco)
	if !ok || vs == nil {
		return "", ""
	}
	before, after = r.expandPath(before), filepath.FromSlash(after)
	matches, _ := filepath.Glob(globQuote(before) + "*" + globQuote(after))
	for _, mp := range matches {
		v, ok := strings.CutPrefix(mp, before)
		if !ok {
			continue
		}
		if v, ok = strings.CutSuffix(v, after); !ok || !vs.Valid(v) {
			continue
		}
		if installed != "" && vs.Valid(installed) && vs.Compare(v, installed) <= 0 {
			continue
		}
		if version == "" || vs.Compare(v, version) > 0 {
			path, version = mp, v
		}
	}
	return path, version
}

// expandPath expands a leading ~ and makes a relative template path
// relative to the project that holds .sightread/.
func (r *reviewer) expandPath(p string) string {
	p = filepath.FromSlash(p)
	if rest, ok := strings.CutPrefix(p, "~"+string(filepath.Separator)); ok {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, rest) + trailingSep(p)
		}
	}
	if !filepath.IsAbs(p) && r.cfgPath != "" {
		return filepath.Join(filepath.Dir(filepath.Dir(r.cfgPath)), p) + trailingSep(p)
	}
	return p
}

// trailingSep keeps the separator filepath.Join drops, so a template
// such as "zips/{version}.zip" still splits at the right place.
func trailingSep(p string) string {
	if strings.HasSuffix(p, string(filepath.Separator)) {
		return string(filepath.Separator)
	}
	return ""
}

// globQuote escapes glob characters in a literal part of a template.
// Windows paths use \ as the separator, where filepath.Match has no
// escape, so there they are left as they are.
func globQuote(s string) string {
	if runtime.GOOS == "windows" {
		return s
	}
	var b strings.Builder
	for _, c := range s {
		if strings.ContainsRune(`*?[\`, c) {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// localVersion is how a --to-file side is named: the --to value when
// it names a version, else core.LocalVersion until its files are read.
func localVersion(to string) string {
	switch to {
	case "", ToLatest, ToWanted, ToInstalled, ToList:
		return core.LocalVersion
	}
	return to
}

func findInstalled(site *core.Site, eco core.Ecosystem, name string) *core.Installed {
	if site == nil {
		return nil
	}
	for i := range site.Installed {
		if site.Installed[i].Ref.Eco == eco && site.Installed[i].Ref.Name == name {
			return &site.Installed[i]
		}
	}
	return nil
}

func findNotChecked(site *core.Site, eco core.Ecosystem, name string) (core.NotChecked, bool) {
	if site == nil {
		return core.NotChecked{}, false
	}
	i := slices.IndexFunc(site.NotChecked, func(n core.NotChecked) bool { return n.Eco == eco && n.Name == name })
	if i < 0 {
		return core.NotChecked{}, false
	}
	return site.NotChecked[i], true
}

func isWP(eco core.Ecosystem) bool { return eco == core.WPPlugin || eco == core.WPTheme }

// wpFolder is where WordPress keeps an ecosystem's packages.
func wpFolder(eco core.Ecosystem) string {
	if eco == core.WPTheme {
		return filepath.Join("wp-content", "themes")
	}
	return filepath.Join("wp-content", "plugins")
}

// notInstalled is E1 for a named package the inventory doesn't list.
// toInstalledNeedsFrom is the usage error of --to installed without
// --from: the installed version has nothing to be compared with.
func toInstalledNeedsFrom(command string, eco core.Ecosystem, name string) error {
	return &core.Error{Code: core.EBadFlag, Exit: cli.ExitUsage, Command: command,
		What: "--to installed reviews the installed version against an older one, so it needs --from",
		Hint: []string{fmt.Sprintf("give the older version: %s %s %s --to installed --from <version>", cli.Name(), ecoCommand(eco), name)}}
}

// fromOlderThanInstalled refuses --to installed when --from is not an
// older version than the one installed (E19): the review would compare
// nothing or run backwards.
func fromOlderThanInstalled(command string, eco core.Ecosystem, from, installed string) error {
	vs := core.Versions(eco)
	if vs == nil {
		return fmt.Errorf("%s version scheme %w", eco, core.ErrNotLinked)
	}
	if vs.Valid(from) && vs.Valid(installed) && vs.Compare(from, installed) < 0 {
		return nil
	}
	return &core.Error{Code: core.EDowngrade, Exit: cli.ExitUsage, Command: command,
		What: fmt.Sprintf("--from %s is not older than the installed %s", from, installed),
		Hint: []string{"--to installed reviews the installed version against an older one: give that with --from"}}
}

func notInstalled(command string, eco core.Ecosystem, name, root string) error {
	e := &core.Error{Code: core.ENothingInstalled, Exit: cli.ExitUsage, Command: command,
		What: fmt.Sprintf("no installed %s under %s", name, root)}
	if isWP(eco) {
		e.Hint = []string{`name the site with --path /var/www/site, read it with --wp "wp --path=..." or give the version: --from <version>`}
	} else {
		e.Hint = []string{"name the project with --path <dir> or give the version: --from <version>"}
	}
	return e
}
