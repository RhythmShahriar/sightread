// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/inventory/gitref"
)

// ChangeSet is what a lockfile change moves: one Bump per package whose
// version, integrity, resolved URL or reference changed and per added
// package. Removed packages are not listed: nothing new runs.
type ChangeSet struct {
	// Base is the ref the working tree was compared with: the --base
	// value, origin/$GITHUB_BASE_REF or the merge-base commit. Empty for
	// --before and --after.
	Base       string
	Bumps      []core.Bump
	NotChecked []core.NotChecked
	Warnings   []string
}

// ChangesOptions tune ReadChanges.
type ChangesOptions struct {
	// Options is the lockfile readers' config. A nil NPMRC means the
	// .npmrc next to each npm lockfile and ~/.npmrc.
	Options
	// Show reads a file at a ref; nil means gitref.Show.
	Show core.GitShow
	// Commit checks the base names a commit; nil means gitref.Commit.
	Commit func(ctx context.Context, repo, ref string) (string, error)
	// Env reads the environment for GITHUB_BASE_REF; nil means os.Getenv.
	Env func(string) string
}

// beforeAfterHint is the way out of every git problem.
const beforeAfterHint = "give --before <old lock> --after <new lock> instead"

// ReadChanges compares lockfiles: req.Before against req.After when
// both are set (no git needed), else each lockfile at the base ref
// against the working tree. The lockfiles are req.Lockfiles, or every
// composer.lock and npm lockfile in the tree (up to DefaultMaxDepth
// folders down, the first npm lockfile of each folder).
func ReadChanges(ctx context.Context, req core.ChangesRequest, opt ChangesOptions) (*ChangeSet, error) {
	if req.Before != "" || req.After != "" {
		return beforeAfter(req, opt)
	}
	repo := req.Repo
	if repo == "" {
		repo = "."
	}
	cs := &ChangeSet{}
	locks, err := changeLockfiles(ctx, repo, req.Lockfiles, cs)
	if err != nil {
		return nil, err
	}
	if len(locks) == 0 {
		return cs, nil // only unreadable lockfiles, listed as Not checked
	}
	show, commit := opt.Show, opt.Commit
	if show == nil {
		show = gitref.Show
	}
	if commit == nil {
		commit = gitref.Commit
	}
	base := req.Base
	if base == "" {
		if base, err = gitref.ResolveBase(ctx, repo, opt.Env); err != nil {
			return nil, gitError(err, repo, locks[0], "the merge base")
		}
	} else if err := gitref.ValidRef(base); err != nil {
		return nil, &core.Error{Code: core.EBadFlag, Exit: 2, What: "--base: " + err.Error()}
	}
	if _, err := commit(ctx, repo, base); err != nil {
		return nil, gitError(err, repo, locks[0], base)
	}
	cs.Base = base
	for _, rel := range locks {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		newPkgs, err := readLockAt(ctx, repo, rel, "", show, opt.Options)
		if err != nil {
			return nil, err
		}
		oldPkgs, err := readLockAt(ctx, repo, rel, base, show, opt.Options)
		switch {
		case errors.Is(err, gitref.ErrNotAtRef):
			cs.Warnings = append(cs.Warnings, fmt.Sprintf("%s is not at %s, so every package in it counts as added", rel, base))
			oldPkgs = &Packages{}
		case err != nil:
			return nil, gitError(err, repo, rel, base)
		}
		cs.Warnings = append(cs.Warnings, newPkgs.Warnings...)
		bumps, nc := lockBumps(oldPkgs.Installed, newPkgs.Installed)
		cs.Bumps = append(cs.Bumps, bumps...)
		cs.NotChecked = append(cs.NotChecked, nc...)
	}
	return cs, nil
}

// beforeAfter compares two lockfiles the user named.
func beforeAfter(req core.ChangesRequest, opt ChangesOptions) (*ChangeSet, error) {
	if req.Before == "" || req.After == "" {
		return nil, &core.Error{Code: core.EBadFlag, Exit: 2, What: "--before and --after go together: the old and the new lockfile"}
	}
	kb, ka := lockKind(req.Before), lockKind(req.After)
	// The --after file names the format. --before may be a copy saved
	// under any name (git show main:package-lock.json > old.json), so
	// only two known names that disagree are refused.
	if ka == "" {
		return nil, unsupportedLock(req.After)
	}
	if kb != "" && kb != ka {
		return nil, &core.Error{Code: core.EBadFlag, Exit: 2,
			What: fmt.Sprintf("--before %s and --after %s are different kinds of lockfile", filepath.Base(req.Before), filepath.Base(req.After)),
			Hint: []string{"give the same lockfile from before and after the change"}}
	}
	cs := &ChangeSet{}
	format := filepath.Base(req.After)
	read := func(flag, path string) (*Packages, error) {
		data, err := readAll(path, maxLockBytes)
		if err != nil {
			return nil, &core.Error{Code: core.EBadFlag, Exit: 2, What: fmt.Sprintf("%s %s: %s", flag, path, errText(err)), Err: err}
		}
		dir := filepath.Dir(path)
		var manifest []byte
		// A file with a lockfile's name sits in its project, so the
		// manifest next to it is its own. Next to a renamed copy it is
		// most likely some other project's.
		if lockKind(path) != "" {
			if manifest, err = readAll(filepath.Join(dir, manifestFor(req.After)), maxLockBytes); err != nil {
				manifest = nil
			}
		}
		return parseLock(filepath.ToSlash(path), format, data, manifest, npmrcOptions(opt.Options, dir))
	}
	oldPkgs, err := read("--before", req.Before)
	if err != nil {
		return nil, err
	}
	newPkgs, err := read("--after", req.After)
	if err != nil {
		return nil, err
	}
	cs.Warnings = append(cs.Warnings, newPkgs.Warnings...)
	cs.Bumps, cs.NotChecked = lockBumps(oldPkgs.Installed, newPkgs.Installed)
	return cs, nil
}

// lockKind is "composer" or "npm" for a lockfile name Sightread reads,
// else "".
func lockKind(path string) string {
	base := filepath.Base(filepath.FromSlash(path))
	switch {
	case base == ComposerLock:
		return "composer"
	case containsString(NPMLockfiles, base):
		return "npm"
	}
	return ""
}

// manifestFor is the manifest next to a lockfile.
func manifestFor(lock string) string {
	if lockKind(lock) == "composer" {
		return ComposerJSON
	}
	return "package.json"
}

// npmrcOptions sets NPMRC to the .npmrc in dir and ~/.npmrc when the
// caller left it nil.
func npmrcOptions(opt Options, dir string) Options {
	if opt.NPMRC == nil {
		opt.NPMRC = []string{filepath.Join(dir, ".npmrc")}
		if home, err := os.UserHomeDir(); err == nil {
			opt.NPMRC = append(opt.NPMRC, filepath.Join(home, ".npmrc"))
		}
	}
	return opt
}

// parseLock reads one lockfile's bytes. name labels the entries; format
// is the base name that picks the reader.
func parseLock(name, format string, data, manifest []byte, opt Options) (*Packages, error) {
	var p *Packages
	var err error
	if format == ComposerLock {
		p, err = ParseComposer(name, data, manifest, nil, opt)
	} else {
		p, err = parseNPMLockAs(name, format, data, manifest, opt)
	}
	if err != nil {
		return nil, lockError(name, err)
	}
	return p, nil
}

// lockError is E8 for a lockfile that can't be parsed. An error that is
// already a *core.Error (bun.lockb) is kept.
func lockError(name string, err error) error {
	var ce *core.Error
	if errors.As(err, &ce) {
		return err
	}
	return &core.Error{Code: core.EUnsupportedLock, Exit: 2,
		What: fmt.Sprintf("%s can't be read: %s", name, strings.TrimPrefix(errText(err), name+": ")),
		Hint: []string{"run your package manager once to write it again"}, Err: err}
}

// readLockAt reads the lockfile rel (slash separated, relative to repo)
// at ref with its manifest, or from the working tree when ref is empty.
func readLockAt(ctx context.Context, repo, rel, ref string, show core.GitShow, opt Options) (*Packages, error) {
	dir := filepath.Join(repo, filepath.FromSlash(filepath.Dir(rel)))
	manifestRel := filepath.ToSlash(filepath.Join(filepath.Dir(rel), manifestFor(rel)))
	var data, manifest []byte
	var err error
	if ref == "" {
		if data, err = readAll(filepath.Join(repo, filepath.FromSlash(rel)), maxLockBytes); err != nil {
			return nil, &core.Error{Code: core.ENoLockfile, Exit: 2, What: fmt.Sprintf("can't read %s: %s", rel, errText(err)), Err: err}
		}
		if manifest, err = readAll(filepath.Join(repo, filepath.FromSlash(manifestRel)), maxLockBytes); err != nil {
			manifest = nil
		}
	} else {
		if data, err = show(ctx, repo, ref, rel); err != nil {
			return nil, err
		}
		if len(data) > maxLockBytes {
			return nil, fmt.Errorf("%s at %s: %w", rel, ref, errTooBig)
		}
		if manifest, err = show(ctx, repo, ref, manifestRel); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				return nil, err
			}
			manifest = nil
		}
	}
	return parseLock(rel, filepath.Base(rel), data, manifest, npmrcOptions(opt, dir))
}

// changeLockfiles returns the lockfiles to compare, relative to repo and
// slash separated. bun.lockb found on the walk is Not checked; named
// with --lockfile it is E8.
func changeLockfiles(ctx context.Context, repo string, named []string, cs *ChangeSet) ([]string, error) {
	if len(named) > 0 {
		var out []string
		for _, n := range named {
			rel, err := repoRel(repo, n)
			if err != nil {
				return nil, &core.Error{Code: core.EBadFlag, Exit: 2, What: fmt.Sprintf("--lockfile %s: %s", n, err)}
			}
			if filepath.Base(rel) == bunBinaryLock {
				e := bunLockbCoreError()
				e.Command = "" // the caller names its own command
				return nil, e
			}
			if lockKind(rel) == "" {
				return nil, unsupportedLock(n)
			}
			out = append(out, rel)
		}
		return out, nil
	}
	var out []string
	err := walkLockDirs(ctx, repo, func(dir string) {
		rel, _ := filepath.Rel(repo, dir)
		rel = filepath.ToSlash(rel)
		join := func(name string) string {
			if rel == "." {
				return name
			}
			return rel + "/" + name
		}
		if isFile(filepath.Join(dir, ComposerLock)) {
			out = append(out, join(ComposerLock))
		}
		name, err := FindNPMLock(dir)
		switch {
		case err == nil:
			out = append(out, join(name))
		case !errors.Is(err, ErrNoLockfile):
			cs.NotChecked = append(cs.NotChecked, bunLockbNotChecked(join(bunBinaryLock)))
		}
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 && len(cs.NotChecked) == 0 {
		return nil, noLockfileError("", repo, append([]string{ComposerLock}, NPMLockfiles...))
	}
	return out, nil
}

// walkLockDirs calls fn for every folder at or below root, at most
// DefaultMaxDepth down, skipping node_modules, vendor, .git and links.
func walkLockDirs(ctx context.Context, root string, fn func(dir string)) error {
	var walk func(dir string, depth int) error
	walk = func(dir string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		fn(dir)
		if depth == DefaultMaxDepth {
			return nil
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			if dir == root {
				return err
			}
			return nil
		}
		for _, e := range entries {
			if !e.IsDir() || skipDirs[e.Name()] {
				continue
			}
			if err := walk(filepath.Join(dir, e.Name()), depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(root, 0)
}

// isFile reports whether path is a regular file (links followed).
func isFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// repoRel is path relative to repo, slash separated; path may be
// absolute or relative to repo but must lie inside it.
func repoRel(repo, path string) (string, error) {
	p := path
	if filepath.IsAbs(p) {
		absRepo, err := filepath.Abs(repo)
		if err != nil {
			return "", err
		}
		if p, err = filepath.Rel(absRepo, p); err != nil {
			return "", err
		}
	}
	p = filepath.Clean(p)
	if !filepath.IsLocal(p) {
		return "", errors.New("not inside the repository folder")
	}
	return filepath.ToSlash(p), nil
}

// unsupportedLock is E8 for a file that is not a lockfile Sightread
// reads.
func unsupportedLock(name string) error {
	return &core.Error{Code: core.EUnsupportedLock, Exit: 2,
		What: fmt.Sprintf("%s is not a lockfile Sightread reads", filepath.Base(name)),
		Hint: []string{"want " + ComposerLock + ", " + strings.Join(NPMLockfiles, ", ")}}
}

// bunLockbNotChecked lists a bun.lockb found on the way as Not checked
// unsupported-lock with the E8 text.
func bunLockbNotChecked(rel string) core.NotChecked {
	e := bunLockbCoreError()
	return core.NotChecked{Eco: core.NPM, Name: rel, Reason: core.UnsupportedLock, Text: e.What, Hint: e.Hint[0]}
}

// gitError turns a git problem into the message the user sees: what is
// missing and that --before and --after need no git. These have no E
// code (lead decision); they exit 2.
func gitError(err error, repo, file, ref string) error {
	var ce *core.Error
	switch {
	case errors.As(err, &ce):
		return err
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, gitref.ErrNoGit):
		return &core.Error{Exit: 2, What: fmt.Sprintf("git is needed to read %s at %s and wasn't found", file, ref),
			Hint: []string{"install git, or " + beforeAfterHint}, Err: err}
	case errors.Is(err, gitref.ErrNotRepo):
		return &core.Error{Exit: 2, What: fmt.Sprintf("%s is not in a git repository, so there is no base to compare with", repo),
			Hint: []string{beforeAfterHint}, Err: err}
	case errors.Is(err, gitref.ErrNoBase):
		return &core.Error{Exit: 2, What: "found no base to compare with: HEAD and origin/HEAD share no commit, or origin/HEAD is not set",
			Hint: []string{"give --base <ref> (for example --base origin/main), or " + beforeAfterHint}, Err: err}
	case errors.Is(err, gitref.ErrUnknownRef):
		return &core.Error{Exit: 2, What: fmt.Sprintf("%s is not a commit in this repository", ref),
			Hint: []string{"fetch it first (git fetch origin), or " + beforeAfterHint}, Err: err}
	}
	return &core.Error{Exit: 2, What: fmt.Sprintf("couldn't read %s at %s: %s", file, ref, errText(err)),
		Hint: []string{beforeAfterHint}, Err: err}
}

// lockBumps compares the packages of one lockfile before and after a
// change. A package is bumped when its version, integrity, resolved URL
// or reference changed, or when it is new; From is the old entry of the
// same name it replaces (nil for a new package). A bump to a source
// other than the registry is Not checked vcs, unless it moves a package
// off the registry: that pair stays a bump so the lockfile source change
// is reported.
func lockBumps(old, cur []core.Installed) ([]core.Bump, []core.NotChecked) {
	same := func(a, b *core.Installed) bool {
		return a.Ref.Eco == b.Ref.Eco && sameName(a, b) && a.Ref.Version == b.Ref.Version &&
			a.Integrity == b.Integrity && a.Resolved == b.Resolved && a.Reference == b.Reference
	}
	byName := map[string][]int{}
	for i := range old {
		k := nameKey(&old[i])
		byName[k] = append(byName[k], i)
	}
	stillThere := make([]bool, len(old))
	unchanged := make([]bool, len(cur))
	for j, c := range cur {
		for _, i := range byName[nameKey(&c)] {
			if same(&old[i], &c) {
				stillThere[i], unchanged[j] = true, true
			}
		}
	}
	var bumps []core.Bump
	var nc []core.NotChecked
	listed := map[string]bool{}
	for j := range cur {
		if unchanged[j] {
			continue
		}
		to := cur[j]
		var cands []*core.Installed
		for _, i := range byName[nameKey(&to)] {
			if !stillThere[i] {
				cands = append(cands, &old[i])
			}
		}
		var from *core.Installed
		if p := pickFrom(cands, &to); p != nil {
			c := *p
			from = &c
		}
		if !onRegistry(&to) && (from == nil || !onRegistry(from)) {
			k := to.Ref.String()
			if !listed[k] {
				listed[k] = true
				nc = append(nc, notChecked(to.Ref.Eco, to.Ref.Name, to.Ref.Version, core.VCS))
			}
			continue
		}
		bumps = append(bumps, core.Bump{From: from, To: to})
	}
	return bumps, nc
}

// onRegistry reports whether in comes from the package registry.
func onRegistry(in *core.Installed) bool {
	return in.ResolvedKind == "" || in.ResolvedKind == core.ResolvedRegistry
}

// nameKey groups entries of one package. Composer names are case
// insensitive.
func nameKey(in *core.Installed) string {
	if in.Ref.Eco == core.Composer {
		return string(in.Ref.Eco) + ":" + strings.ToLower(in.Ref.Name)
	}
	return string(in.Ref.Eco) + ":" + in.Ref.Name
}

// sameName compares names the way nameKey groups them.
func sameName(a, b *core.Installed) bool { return nameKey(a) == nameKey(b) }

// pickFrom chooses the old entry a new one replaces: the same version
// (only its integrity, URL or reference changed), else the newest older
// version, else the oldest of the rest (a downgrade). With no version
// scheme linked, versions sort as text.
func pickFrom(cands []*core.Installed, to *core.Installed) *core.Installed {
	if len(cands) == 0 {
		return nil
	}
	cmp := func(a, b string) int { return strings.Compare(a, b) }
	if vs := core.Versions(to.Ref.Eco); vs != nil {
		cmp = vs.Compare
	}
	for _, c := range cands {
		if c.Ref.Version == to.Ref.Version {
			return c
		}
	}
	sorted := append([]*core.Installed(nil), cands...)
	sort.SliceStable(sorted, func(i, j int) bool { return cmp(sorted[i].Ref.Version, sorted[j].Ref.Version) < 0 })
	var best *core.Installed
	for _, c := range sorted {
		if cmp(c.Ref.Version, to.Ref.Version) < 0 {
			best = c
		}
	}
	if best == nil {
		best = sorted[0]
	}
	return best
}
