// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run

import (
	"context"
	"fmt"
	"slices"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

// The --to keywords of PRD 5.3. Anything else is a version or an npm
// dist-tag.
const (
	ToLatest    = "latest"
	ToWanted    = "wanted"
	ToInstalled = "installed"
	ToList      = "list"
)

// candidate is the version to review and the two reference points the
// header prints beside it.
type candidate struct {
	Version string
	Latest  string // newest stable the source has (or its latest tag)
	Wanted  string // newest the constraint allows
}

// pickInput is what candidate selection works from.
type pickInput struct {
	Command    string
	Eco        core.Ecosystem
	Name       string
	From       string // installed version; "" for a package with none
	Constraint string // composer.json or package.json range
	To         string // --to, "" for the ecosystem's default
	Pre        bool
	Downgrade  bool // --allow-downgrade
	Explicit   bool // the user gave --to, so an older one is E19 not "no update"
}

// pickResult says what to review, or why nothing.
type pickResult struct {
	cand     candidate
	versions []string
	upToDate bool // the candidate is the installed version
	older    bool // the default candidate is older than what is installed
}

// defaultTo is the candidate a run picks without --to: what WordPress
// offers for plugins and themes, what the manifest's constraint allows
// for Composer and npm.
func defaultTo(eco core.Ecosystem) string {
	if eco == core.WPPlugin || eco == core.WPTheme {
		return ToLatest
	}
	return ToWanted
}

// pickCandidate resolves --to against the published versions (PRD 5.3).
func pickCandidate(ctx context.Context, src core.Source, in pickInput) (pickResult, error) {
	vs := core.Versions(in.Eco)
	if vs == nil {
		return pickResult{}, fmt.Errorf("%s version scheme %w", in.Eco, core.ErrNotLinked)
	}
	versions, err := src.Versions(ctx, in.Name)
	if err != nil {
		return pickResult{}, withCommand(err, in.Command)
	}
	var tags map[string]string
	if ts, ok := src.(core.TagSource); ok {
		tags, _ = ts.Tags(ctx, in.Name) // a source without tags falls back to the version list
	}
	published := func(v string) bool { return v != "" && slices.Contains(versions, v) }

	c := candidate{Latest: core.Newest(vs, versions, "", in.Pre)}
	if t := tags[ToLatest]; published(t) && (in.Pre || !vs.Prerelease(t)) {
		// WordPress's info API version and npm's dist-tags.latest are
		// what the package manager installs, even when a higher version
		// was published (a backport, a mistake the maintainers rolled
		// back).
		c.Latest = t
	}
	c.Wanted = c.Latest
	if in.Constraint != "" && in.Eco != core.WPPlugin && in.Eco != core.WPTheme {
		c.Wanted = core.Newest(vs, versions, in.Constraint, in.Pre)
		if t := tags[ToLatest]; in.Eco == core.NPM && published(t) {
			// npm installs dist-tags.latest when it satisfies the range,
			// even when a higher version also does.
			if ok, err := vs.Satisfies(t, in.Constraint); err == nil && ok && (in.Pre || !vs.Prerelease(t)) {
				c.Wanted = t
			}
		}
	}

	to := in.To
	if to == "" {
		to = defaultTo(in.Eco)
	}
	switch to {
	case ToLatest:
		c.Version = c.Latest
	case ToWanted:
		c.Version = c.Wanted
	case ToInstalled:
		c.Version = in.From
	default:
		switch {
		case published(to):
			c.Version = to
		case tags[to] != "" && published(tags[to]):
			c.Version = tags[to]
		default:
			err := versionMissing(in, to, versions, vs)
			if u, ok := src.(unpublishedSource); ok && vs.Valid(to) && u.Unpublished(ctx, in.Name, to) {
				err.What = fmt.Sprintf("%s %s was unpublished from %s", in.Name, to, sourceName(in.Eco))
			}
			return pickResult{}, err
		}
	}
	if c.Version == "" {
		return pickResult{}, versionMissing(in, to, versions, vs)
	}
	res := pickResult{cand: c, versions: versions}
	if in.From == "" || !vs.Valid(in.From) || !vs.Valid(c.Version) {
		return res, nil
	}
	switch cmp := vs.Compare(c.Version, in.From); {
	case cmp == 0:
		res.upToDate = true
	case cmp < 0 && !in.Downgrade:
		if !in.Explicit {
			res.older = true
			return res, nil
		}
		return pickResult{}, &core.Error{Code: core.EDowngrade, Exit: cli.ExitUsage, Command: in.Command,
			What: fmt.Sprintf("--to %s is older than the installed %s", c.Version, in.From),
			Hint: []string{"add --allow-downgrade to review a downgrade"}}
	}
	return res, nil
}

// unpublishedSource is a source that can tell a version that was
// published and then taken down (npm keeps it in the time map) from one
// that never existed.
type unpublishedSource interface {
	Unpublished(ctx context.Context, name, version string) bool
}

// versionMissing is E3: the asked version isn't published.
func versionMissing(in pickInput, to string, versions []string, vs core.VersionScheme) *core.Error {
	newest := core.Newest(vs, versions, "", false)
	if newest == "" {
		newest = core.Newest(vs, versions, "", true)
	}
	what := fmt.Sprintf("%s has no version %s on %s", in.Name, to, sourceName(in.Eco))
	if len(versions) == 0 {
		what = fmt.Sprintf("%s has no published version on %s", in.Name, sourceName(in.Eco))
	}
	e := &core.Error{Code: core.EVersionMissing, Exit: cli.ExitUsage, Command: in.Command, What: what}
	if newest != "" {
		e.Hint = []string{fmt.Sprintf("newest: %s · see them all: %s %s %s --to list", newest, cli.Name(), ecoCommand(in.Eco), in.Name)}
	}
	return e
}

// sourceName is how messages name an ecosystem's official source.
func sourceName(eco core.Ecosystem) string {
	switch eco {
	case core.WPPlugin, core.WPTheme:
		return "wordpress.org"
	case core.Composer:
		return "packagist.org"
	case core.NPM:
		return "registry.npmjs.org"
	}
	return string(eco)
}

// ecoCommand is the review command of an ecosystem.
func ecoCommand(eco core.Ecosystem) string {
	switch eco {
	case core.WPPlugin:
		return "plugin"
	case core.WPTheme:
		return "theme"
	}
	return string(eco)
}

// withCommand names the command in a *core.Error that a stage built
// without one, so every message reads "<program> <command>: ...".
func withCommand(err error, command string) error {
	if e, ok := err.(*core.Error); ok && e.Command == "" { //nolint:errorlint // only a bare *core.Error is adjusted; a wrapped one keeps its wrapper
		c := *e
		c.Command = command
		return &c
	}
	return err
}

// asCommand gives a command's error to command: a source names the
// review command its ecosystem belongs to ("plugin"), which is wrong
// when another command, such as allow, asked. A tool-wide error (no
// command) stays tool-wide.
func asCommand(err error, command string) error {
	if e, ok := err.(*core.Error); ok && e.Command != "" { //nolint:errorlint // only a bare *core.Error is adjusted; a wrapped one keeps its wrapper
		c := *e
		c.Command = command
		return &c
	}
	return withCommand(err, command)
}

// VersionList is one package's published versions, newest first, for
// --to list.
type VersionList struct {
	Eco      core.Ecosystem
	Name     string
	Versions []string
}

// sortNewestFirst orders versions newest first by the ecosystem's scheme;
// ones it can't read go last in their published order.
func sortNewestFirst(vs core.VersionScheme, versions []string) []string {
	out := slices.Clone(versions)
	slices.SortStableFunc(out, func(a, b string) int {
		va, vb := vs.Valid(a), vs.Valid(b)
		switch {
		case va && vb:
			return vs.Compare(b, a)
		case va:
			return -1
		case vb:
			return 1
		}
		return 0
	})
	return out
}

// ListVersions answers --to list: the published versions of each named
// package, newest first. It reads no inventory and fetches no archive.
func ListVersions(ctx context.Context, req Request) ([]VersionList, error) {
	r := &reviewer{req: req}
	if err := r.setup(); err != nil {
		return nil, err
	}
	src, vs := core.SourceFor(req.Eco, r.env), core.Versions(req.Eco)
	if src == nil || vs == nil {
		return nil, fmt.Errorf("%s source %w", req.Eco, core.ErrNotLinked)
	}
	var out []VersionList
	for _, name := range req.Names {
		versions, err := src.Versions(ctx, name)
		if err != nil {
			return nil, withCommand(err, req.Command)
		}
		out = append(out, VersionList{Eco: req.Eco, Name: name, Versions: sortNewestFirst(vs, versions)})
	}
	return out, nil
}
