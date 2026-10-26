// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package packagist

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/fetch"
	"github.com/RhythmShahriar/sightread/version"
)

func init() {
	core.RegisterSource(core.Composer, func(env *core.Env) core.Source { return New(env) })
}

// command names the CLI command in errors.
const command = "composer"

// publicHost is how messages name Packagist.
const publicHost = "packagist.org"

// maxHistory is how many earlier releases Meta.History lists.
const maxHistory = 10

// Source is the Composer source: Packagist's p2 metadata (tagged and
// ~dev), maintainers and abandoned flags from packagist.org, the dist
// archive verified by its shasum or pinned to its commit. Private
// Composer repositories from config come first. It implements core.Source and
// core.LocalVerifier.
type Source struct {
	env       *core.Env
	lim       core.Limits
	packagist string
	meta      string
	repos     []*repo

	mu   sync.Mutex
	pkgs map[string]*pkg // by lower-case name
}

// pkg is everything known about one package for the run.
type pkg struct {
	rels     []release // oldest first by the Composer scheme
	private  bool
	host     string // packagist.org or the private repository's host
	notFound bool

	metaOnce    sync.Once
	maintainers []core.Person
	abandoned   bool
}

// New returns the Composer source for env.
func New(env *core.Env) *Source {
	return &Source{
		env: env, lim: limits(env.Limits), pkgs: map[string]*pkg{},
		packagist: base(env, core.BasePackagist), meta: base(env, core.BasePackagistMeta),
		repos: repos(env),
	}
}

// base is env's base for key, or the official one, without a trailing
// slash.
func base(env *core.Env, key string) string {
	b := env.Bases[key]
	if b == "" {
		b = fetch.DefaultBases()[key]
	}
	return strings.TrimRight(b, "/")
}

// limits fills the limits a caller left at zero.
func limits(l core.Limits) core.Limits {
	d := core.DefaultLimits()
	if l.Download <= 0 {
		l.Download = d.Download
	}
	if l.Uncompressed <= 0 {
		l.Uncompressed = d.Uncompressed
	}
	if l.EntryStored <= 0 {
		l.EntryStored = d.EntryStored
	}
	if l.Entries <= 0 {
		l.Entries = d.Entries
	}
	if l.Ratio <= 0 {
		l.Ratio = d.Ratio
	}
	return l
}

// Eco returns core.Composer.
func (s *Source) Eco() core.Ecosystem { return core.Composer }

// logf writes a -v note.
func (s *Source) logf(format string, args ...any) {
	if s.env.Log != nil {
		_, _ = fmt.Fprintf(s.env.Log, "  composer: "+format+"\n", args...)
	}
}

// load returns what the private repositories or Packagist list for
// name. A package a private repository has is never looked up on
// Packagist, so its name can't be answered by a public namesake.
func (s *Source) load(ctx context.Context, name string) (*pkg, error) {
	key := strings.ToLower(name)
	s.mu.Lock()
	p, ok := s.pkgs[key]
	s.mu.Unlock()
	if ok {
		return p, nil
	}
	p, err := s.fetchPkg(ctx, key)
	if err != nil {
		return nil, fetch.Package{Command: command, Name: name}.Wrap(err)
	}
	s.mu.Lock()
	s.pkgs[key] = p
	s.mu.Unlock()
	return p, nil
}

func (s *Source) fetchPkg(ctx context.Context, name string) (*pkg, error) {
	for _, r := range s.repos {
		rels, found, err := r.lookup(ctx, s, name)
		if err != nil {
			return nil, err
		}
		if found {
			return &pkg{rels: sorted(rels), private: true, host: r.host}, nil
		}
	}
	tagged, ok, err := s.p2(ctx, s.packagist+"/p2/"+escapeName(name)+".json", name)
	if err != nil {
		return nil, err
	}
	if !ok {
		return &pkg{notFound: true, host: publicHost}, nil
	}
	dev, _, err := s.p2(ctx, s.packagist+"/p2/"+escapeName(name)+"~dev.json", name)
	if err != nil {
		return nil, err
	}
	return &pkg{rels: sorted(append(tagged, dev...)), host: publicHost}, nil
}

// escapeName escapes vendor and package for a URL path, keeping the
// slash between them.
func escapeName(name string) string {
	v, n, _ := strings.Cut(name, "/")
	return url.PathEscape(v) + "/" + url.PathEscape(n)
}

// sorted orders releases oldest first and drops a version listed twice
// (a tag that is also a branch name), keeping the first.
func sorted(rels []release) []release {
	seen := map[string]bool{}
	out := rels[:0:0]
	for _, r := range rels {
		if !seen[r.Version] {
			seen[r.Version] = true
			out = append(out, r)
		}
	}
	slices.SortStableFunc(out, func(a, b release) int {
		if c := version.Composer.Compare(a.Version, b.Version); c != 0 {
			return c
		}
		return strings.Compare(a.Version, b.Version)
	})
	return out
}

// Versions lists name's versions, oldest first, branches included
// (dev-main sorts before every numbered version). An unknown name is
// E2.
func (s *Source) Versions(ctx context.Context, name string) ([]string, error) {
	p, err := s.load(ctx, name)
	if err != nil {
		return nil, err
	}
	if p.notFound {
		return nil, unknown(name)
	}
	out := make([]string, len(p.rels))
	for i, r := range p.rels {
		out[i] = r.Version
	}
	return out, nil
}

// find returns the release for v: the same text, the same normalized
// version ("v1.2.3" for "1.2.3") or a branch whose branch-alias is v.
func (p *pkg) find(v string) (release, bool) {
	for _, r := range p.rels {
		if r.Version == v {
			return r, true
		}
	}
	if version.Composer.Valid(v) {
		for _, r := range p.rels {
			if version.Composer.Valid(r.Version) && version.Composer.Compare(r.Version, v) == 0 &&
				!strings.HasPrefix(r.Version, "dev-") {
				return r, true
			}
		}
	}
	for _, r := range p.rels {
		for _, alias := range r.BranchAlias {
			if alias == v {
				return r, true
			}
		}
	}
	return release{}, false
}

// Meta describes name at ref.Version (the newest stable release when
// empty). A version the source does not list is E3.
func (s *Source) Meta(ctx context.Context, ref core.Ref) (*core.Meta, error) {
	p, err := s.load(ctx, ref.Name)
	if err != nil {
		return nil, err
	}
	if p.notFound {
		return nil, unknown(ref.Name)
	}
	all := make([]string, len(p.rels))
	for i, r := range p.rels {
		all[i] = r.Version
	}
	latest := core.Newest(version.Composer, all, "", false)
	if ref.Version == "" {
		ref.Version = latest
	}
	rel, ok := p.find(ref.Version)
	if !ok || ref.Version == "" {
		return nil, noVersion(ref.Name, ref.Version, latest, p.host)
	}
	m := &core.Meta{
		Ref: ref, Published: rel.Time, Repository: rel.Repository, Homepage: rel.Homepage,
		License: rel.License, Type: rel.Type, Deps: rel.Require, DevDeps: rel.RequireDev,
		RequiresPHP: rel.Require["php"], Abandoned: rel.Abandoned, Private: p.private, Latest: latest,
		Archive: core.ArchiveRef{URL: rel.DistURL, Shasum: rel.Shasum, Reference: rel.Reference},
	}
	m.History = history(p.rels, rel.Version)
	if !p.private {
		s.maintainers(ctx, ref.Name, p)
		m.Maintainers = slices.Clone(p.maintainers)
		m.Abandoned = m.Abandoned || p.abandoned
	}
	return m, nil
}

// history lists up to maxHistory numbered releases before v, newest
// first, with their dates.
func history(rels []release, v string) []core.Release {
	var out []core.Release
	for i := len(rels) - 1; i >= 0 && len(out) < maxHistory; i-- {
		r := rels[i]
		if strings.HasPrefix(r.Version, "dev-") || version.Composer.Compare(r.Version, v) >= 0 {
			continue
		}
		out = append(out, core.Release{Version: r.Version, Published: r.Time})
	}
	return out
}

// maintainers reads the maintainers and the abandoned flag from
// packagist.org once per package (cached 12 hours). Packagist's p2 files
// do not carry them. A failure leaves both empty with a -v note: they
// feed owner-change, never integrity.
func (s *Source) maintainers(ctx context.Context, name string, p *pkg) {
	p.metaOnce.Do(func() {
		var doc struct {
			Package struct {
				Maintainers []struct {
					Name json.RawMessage `json:"name"`
				} `json:"maintainers"`
				Abandoned json.RawMessage `json:"abandoned"`
			} `json:"package"`
		}
		u := s.meta + "/packages/" + escapeName(strings.ToLower(name)) + ".json"
		if err := s.env.Get.JSON(ctx, u, &doc, fetch.KindMaintainers); err != nil {
			s.logf("no maintainers for %s: %v", name, err)
			return
		}
		for _, m := range doc.Package.Maintainers {
			if n := str(m.Name); n != "" {
				p.maintainers = append(p.maintainers, core.Person{Name: n, Login: n})
			}
		}
		slices.SortFunc(p.maintainers, func(a, b core.Person) int { return strings.Compare(a.Login, b.Login) })
		p.abandoned = abandoned(doc.Package.Abandoned)
	})
}

// unknown is E2 for a name Packagist does not know.
func unknown(name string) *core.Error {
	hint := "if it comes from a private repository, list it under sources.composer.repositories in .sightread/config.yaml"
	if near := suggest(name); near != "" {
		hint = "did you mean " + near + "? " + hint
	}
	return &core.Error{
		Code: core.EUnknownPackage, Exit: cli.ExitUsage, Command: command,
		What: fmt.Sprintf("%s has no package %q", publicHost, name),
		Hint: []string{hint},
	}
}

func suggest(name string) string {
	packs := core.GetDataPacks()
	if packs == nil || packs.Names() == nil {
		return ""
	}
	return cli.Suggest(name, packs.Names().Near(core.Composer, name))
}

// noVersion is E3.
func noVersion(name, v, newest, host string) *core.Error {
	list := "see them all: " + cli.Name() + " " + command + " " + name + " --to list"
	hint := list
	if newest != "" {
		hint = "newest: " + newest + " · " + list
	}
	return &core.Error{
		Code: core.EVersionMissing, Exit: cli.ExitUsage, Command: command,
		What: fmt.Sprintf("%s has no version %s on %s", name, v, host),
		Hint: []string{hint},
	}
}

// The interfaces Source promises.
var (
	_ core.Source        = (*Source)(nil)
	_ core.LocalVerifier = (*Source)(nil)
)
