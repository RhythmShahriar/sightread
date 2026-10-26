// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package npm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
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
	core.RegisterSource(core.NPM, func(env *core.Env) core.Source { return New(env) })
}

// command names the CLI command in errors.
const command = "npm"

// maxHistory is how many earlier releases Meta.History lists.
const maxHistory = 10

// Source is the npm source: the abbreviated packument for versions and
// dist-tags, the per-version document for scripts, publisher, dist and
// provenance and the full packument's time map for dates. The tarball is
// verified by SHA-512 and the registry signature against pinned keys.
// Private scopes go to their own registry. It implements core.Source
// and core.TagSource.
type Source struct {
	env    *core.Env
	lim    core.Limits
	base   string            // the public registry (or its mirror)
	scopes map[string]string // "@acme" to its registry
	pinned map[string]key

	mu   sync.Mutex
	pkgs map[string]*pkg

	keysMu sync.Mutex
	keys   map[string]keysResult // by registry base
}

// keysResult is one registry's keys answer, kept for the run.
type keysResult struct {
	keys map[string]key
	err  error
}

// pkg is what the run knows about one package.
type pkg struct {
	reg      string
	private  bool
	abbr     *packument
	notFound bool

	timesOnce sync.Once
	times     *times
}

// New returns the npm source for env.
func New(env *core.Env) *Source {
	s := &Source{env: env, lim: limits(env.Limits), pkgs: map[string]*pkg{}, scopes: map[string]string{}, keys: map[string]keysResult{}}
	s.base = base(env, core.BaseNPM)
	for k, v := range env.Bases {
		if scope, ok := strings.CutPrefix(k, core.BaseNPMScope); ok && strings.TrimSpace(v) != "" {
			s.scopes[strings.ToLower(scope)] = strings.TrimRight(strings.TrimSpace(v), "/")
		}
	}
	s.pinned = pinned(s.base, s.logf)
	return s
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

// Eco returns core.NPM.
func (s *Source) Eco() core.Ecosystem { return core.NPM }

// logf writes a -v note.
func (s *Source) logf(format string, args ...any) {
	if s.env.Log != nil {
		_, _ = fmt.Fprintf(s.env.Log, "  npm: "+format+"\n", args...)
	}
}

// registry returns the registry for name: its scope's when the scope is
// configured (private), else the public one. A private scope's names
// never reach the public registry (SR-8).
func (s *Source) registry(name string) (reg string, private bool) {
	if strings.HasPrefix(name, "@") {
		scope, _, _ := strings.Cut(name, "/")
		if r, ok := s.scopes[strings.ToLower(scope)]; ok {
			return r, true
		}
	}
	return s.base, false
}

// hostOf names a registry in messages.
func hostOf(reg string) string {
	if u, err := url.Parse(reg); err == nil && u.Host != "" {
		return u.Hostname()
	}
	return reg
}

// pathName is name as a registry path: "@scope%2fname" for a scoped
// name, as npm writes it.
func pathName(name string) string {
	if scope, rest, ok := strings.Cut(name, "/"); ok && strings.HasPrefix(scope, "@") {
		return "@" + url.PathEscape(scope[1:]) + "%2f" + url.PathEscape(rest)
	}
	return url.PathEscape(name)
}

// load reads the abbreviated packument once per run.
func (s *Source) load(ctx context.Context, name string) (*pkg, error) {
	s.mu.Lock()
	p, ok := s.pkgs[name]
	s.mu.Unlock()
	if ok {
		return p, nil
	}
	reg, private := s.registry(name)
	p = &pkg{reg: reg, private: private}
	var raw json.RawMessage
	err := s.env.Get.JSON(ctx, reg+"/"+pathName(name), &raw, fetch.KindVersions)
	switch {
	case fetch.StatusOf(err) == http.StatusNotFound:
		p.notFound = true
	case err != nil:
		return nil, fetch.Package{Command: command, Name: name}.Wrap(err)
	default:
		if p.abbr, err = decodePackument(raw); err != nil {
			return nil, fmt.Errorf("unexpected answer from %s for %s: %w", hostOf(reg), name, err)
		}
	}
	s.mu.Lock()
	s.pkgs[name] = p
	s.mu.Unlock()
	return p, nil
}

// timesOf reads the full packument's time map once per package: the
// abbreviated one has no publish dates. It can be large, so it is read
// only when a date or the unpublished state is needed, under the JSON
// cap; a failure leaves the dates out with a -v note.
func (s *Source) timesOf(ctx context.Context, name string, p *pkg) *times {
	p.timesOnce.Do(func() {
		var raw json.RawMessage
		if err := s.env.Get.JSON(ctx, p.reg+"/"+pathName(name), &raw, fetch.KindPackument); err != nil {
			s.logf("no publish dates for %s: %v", name, err)
			return
		}
		t, err := decodeTimes(raw)
		if err != nil {
			s.logf("no publish dates for %s: %v", name, err)
			return
		}
		p.times = t
	})
	return p.times
}

// valid lists the versions npm can order, oldest first.
func valid(abbr *packument) []string {
	var out []string
	for _, v := range abbr.Versions {
		if version.NPM.Valid(v) {
			out = append(out, v)
		}
	}
	slices.SortFunc(out, func(a, b string) int {
		if c := version.NPM.Compare(a, b); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
	return out
}

// Versions lists name's versions, oldest first. An unknown name is E2;
// a package whose every version was unpublished is E3.
func (s *Source) Versions(ctx context.Context, name string) ([]string, error) {
	p, err := s.load(ctx, name)
	if err != nil {
		return nil, err
	}
	if p.notFound {
		return nil, unknown(name, p.reg)
	}
	all := valid(p.abbr)
	if len(all) == 0 {
		if t := s.timesOf(ctx, name, p); t != nil && t.Unpublished {
			return nil, allUnpublished(name, p.reg)
		}
	}
	return all, nil
}

// Tags returns the packument's dist-tags unchanged: run takes latest for
// the wanted version and any other tag for --to <tag>, even when latest
// is lower than the highest version.
func (s *Source) Tags(ctx context.Context, name string) (map[string]string, error) {
	p, err := s.load(ctx, name)
	if err != nil {
		return nil, err
	}
	if p.notFound {
		return nil, unknown(name, p.reg)
	}
	return cloneTags(p.abbr.DistTags), nil
}

// Meta describes name at ref.Version (dist-tags latest when empty). A
// version that is not published is E3, saying so when it was
// unpublished.
func (s *Source) Meta(ctx context.Context, ref core.Ref) (*core.Meta, error) {
	p, err := s.load(ctx, ref.Name)
	if err != nil {
		return nil, err
	}
	if p.notFound {
		return nil, unknown(ref.Name, p.reg)
	}
	latest := p.abbr.DistTags["latest"]
	if ref.Version == "" {
		ref.Version = latest
	}
	all := valid(p.abbr)
	if ref.Version == "" || !slices.Contains(p.abbr.Versions, ref.Version) {
		return nil, s.missing(ctx, ref, p, latest)
	}
	var raw json.RawMessage
	err = s.env.Get.JSON(ctx, p.reg+"/"+pathName(ref.Name)+"/"+url.PathEscape(ref.Version), &raw, fetch.KindMeta)
	if fetch.StatusOf(err) == http.StatusNotFound {
		return nil, s.missing(ctx, ref, p, latest)
	}
	if err != nil {
		return nil, fetch.Package{Command: command, Name: ref.Name, Version: ref.Version}.Wrap(err)
	}
	doc, err := decodeVersion(raw)
	if err != nil {
		return nil, fmt.Errorf("unexpected answer from %s for %s %s: %w", hostOf(p.reg), ref.Name, ref.Version, err)
	}
	m := &core.Meta{
		Ref: ref, Repository: doc.Repository, Homepage: doc.Homepage, License: doc.License,
		Scripts: doc.Scripts, Deps: doc.Deps, DevDeps: doc.DevDeps, Private: p.private, Latest: latest,
		HasInstallScript: doc.HasInstallScript || installScript(doc.Scripts),
		Archive:          core.ArchiveRef{URL: doc.Tarball, Integrity: doc.Integrity, Shasum: doc.Shasum},
	}
	for _, sg := range doc.Signatures {
		m.Archive.Signatures = append(m.Archive.Signatures, core.NPMSignature{KeyID: sg.KeyID, Sig: sg.Sig})
	}
	if doc.NPMUser != nil {
		m.Publisher = &core.Person{Name: doc.NPMUser.Name, Login: doc.NPMUser.Name, Email: doc.NPMUser.Email}
	}
	for _, mt := range doc.Maintainers {
		m.Maintainers = append(m.Maintainers, core.Person{Name: mt.Name, Login: mt.Name, Email: mt.Email})
	}
	switch {
	case doc.Trusted:
		m.Provenance = "trusted-publisher"
	case doc.Attestations:
		m.Provenance = "slsa"
	}
	t := s.timesOf(ctx, ref.Name, p)
	if t != nil {
		m.Published = t.At[ref.Version]
	} else if ref.Version == latest {
		m.Published = p.abbr.Modified
	}
	m.History = history(all, ref.Version, t)
	return m, nil
}

// installScript reports whether npm runs scripts on install.
func installScript(scripts map[string]string) bool {
	for _, k := range []string{"preinstall", "install", "postinstall"} {
		if strings.TrimSpace(scripts[k]) != "" {
			return true
		}
	}
	return false
}

// history lists up to maxHistory versions before v, newest first, with
// their dates when the time map was read.
func history(all []string, v string, t *times) []core.Release {
	var out []core.Release
	for i := len(all) - 1; i >= 0 && len(out) < maxHistory; i-- {
		if version.NPM.Compare(all[i], v) >= 0 {
			continue
		}
		r := core.Release{Version: all[i]}
		if t != nil {
			r.Published = t.At[all[i]]
		}
		out = append(out, r)
	}
	return out
}

// missing is the E3 for a version the packument does not list: in npm's
// words when the time map shows it was published and then unpublished.
func (s *Source) missing(ctx context.Context, ref core.Ref, p *pkg, latest string) error {
	if latest == "" {
		latest = core.Newest(version.NPM, valid(p.abbr), "", false)
	}
	if ref.Version != "" {
		if t := s.timesOf(ctx, ref.Name, p); t != nil {
			if _, ok := t.At[ref.Version]; ok {
				return versionError(fmt.Sprintf("%s %s was unpublished from %s", ref.Name, ref.Version, hostOf(p.reg)), ref.Name, latest)
			}
			if t.Unpublished && len(p.abbr.Versions) == 0 {
				return allUnpublished(ref.Name, p.reg)
			}
		}
	}
	return versionError(fmt.Sprintf("%s has no version %s on %s", ref.Name, ref.Version, hostOf(p.reg)), ref.Name, latest)
}

// unknown is E2 for a name the registry does not know.
func unknown(name, reg string) *core.Error {
	hint := "if it is private, set its scope's registry under sources.npm.scopes in .sightread/config.yaml"
	if near := suggest(name); near != "" {
		hint = "did you mean " + near + "? " + hint
	}
	return &core.Error{
		Code: core.EUnknownPackage, Exit: cli.ExitUsage, Command: command,
		What: fmt.Sprintf("%s has no package %q", hostOf(reg), name),
		Hint: []string{hint},
	}
}

func suggest(name string) string {
	packs := core.GetDataPacks()
	if packs == nil || packs.Names() == nil {
		return ""
	}
	return cli.Suggest(name, packs.Names().Near(core.NPM, name))
}

// versionError is E3 with the newest version and the list command.
func versionError(what, name, newest string) *core.Error {
	list := "see them all: " + cli.Name() + " " + command + " " + name + " --to list"
	hint := list
	if newest != "" {
		hint = "newest: " + newest + " · " + list
	}
	return &core.Error{Code: core.EVersionMissing, Exit: cli.ExitUsage, Command: command, What: what, Hint: []string{hint}}
}

// allUnpublished is E3 for a package with nothing left to download.
func allUnpublished(name, reg string) *core.Error {
	return &core.Error{
		Code: core.EVersionMissing, Exit: cli.ExitUsage, Command: command,
		What: fmt.Sprintf("every version of %s was unpublished from %s", name, hostOf(reg)),
		Hint: []string{"there is nothing to download; review a copy you trust with --to-file <tgz>"},
	}
}

// The interfaces Source promises.
var (
	_ core.Source    = (*Source)(nil)
	_ core.TagSource = (*Source)(nil)
)
