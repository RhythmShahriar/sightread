// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
)

// NPMLockfiles are the npm lockfiles inventory reads, in the order it
// looks for them; the first one found is read.
var NPMLockfiles = []string{"npm-shrinkwrap.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"}

// bunBinaryLock is Bun's binary lockfile, which Sightread can't read.
const bunBinaryLock = "bun.lockb"

// ErrNoLockfile is ReadNPM's error when dir holds none of NPMLockfiles.
var ErrNoLockfile = errors.New("no npm lockfile")

// npmRegistryHosts are the public registry and yarn's name for it.
var npmRegistryHosts = []string{"registry.npmjs.org", "registry.yarnpkg.com"}

// npmEntry is one package a lockfile pins, before it is checked and
// turned into a core.Installed.
type npmEntry struct {
	name, version string
	resolved      string // URL or spec as written; "" means the registry
	kind          string // set by a parser that knows better than the URL (berry)
	integrity     string
	constraint    string
	path          string // install folder, relative to the project
	line          int
	dev, direct   bool
	devKnown      bool // the lock says whether it is dev
	link          bool // a workspace package or a link: never a registry package
}

// npmManifest is what inventory reads from the root package.json.
type npmManifest struct {
	deps map[string]string // every root range by name
	dev  map[string]bool   // names only in devDependencies
}

// parseNPMManifest reads package.json: dependencies, devDependencies,
// optionalDependencies and peerDependencies of the root.
func parseNPMManifest(b []byte) (*npmManifest, error) {
	var raw struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
	}
	if err := json.Unmarshal(trimBOM(b), &raw); err != nil {
		return nil, fmt.Errorf("package.json: %w", err)
	}
	m := &npmManifest{deps: map[string]string{}, dev: map[string]bool{}}
	for name, r := range raw.DevDependencies {
		m.deps[name], m.dev[name] = r, true
	}
	// A name in both lists is a production dependency, as npm treats it.
	for _, deps := range []map[string]string{raw.PeerDependencies, raw.OptionalDependencies, raw.Dependencies} {
		for name, r := range deps {
			m.deps[name] = r
			delete(m.dev, name)
		}
	}
	return m, nil
}

// npmSources is where npm packages come from: the registry hosts and
// the private scopes.
type npmSources struct {
	hosts      map[string]bool   // registry hosts; entries from these are registry
	scopes     map[string]string // every private scope to its registry
	configured map[string]bool   // scopes config routes to their registry
}

// newNPMSources joins the config with the @scope:registry lines of the
// .npmrc files.
func newNPMSources(opt Options, npmrc map[string]string) *npmSources {
	s := &npmSources{hosts: map[string]bool{}, scopes: map[string]string{}, configured: map[string]bool{}}
	for _, h := range npmRegistryHosts {
		s.hosts[h] = true
	}
	if h := urlHost(opt.NPMRegistry); h != "" {
		s.hosts[h] = true
	}
	for scope, reg := range npmrc {
		s.scopes[scope] = reg
	}
	for scope, reg := range opt.NPMScopes {
		scope = strings.ToLower(scope)
		s.scopes[scope], s.configured[scope] = reg, true
	}
	for _, reg := range s.scopes {
		if h := urlHost(reg); h != "" {
			s.hosts[h] = true
		}
	}
	return s
}

// scopeOf is the "@scope" of a scoped name, or "".
func scopeOf(name string) string {
	if !strings.HasPrefix(name, "@") {
		return ""
	}
	scope, _, _ := strings.Cut(name, "/")
	return strings.ToLower(scope)
}

// tarballPath matches the path of a tarball URL.
var tarballPath = regexp.MustCompile(`(?i)\.(tgz|tar\.gz|tar)$`)

// classifyNPM says where a lock entry comes from, from its resolved
// URL or spec as the lock wrote it.
func (s *npmSources) classify(resolved string) string {
	r := strings.TrimSpace(resolved)
	lower := strings.ToLower(r)
	switch {
	case r == "":
		return core.ResolvedRegistry
	case hasAnyPrefix(lower, "git+", "git:", "git@", "github:", "gitlab:", "bitbucket:", "gist:", "ssh://"):
		return core.ResolvedGit
	case hasAnyPrefix(lower, "file:", "link:", "portal:", "workspace:", "exec:", "./", "../", "/", "~/"):
		return core.ResolvedFile
	case hasAnyPrefix(lower, "https://", "http://"):
		host := urlHost(r)
		switch {
		case s.hosts[host]:
			return core.ResolvedRegistry
		case host == "codeload.github.com" || host == "github.com" || host == "gitlab.com" || host == "bitbucket.org":
			return core.ResolvedGit
		}
		u := r
		if i := strings.IndexAny(u, "?#"); i >= 0 {
			u = u[:i]
		}
		if tarballPath.MatchString(u) {
			return core.ResolvedTarball
		}
		return core.ResolvedForeign
	}
	return core.ResolvedForeign
}

// hasAnyPrefix reports whether s starts with one of the prefixes.
func hasAnyPrefix(s string, prefixes ...string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// finishNPM turns parsed entries into Packages: it applies the root
// package.json, checks names, classifies sources, marks private scopes
// and merges entries that pin the same package twice.
func finishNPM(lockName string, entries []npmEntry, m *npmManifest, src *npmSources, out *Packages) *Packages {
	if out == nil {
		out = &Packages{}
	}
	out.Lockfile = lockName
	type key struct{ name, version, resolved string }
	seen := map[key]int{}
	for _, e := range entries {
		if e.link {
			continue // a workspace package is the project's own code
		}
		if !validRef(core.NPM, e.name, e.version) {
			out.warn("skipped a %s entry with a name or version Sightread can't use: %q %q", lockName, clipText(e.name), clipText(e.version))
			continue
		}
		if m != nil {
			if r, ok := m.deps[e.name]; ok && e.direct {
				e.constraint = r
				if !e.devKnown {
					e.dev = m.dev[e.name]
				}
			}
		}
		k := key{e.name, e.version, e.resolved}
		if i, ok := seen[k]; ok {
			// The same release installed in two folders is one review.
			in := &out.Installed[i]
			in.Direct = in.Direct || e.direct
			in.Dev = in.Dev && e.dev
			if e.direct && in.Constraint == "" {
				in.Constraint = e.constraint
			}
			continue
		}
		kind := e.kind
		if kind == "" {
			kind = src.classify(e.resolved)
		}
		in := core.Installed{
			Ref:          core.Ref{Eco: core.NPM, Name: e.name, Version: e.version},
			Path:         e.path,
			Lockfile:     lockName,
			LockLine:     e.line,
			Integrity:    e.integrity,
			Resolved:     cleanURL(e.resolved),
			ResolvedKind: kind,
			Constraint:   e.constraint,
			Direct:       e.direct,
			Dev:          e.dev,
		}
		if scope := scopeOf(e.name); scope != "" {
			if _, ok := src.scopes[scope]; ok {
				in.Private = true
			}
		}
		seen[k] = len(out.Installed)
		out.Installed = append(out.Installed, in)
	}
	slices.SortStableFunc(out.Installed, func(a, b core.Installed) int {
		return cmp.Or(strings.Compare(a.Ref.Name, b.Ref.Name), strings.Compare(a.Ref.Version, b.Ref.Version), strings.Compare(a.Path, b.Path))
	})
	for _, in := range out.Installed {
		switch {
		case in.Private && !src.configured[scopeOf(in.Ref.Name)]:
			out.NotChecked = append(out.NotChecked, notChecked(core.NPM, in.Ref.Name, in.Ref.Version, core.Private))
		case in.ResolvedKind != core.ResolvedRegistry:
			out.NotChecked = append(out.NotChecked, notChecked(core.NPM, in.Ref.Name, in.Ref.Version, lockReason(&in)))
		}
	}
	return out
}

// npmrcScope matches an @scope:registry= line.
var npmrcScope = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._~-]*):registry\s*=\s*(\S+)\s*$`)

// readNPMRC reads only the @scope:registry= lines of the .npmrc files.
// Every other line, tokens included, is skipped without being kept, so
// no credential can reach a value or an error. A file that can't be
// read is skipped; the warning names the file, never its contents.
func readNPMRC(files []string, out *Packages) map[string]string {
	scopes := map[string]string{}
	for _, f := range files {
		b, err := readAll(f, 1<<20)
		if err != nil {
			if !os.IsNotExist(err) {
				out.warn("couldn't read %s for scope registries: %s", f, errText(err))
			}
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			m := npmrcScope.FindStringSubmatch(strings.TrimSpace(line))
			if m == nil {
				continue
			}
			reg := strings.Trim(m[2], `"'`)
			if strings.Contains(reg, "${") {
				reg = "" // an environment reference: the scope is private, its host unknown here
			}
			scopes[strings.ToLower(m[1])] = cleanURL(reg)
		}
	}
	return scopes
}

// ParseNPMLock reads one npm lockfile's bytes. lockName is its path as
// reports show it; its base name picks the format. manifest is the root
// package.json, or nil.
func ParseNPMLock(lockName string, data, manifest []byte, opt Options) (*Packages, error) {
	return parseNPMLockAs(lockName, filepath.Base(filepath.FromSlash(lockName)), data, manifest, opt)
}

// parseNPMLockAs is ParseNPMLock with the format named apart from the
// label: format is a lockfile base name such as yarn.lock. `changes
// --before` takes a copy saved under any name, so its format comes from
// the --after file.
func parseNPMLockAs(lockName, format string, data, manifest []byte, opt Options) (*Packages, error) {
	out := &Packages{}
	var npmrc map[string]string
	if opt.NPMRC != nil {
		npmrc = readNPMRC(opt.NPMRC, out)
	}
	return parseNPMLock(lockName, format, data, manifest, newNPMSources(opt, npmrc), out)
}

// parseNPMLock is parseNPMLockAs with the sources already joined.
func parseNPMLock(lockName, format string, data, manifest []byte, src *npmSources, out *Packages) (*Packages, error) {
	var m *npmManifest
	if manifest != nil {
		var err error
		if m, err = parseNPMManifest(manifest); err != nil {
			return nil, err
		}
	}
	data = trimBOM(data)
	var entries []npmEntry
	var err error
	switch format {
	case "npm-shrinkwrap.json", "package-lock.json":
		entries, err = parsePackageLock(data, m)
	case "pnpm-lock.yaml":
		entries, err = parsePnpmLock(data)
	case "yarn.lock":
		entries, err = parseYarnLock(data, m)
	case "bun.lock":
		entries, err = parseBunLock(data)
	case bunBinaryLock:
		return nil, bunLockbError()
	default:
		return nil, fmt.Errorf("%s: not an npm lockfile Sightread reads (want one of %s)", lockName, strings.Join(NPMLockfiles, ", "))
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", lockName, err)
	}
	return finishNPM(lockName, entries, m, src, out), nil
}

// bunLockbError is E8: Bun's binary lockfile.
func bunLockbError() error { return bunLockbCoreError() }

// bunLockbCoreError is bunLockbError as a *core.Error, for callers that
// adjust it or copy its text.
func bunLockbCoreError() *core.Error {
	return &core.Error{
		Code:    core.EUnsupportedLock,
		Exit:    2,
		Command: "npm",
		What:    "bun.lockb is Bun's binary lockfile, which Sightread can't read",
		Hint:    []string{"run bun install --save-text-lockfile once to write bun.lock"},
	}
}

// FindNPMLock returns the lockfile ReadNPM would read in dir: the first
// of NPMLockfiles there. With none it returns E8 when bun.lockb is
// there, else ErrNoLockfile.
func FindNPMLock(dir string) (string, error) {
	for _, name := range NPMLockfiles {
		if fi, err := os.Stat(filepath.Join(dir, name)); err == nil && !fi.IsDir() {
			return name, nil
		}
	}
	if _, err := os.Stat(filepath.Join(dir, bunBinaryLock)); err == nil {
		return "", bunLockbError()
	}
	return "", ErrNoLockfile
}

// ReadNPM reads the first npm lockfile in dir with the package.json
// next to it and the .npmrc scope lines (opt.NPMRC, or dir/.npmrc and
// ~/.npmrc when that is nil).
func ReadNPM(dir string, opt Options) (*Packages, error) {
	name, err := FindNPMLock(dir)
	if err != nil {
		return nil, err
	}
	return readNPMFile(dir, name, opt)
}

// readNPMFile is ReadNPM for the lockfile name in dir.
func readNPMFile(dir, name string, opt Options) (*Packages, error) {
	data, err := readAllWithin(dir, filepath.Join(dir, name), maxLockBytes)
	if err != nil {
		return nil, err
	}
	out := &Packages{}
	manifest, err := readAllWithin(dir, filepath.Join(dir, "package.json"), maxLockBytes)
	switch {
	case errors.Is(err, errOutsideRoot):
		out.warn("skipped package.json: %s", errOutsideRoot)
	case err != nil && !os.IsNotExist(err):
		return nil, err
	}
	files := opt.NPMRC
	if files == nil {
		files = []string{filepath.Join(dir, ".npmrc")}
		if home, err := os.UserHomeDir(); err == nil {
			files = append(files, filepath.Join(home, ".npmrc"))
		}
	}
	p, err := parseNPMLock(name, name, data, manifest, newNPMSources(opt, readNPMRC(files, out)), out)
	if err != nil {
		return nil, err
	}
	if manifest == nil {
		p.warn("%s has no package.json next to it, so no npm package counts as direct", name)
	}
	return p, nil
}

// splitNameVersion splits "name@version" at the last "@" past the
// first byte, so a scope's "@" stays in the name.
func splitNameVersion(s string) (name, version string, ok bool) {
	i := strings.LastIndexByte(s, '@')
	if i <= 0 {
		return s, "", false
	}
	return s[:i], s[i+1:], true
}

// splitSpec splits a "name@range" specifier at the first "@" past the
// first byte: the range may hold an "@" of its own (npm:real@^1).
func splitSpec(s string) (name, rng string, ok bool) {
	i := strings.IndexByte(s[min(1, len(s)):], '@')
	if i < 0 {
		return s, "", false
	}
	i += min(1, len(s))
	return s[:i], s[i+1:], true
}
