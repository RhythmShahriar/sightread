// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
)

// The Composer files inventory reads.
const (
	ComposerLock      = "composer.lock"
	ComposerJSON      = "composer.json"
	composerInstalled = "composer/installed.json" // under the vendor folder
)

// packagistHosts are the hosts of Packagist itself.
var packagistHosts = map[string]bool{"packagist.org": true, "repo.packagist.org": true}

// composerPkg is one composer.lock entry, with only the fields
// inventory reads.
type composerPkg struct {
	Name            string       `json:"name"`
	Version         string       `json:"version"`
	Source          *composerSrc `json:"source"`
	Dist            *composerSrc `json:"dist"`
	NotificationURL string       `json:"notification-url"`
}

// composerSrc is a lock entry's source or dist.
type composerSrc struct {
	Type      string `json:"type"`
	URL       string `json:"url"`
	Reference string `json:"reference"`
}

// composerLockFile is composer.lock.
type composerLockFile struct {
	Packages    []composerPkg `json:"packages"`
	PackagesDev []composerPkg `json:"packages-dev"`
}

// composerRepo is one entry of composer.json repositories.
type composerRepo struct {
	Type  string
	URL   string
	host  string
	names []string // a package repository's inline package names
}

// composerManifest is what inventory reads from composer.json.
type composerManifest struct {
	require    map[string]string // lower-case name to constraint
	requireDev map[string]string
	repos      []composerRepo
	packagist  bool // false when composer.json turns Packagist off
	vendorDir  string
}

// parseComposerManifest reads composer.json. Repositories may be a list
// or an object keyed by name; an entry may be false
// ({"packagist.org": false}).
func parseComposerManifest(b []byte) (*composerManifest, error) {
	var raw struct {
		Require      map[string]string `json:"require"`
		RequireDev   map[string]string `json:"require-dev"`
		Repositories json.RawMessage   `json:"repositories"`
		Config       struct {
			VendorDir string `json:"vendor-dir"`
		} `json:"config"`
	}
	if err := json.Unmarshal(trimBOM(b), &raw); err != nil {
		return nil, fmt.Errorf("composer.json: %w", err)
	}
	m := &composerManifest{require: lowerKeys(raw.Require), requireDev: lowerKeys(raw.RequireDev), packagist: true, vendorDir: "vendor"}
	if vd := path.Clean(filepath.ToSlash(raw.Config.VendorDir)); raw.Config.VendorDir != "" && localSlashPath(vd) {
		m.vendorDir = vd
	}
	var entries []json.RawMessage
	switch r := bytes.TrimSpace(raw.Repositories); {
	case len(r) == 0 || string(r) == "null":
	case r[0] == '[':
		if err := json.Unmarshal(r, &entries); err != nil {
			return nil, fmt.Errorf("composer.json repositories: %w", err)
		}
	case r[0] == '{':
		var named map[string]json.RawMessage
		if err := json.Unmarshal(r, &named); err != nil {
			return nil, fmt.Errorf("composer.json repositories: %w", err)
		}
		for name, e := range named {
			if strings.EqualFold(name, "packagist.org") || strings.EqualFold(name, "packagist") {
				if string(bytes.TrimSpace(e)) == "false" {
					m.packagist = false
					continue
				}
			}
			entries = append(entries, e)
		}
	default:
		return nil, errors.New("composer.json repositories: want a list or an object")
	}
	for _, e := range entries {
		if string(bytes.TrimSpace(e)) == "false" {
			continue
		}
		var r struct {
			Type      string          `json:"type"`
			URL       string          `json:"url"`
			Package   json.RawMessage `json:"package"`
			Packagist *bool           `json:"packagist.org"`
		}
		if json.Unmarshal(e, &r) != nil {
			continue // a shape Composer itself would refuse
		}
		if r.Packagist != nil && !*r.Packagist {
			m.packagist = false
			continue
		}
		repo := composerRepo{Type: strings.ToLower(r.Type), URL: r.URL, host: urlHost(r.URL)}
		if repo.Type == "package" {
			repo.names = inlinePackageNames(r.Package)
		}
		if repo.Type == "composer" && packagistHosts[repo.host] {
			continue // Packagist named explicitly is still Packagist
		}
		m.repos = append(m.repos, repo)
	}
	return m, nil
}

// inlinePackageNames lists the names a "package" repository defines: one
// object or a list of them.
func inlinePackageNames(b json.RawMessage) []string {
	var one struct {
		Name string `json:"name"`
	}
	if json.Unmarshal(b, &one) == nil && one.Name != "" {
		return []string{strings.ToLower(one.Name)}
	}
	var many []struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(b, &many)
	var out []string
	for _, p := range many {
		if p.Name != "" {
			out = append(out, strings.ToLower(p.Name))
		}
	}
	return out
}

// lowerKeys copies m with lower-case keys: Composer names are not case
// sensitive.
func lowerKeys(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[strings.ToLower(k)] = v
	}
	return out
}

// localSlashPath reports whether a cleaned slash path stays inside the
// folder it is relative to.
func localSlashPath(p string) bool {
	return p != "" && p != "." && p != ".." && !strings.HasPrefix(p, "../") && !strings.HasPrefix(p, "/") &&
		!strings.Contains(p, ":") && !strings.Contains(p, `\`)
}

// parseInstalledJSON reads vendor/composer/installed.json, Composer 1's
// list or Composer 2's {"packages": [...]}, into lower-case name to the
// install folder relative to the project. A path that leaves the
// project is dropped.
func parseInstalledJSON(b []byte, vendorDir string) (map[string]string, error) {
	type pkg struct {
		Name        string `json:"name"`
		InstallPath string `json:"install-path"`
	}
	var pkgs []pkg
	b = bytes.TrimSpace(trimBOM(b))
	if len(b) > 0 && b[0] == '[' {
		if err := json.Unmarshal(b, &pkgs); err != nil {
			return nil, fmt.Errorf("installed.json: %w", err)
		}
	} else {
		var v2 struct {
			Packages []pkg `json:"packages"`
		}
		if err := json.Unmarshal(b, &v2); err != nil {
			return nil, fmt.Errorf("installed.json: %w", err)
		}
		pkgs = v2.Packages
	}
	out := map[string]string{}
	for _, p := range pkgs {
		name := strings.ToLower(p.Name)
		if name == "" {
			continue
		}
		dir := path.Join(vendorDir, name) // Composer 1 had no install-path
		if ip := filepath.ToSlash(p.InstallPath); ip != "" {
			if strings.HasPrefix(ip, "/") || strings.Contains(ip, ":") {
				continue // absolute: outside the project
			}
			dir = path.Join(vendorDir, "composer", ip)
		}
		if localSlashPath(dir) {
			out[name] = dir
		}
	}
	return out, nil
}

// ParseComposer reads composer.lock bytes. manifest is composer.json
// and installed vendor/composer/installed.json; either may be nil.
// lockName is the lockfile's path as reports show it.
func ParseComposer(lockName string, lock, manifest, installed []byte, opt Options) (*Packages, error) {
	lock = trimBOM(lock)
	var lf composerLockFile
	if err := json.Unmarshal(lock, &lf); err != nil {
		return nil, fmt.Errorf("%s: %w", lockName, err)
	}
	out := &Packages{Lockfile: lockName}
	m := &composerManifest{packagist: true, vendorDir: "vendor"}
	if manifest != nil {
		var err error
		if m, err = parseComposerManifest(manifest); err != nil {
			return nil, err
		}
	}
	var paths map[string]string
	if installed != nil {
		var err error
		if paths, err = parseInstalledJSON(installed, m.vendorDir); err != nil {
			out.warn("couldn't read %s/%s, so drift is not checked: %v", m.vendorDir, composerInstalled, err)
		}
	}
	lines := map[string]int{}
	if err := scanJSONKeys(lock, func(p []string, line int) {
		if len(p) == 3 && (p[0] == "packages" || p[0] == "packages-dev") && p[2] == "name" {
			lines[p[0]+"/"+p[1]] = line
		}
	}); err != nil {
		return nil, fmt.Errorf("%s: %w", lockName, err)
	}
	configured := map[string]bool{}
	for _, r := range opt.ComposerRepos {
		if h := urlHost(r); h != "" {
			configured[h] = true
		}
	}
	for _, sec := range []struct {
		key  string
		pkgs []composerPkg
		dev  bool
	}{{"packages", lf.Packages, false}, {"packages-dev", lf.PackagesDev, true}} {
		for i, p := range sec.pkgs {
			if !validRef(core.Composer, p.Name, p.Version) {
				out.warn("skipped a %s entry with a name or version Sightread can't use: %q %q", lockName, clipText(p.Name), clipText(p.Version))
				continue
			}
			name := strings.ToLower(p.Name)
			in := core.Installed{
				Ref:      core.Ref{Eco: core.Composer, Name: p.Name, Version: p.Version},
				Path:     paths[name],
				Lockfile: lockName,
				LockLine: lines[sec.key+"/"+strconv.Itoa(i)],
				Dev:      sec.dev,
			}
			if c, ok := m.require[name]; ok {
				in.Constraint, in.Direct = c, true
			} else if c, ok := m.requireDev[name]; ok {
				in.Constraint, in.Direct = c, true
			}
			if p.Dist != nil && p.Dist.Reference != "" {
				in.Reference = p.Dist.Reference
			} else if p.Source != nil {
				in.Reference = p.Source.Reference
			}
			reason := classifyComposer(&in, p, m, configured)
			out.Installed = append(out.Installed, in)
			if reason != "" {
				out.NotChecked = append(out.NotChecked, notChecked(core.Composer, p.Name, p.Version, reason))
			}
		}
	}
	return out, nil
}

// classifyComposer sets Resolved, ResolvedKind and Private from where
// the lock says the package came from. It returns the Not checked
// reason, or "" when the package can be reviewed.
//
// Packagist entries carry its notification-url. A package from another
// Composer repository is private: reviewed when config lists the
// repository, else Not checked private. Path, VCS, artifact and inline
// package repositories have no registry release to compare with.
func classifyComposer(in *core.Installed, p composerPkg, m *composerManifest, configured map[string]bool) core.NotCheckedReason {
	dist := p.Dist
	if dist == nil || dist.URL == "" {
		dist = nil
	}
	switch {
	case dist != nil && dist.Type == "path", dist == nil && p.Source != nil && p.Source.Type == "path":
		in.ResolvedKind = core.ResolvedFile
		if dist != nil {
			in.Resolved = cleanURL(dist.URL)
		} else {
			in.Resolved = cleanURL(p.Source.URL)
		}
		return core.VCS
	case dist == nil && p.Source != nil:
		in.ResolvedKind, in.Resolved = core.ResolvedGit, cleanURL(p.Source.URL)
		return core.VCS
	case dist == nil:
		// Neither dist nor source: a metapackage, nothing to fetch.
		in.ResolvedKind = core.ResolvedForeign
		return core.VCS
	}
	in.Resolved = cleanURL(dist.URL)
	if dist.Type == "artifact" {
		in.ResolvedKind = core.ResolvedFile
		return core.VCS
	}
	notify := urlHost(p.NotificationURL)
	if packagistHosts[notify] {
		in.ResolvedKind = core.ResolvedRegistry
		return ""
	}
	name := strings.ToLower(p.Name)
	distHost := urlHost(dist.URL)
	for _, r := range m.repos {
		switch r.Type {
		case "composer":
			if r.host != "" && (r.host == notify || r.host == distHost) {
				in.ResolvedKind, in.Private = core.ResolvedRegistry, true
				if configured[r.host] {
					return ""
				}
				return core.Private
			}
		case "package":
			for _, n := range r.names {
				if n == name {
					in.ResolvedKind = core.ResolvedTarball
					return core.VCS
				}
			}
		case "vcs", "git", "github", "gitlab", "bitbucket", "hg", "svn", "fossil", "git-bitbucket":
			if p.Source != nil && sameRepoURL(r.URL, p.Source.URL) {
				in.ResolvedKind = core.ResolvedGit
				return core.VCS
			}
		}
	}
	if notify != "" {
		// Another Composer repository composer.json doesn't name (a
		// global one, say): private; reviewed only when configured.
		in.ResolvedKind, in.Private = core.ResolvedRegistry, true
		if configured[notify] {
			return ""
		}
		return core.Private
	}
	if m.packagist {
		in.ResolvedKind = core.ResolvedRegistry
		return ""
	}
	in.ResolvedKind = core.ResolvedForeign
	return core.VCS
}

// sameRepoURL compares two repository URLs, ignoring case, a trailing
// slash and ".git".
func sameRepoURL(a, b string) bool {
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".git")
		return s
	}
	return a != "" && norm(a) == norm(b)
}

// ReadComposer reads dir's composer.lock with its composer.json and
// vendor/composer/installed.json. It fails with an error wrapping
// fs.ErrNotExist when there is no composer.lock.
func ReadComposer(dir string, opt Options) (*Packages, error) {
	lock, err := readAllWithin(dir, filepath.Join(dir, ComposerLock), maxLockBytes)
	if err != nil {
		return nil, err
	}
	var skipped []string
	manifest, err := readAllWithin(dir, filepath.Join(dir, ComposerJSON), maxLockBytes)
	switch {
	case errors.Is(err, errOutsideRoot):
		skipped = append(skipped, ComposerJSON)
	case err != nil && !os.IsNotExist(err):
		return nil, err
	}
	var installed []byte
	vendorDir := "vendor"
	if manifest != nil {
		if m, err := parseComposerManifest(manifest); err == nil {
			vendorDir = m.vendorDir
		}
	}
	installedPath := filepath.Join(dir, filepath.FromSlash(vendorDir), filepath.FromSlash(composerInstalled))
	installed, err = readAllWithin(dir, installedPath, maxLockBytes)
	if err != nil {
		if errors.Is(err, errOutsideRoot) {
			skipped = append(skipped, filepath.ToSlash(filepath.Join(vendorDir, composerInstalled)))
		}
		installed = nil
	}
	p, err := ParseComposer(ComposerLock, lock, manifest, installed, opt)
	if err != nil {
		return nil, err
	}
	for _, name := range skipped {
		p.warn("skipped %q: %s", clipText(name), errOutsideRoot)
	}
	if manifest == nil {
		p.warn("%s has no %s next to it, so no Composer package counts as direct", ComposerLock, ComposerJSON)
	}
	return p, nil
}
