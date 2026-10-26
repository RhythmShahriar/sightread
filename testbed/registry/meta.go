// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// PackageMeta is one scenario's meta.yaml: what the fixture registry
// should say about the package and how its versions map to the file
// trees under the scenario folder. The field set is small on purpose; a
// scenario adds only what it exercises.
//
// Note on dependencies: the registry is standard library only for its
// servers, crypto and archive building. The one exception is reading
// this file with gopkg.in/yaml.v3, which the module already depends on;
// writing a YAML parser by hand would add more risk than it removes.
type PackageMeta struct {
	// Ecosystem is wp-plugin, wp-theme, composer or npm.
	Ecosystem string `yaml:"ecosystem"`
	// Name is the package name as the ecosystem writes it: a slug, a
	// vendor/package or an npm name.
	Name string `yaml:"name"`
	// Repository is the source repository, used for the Composer source
	// URL and the npm git tag check.
	Repository string `yaml:"repository,omitempty"`
	// Closed marks a WordPress.org plugin or theme the directory closed.
	Closed bool `yaml:"closed,omitempty"`
	// ClosedReason is the WordPress.org close reason text.
	ClosedReason string `yaml:"closed_reason,omitempty"`
	// Private marks a package that lives on a private registry or
	// repository, so the public registry must never be asked about it.
	Private bool `yaml:"private,omitempty"`
	// Versions are the published versions newest last. Exactly one is
	// the installed version (Installed true) and one is the candidate
	// (Candidate true).
	Versions []VersionMeta `yaml:"versions"`
}

// VersionMeta is one published version of a scenario package.
type VersionMeta struct {
	// Version is the version string.
	Version string `yaml:"version"`
	// Tree names the subfolder of the scenario whose files are this
	// version: "old" or "new". Empty defaults to "old" for the installed
	// version and "new" for the candidate.
	Tree string `yaml:"tree,omitempty"`
	// Installed marks the version the project has on disk (the "from").
	Installed bool `yaml:"installed,omitempty"`
	// Candidate marks the version served as the update under review (the
	// "to"); in the good state the registry serves the installed tree
	// under this version number instead.
	Candidate bool `yaml:"candidate,omitempty"`
	// PublishedRel is the publish time relative to the run start, e.g.
	// "-30d", "-3h" or "-90m"; empty means a long time ago.
	PublishedRel string `yaml:"published,omitempty"`
	// Maintainers are the npm maintainers or Composer maintainers of this
	// version (login names).
	Maintainers []string `yaml:"maintainers,omitempty"`
	// Contributors are the WordPress.org readme and info API contributors.
	Contributors []string `yaml:"contributors,omitempty"`
	// Author is the WordPress.org or Composer author.
	Author string `yaml:"author,omitempty"`
	// Committer is the SVN tag creator a PROPFIND returns.
	Committer string `yaml:"committer,omitempty"`
	// Scripts are the npm lifecycle scripts of this version.
	Scripts map[string]string `yaml:"scripts,omitempty"`
	// ComposerType is the Composer package type, e.g. composer-plugin.
	ComposerType string `yaml:"composer_type,omitempty"`
	// Provenance is "" or "slsa" for an npm version with attestations.
	Provenance string `yaml:"provenance,omitempty"`
	// GitTag, when true, means a matching tag exists in the repository.
	GitTag *bool `yaml:"git_tag,omitempty"`
	// Advisories are the OSV ids that affect this version; an id that
	// starts with MAL- marks it malicious.
	Advisories []string `yaml:"advisories,omitempty"`
	// Reference is the Composer dist.reference (a git commit) this
	// version resolves to.
	Reference string `yaml:"reference,omitempty"`
	// Shasum, when true, means Packagist publishes a dist.shasum for this
	// version; when false the archive is pinned by commit only.
	Shasum *bool `yaml:"shasum,omitempty"`
}

// ParseRelTime reads a PublishedRel offset like "-30d", "-3h", "-90m"
// against base. An empty value is a year before base.
func ParseRelTime(rel string, base time.Time) (time.Time, error) {
	if rel == "" {
		return base.AddDate(-1, 0, 0), nil
	}
	if !strings.HasPrefix(rel, "-") && !strings.HasPrefix(rel, "+") {
		return time.Time{}, fmt.Errorf("published %q: want a signed offset like -30d or -3h", rel)
	}
	unit := rel[len(rel)-1]
	n, err := strconv.Atoi(rel[:len(rel)-1])
	if err != nil {
		return time.Time{}, fmt.Errorf("published %q: %w", rel, err)
	}
	switch unit {
	case 'd':
		return base.AddDate(0, 0, n), nil
	case 'h':
		return base.Add(time.Duration(n) * time.Hour), nil
	case 'm':
		return base.Add(time.Duration(n) * time.Minute), nil
	}
	return time.Time{}, fmt.Errorf("published %q: unit must be d, h or m", rel)
}

// InstalledVersion returns the installed version entry, or false.
func (p *PackageMeta) InstalledVersion() (VersionMeta, bool) {
	for _, v := range p.Versions {
		if v.Installed {
			return v, true
		}
	}
	return VersionMeta{}, false
}

// CandidateVersion returns the candidate version entry, or false.
func (p *PackageMeta) CandidateVersion() (VersionMeta, bool) {
	for _, v := range p.Versions {
		if v.Candidate {
			return v, true
		}
	}
	return VersionMeta{}, false
}

// treeOf returns the subtree name a version's files come from, applying
// the defaults (old for the installed version, new otherwise).
func (v VersionMeta) treeOf() string {
	if v.Tree != "" {
		return v.Tree
	}
	if v.Installed {
		return "old"
	}
	return "new"
}

// loadMeta reads and validates one scenario's meta.yaml.
func loadMeta(path string) (*PackageMeta, error) {
	b, err := os.ReadFile(path) //nolint:gosec // a testbed fixture path under our own tree
	if err != nil {
		return nil, err
	}
	var m PackageMeta
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if m.Ecosystem == "" || m.Name == "" {
		return nil, fmt.Errorf("%s: ecosystem and name are required", path)
	}
	if len(m.Versions) == 0 {
		return nil, fmt.Errorf("%s: at least one version is required", path)
	}
	var installed, candidate int
	for _, v := range m.Versions {
		if v.Version == "" {
			return nil, fmt.Errorf("%s: a version is missing its number", path)
		}
		if v.Installed {
			installed++
		}
		if v.Candidate {
			candidate++
		}
	}
	if installed != 1 || candidate != 1 {
		return nil, fmt.Errorf("%s: need exactly one installed and one candidate version", path)
	}
	return &m, nil
}

// scenarioMetaPath is the meta.yaml of scenario id under packagesDir.
func scenarioMetaPath(packagesDir, id string) string {
	return filepath.Join(packagesDir, id, "meta.yaml")
}

// scenarioIDs lists every scenario folder under packagesDir in order.
func scenarioIDs(packagesDir string) ([]string, error) {
	entries, err := os.ReadDir(packagesDir)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		if e.IsDir() {
			ids = append(ids, e.Name())
		}
	}
	sort.Strings(ids)
	return ids, nil
}
