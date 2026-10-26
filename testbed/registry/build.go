// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// builtVersion is one version of a scenario package after its archive
// has been built and hashed at start.
type builtVersion struct {
	meta      VersionMeta
	published time.Time
	files     []treeFile        // the version's files, fake keys expanded
	checksums map[string]string // per-file SHA-256 (WordPress.org)

	// archive is the built archive bytes: a zip for WordPress and
	// GitHub, a tgz for npm.
	archive []byte
	// archiveSHA256 is the hex SHA-256 of the archive bytes.
	archiveSHA256 string
	// shasum is the hex SHA-1 of the archive bytes (Composer dist.shasum).
	shasum string
	// integrity is the npm SRI "sha512-<base64>" of the tarball.
	integrity string
	// signature is the base64 npm registry signature, set in the bad
	// state only for npm versions.
	signature string
}

// builtPkg is one scenario package, keyed by its name, with every
// version built.
type builtPkg struct {
	id        string
	meta      *PackageMeta
	installed string // installed version number
	candidate string // candidate version number
	versions  map[string]*builtVersion
	order     []string // version numbers oldest first
}

// archiveTop returns the top folder name a version's archive carries.
func archiveTop(m *PackageMeta, v VersionMeta) string {
	switch m.Ecosystem {
	case "wp-plugin", "wp-theme":
		return m.Name
	case "npm":
		return "package"
	case "composer":
		owner, repo := ownerRepo(m.Repository)
		ref := v.Reference
		if len(ref) > 7 {
			ref = ref[:7]
		}
		return fmt.Sprintf("%s-%s-%s", owner, repo, ref)
	}
	return m.Name
}

// ownerRepo splits a repository string like "github.com/acme/widget" or
// "https://github.com/acme/widget.git" into owner and repo.
func ownerRepo(repo string) (owner, name string) {
	repo = strings.TrimSuffix(repo, ".git")
	repo = strings.TrimPrefix(repo, "https://")
	repo = strings.TrimPrefix(repo, "git+https://")
	repo = strings.TrimPrefix(repo, "github.com/")
	parts := strings.SplitN(repo, "/", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "unknown", repo
}

// build reads one scenario and builds every version's archive. The npm
// signature is left empty here and signed by the registry once its
// per-run key exists.
func build(packagesDir, id string, m *PackageMeta, now time.Time) (*builtPkg, error) {
	bp := &builtPkg{id: id, meta: m, versions: map[string]*builtVersion{}}
	for _, v := range m.Versions {
		treeDir := filepath.Join(packagesDir, id, v.treeOf())
		files, err := readTree(treeDir)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", id, v.Version, err)
		}
		pub, err := ParseRelTime(v.PublishedRel, now)
		if err != nil {
			return nil, fmt.Errorf("%s %s: %w", id, v.Version, err)
		}
		bv := &builtVersion{meta: v, published: pub, files: files, checksums: checksumsFor(files)}
		if err := buildArchive(m, bv); err != nil {
			return nil, fmt.Errorf("%s %s: %w", id, v.Version, err)
		}
		bp.versions[v.Version] = bv
		bp.order = append(bp.order, v.Version)
		if v.Installed {
			bp.installed = v.Version
		}
		if v.Candidate {
			bp.candidate = v.Version
		}
	}
	return bp, nil
}

// buildArchive packs and hashes one version's archive by ecosystem.
func buildArchive(m *PackageMeta, bv *builtVersion) error {
	switch m.Ecosystem {
	case "npm":
		tgz, err := buildTarGz(bv.files)
		if err != nil {
			return err
		}
		bv.archive = tgz
		bv.archiveSHA256 = sha256hex(tgz)
		bv.integrity = sha512b64(tgz)
	default:
		z, err := buildZip(archiveTop(m, bv.meta), bv.files)
		if err != nil {
			return err
		}
		bv.archive = z
		bv.archiveSHA256 = sha256hex(z)
		bv.shasum = sha1hex(z)
	}
	return nil
}
