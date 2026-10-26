// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"io"
	"net/http"
)

// Getter is the only way a stage reaches the network. It is implemented
// by package fetch, which enforces HTTPS, the host allowlist, the
// credential rules and the caps of PRD section 11.
type Getter interface {
	// JSON fetches url and decodes it into v. kind picks the cache TTL.
	JSON(ctx context.Context, url string, v any, kind string) error
	// Download streams url into blobs, stopping at limit.
	Download(ctx context.Context, url string, limit int64, blobs BlobStore) (Download, error)
	// Text is for the few requests that are not a GET of JSON or an
	// archive: SVN PROPFIND and the OSV batch POST.
	Text(ctx context.Context, method, url string, body io.Reader, limit int64) ([]byte, http.Header, error)
}

// Download is one fetched archive with every hash a source may publish.
type Download struct {
	Path   string // the cached archive on disk, by hash
	SHA256 [32]byte
	SHA512 [64]byte
	SHA1   [20]byte
	Size   int64
}

// Bases keys of Env.Bases and GetterConfig.Bases.
const (
	BaseWPOrgAPI       = "wporg_api"
	BaseWPOrgDownloads = "wporg_downloads"
	BaseWPOrgSVN       = "wporg_svn"
	BaseWPOrgThemeSVN  = "wporg_theme_svn"
	BasePackagist      = "packagist"
	BasePackagistMeta  = "packagist_meta"
	BaseGitHubAPI      = "github_api"
	BaseGitHubCodeload = "github_codeload"
	BaseNPM            = "npm"
	BaseOSV            = "osv"
	// BaseNPMScope + "@acme" is a private npm scope's registry.
	BaseNPMScope = "npm_scope:"
	// BaseComposerRepo + "<n>" is the n-th private Composer repository.
	BaseComposerRepo = "composer_repo:"
)

// Env is what a source gets to work with.
type Env struct {
	Get     Getter
	Blobs   BlobStore
	Limits  Limits
	Offline bool
	Bases   map[string]string // the Base* keys above
	Options SourceOptions
	Log     io.Writer // -v
}

// SourceOptions are the flags that change what a source checks.
type SourceOptions struct{ SVNCheck, Pre, CheckConfusion bool }

// Source is one ecosystem's official registry.
type Source interface {
	Eco() Ecosystem
	// Versions lists published versions, oldest first. An unknown name
	// is an E2 *Error.
	Versions(ctx context.Context, name string) ([]string, error)
	// Meta describes one version. A version that isn't published is an
	// E3 *Error.
	Meta(ctx context.Context, ref Ref) (*Meta, error)
	// Fetch downloads, verifies and unpacks the version m describes.
	Fetch(ctx context.Context, m *Meta) (*Tree, Integrity, error)
}

// LocalVerifier is implemented by sources that can compare an installed
// copy with the official copy of the same version (wporg, packagist).
type LocalVerifier interface {
	VerifyLocal(ctx context.Context, ref Ref, local *Tree) (Drift, error)
}

// Drift compares an installed copy with the official one. Official is
// false when under half the files match: then the copy is not the
// package the source knows (not-wporg).
type Drift struct {
	Matched, Differ, Missing, Extra []string
	Official                        bool
}

// TagSource is implemented by sources with named versions: wporg
// ({"latest": info API version}) and npm (dist-tags). Packagist has none.
type TagSource interface {
	Tags(ctx context.Context, name string) (map[string]string, error)
}

// SourceFactory builds a source for one run.
type SourceFactory func(env *Env) Source

// Advisories looks up OSV records (source/osv).
type Advisories interface {
	Query(ctx context.Context, refs []Ref) (map[Ref][]Advisory, error)
}

// TagChecker tells whether a repository has a tag for a version
// (source/github).
type TagChecker interface {
	TagExists(ctx context.Context, repoURL, version, name string) (bool, error)
}
