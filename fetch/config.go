// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package fetch

import (
	"maps"
	"strings"
	"time"

	"github.com/RhythmShahriar/sightread/core"
)

// Cache kinds for Getter.JSON. Each picks how long a cached answer is
// reused before it is fetched again (PRD 8.5).
const (
	// KindVersions is a version list (10 minutes). A JSON request of this
	// kind to an npm registry asks for the abbreviated packument
	// (Accept: application/vnd.npm.install-v1+json).
	KindVersions = "versions"
	// KindMeta is per-version metadata, immutable once published (7 days).
	KindMeta = "meta"
	// KindChecksums is a WordPress.org checksums file (kept forever).
	KindChecksums = "checksums"
	// KindMaintainers is a maintainer or owner list (12 hours).
	KindMaintainers = "maintainers"
	// KindOSV is an OSV record (6 hours).
	KindOSV = "osv"
	// KindKeys is the npm registry signing keys (24 hours).
	KindKeys = "keys"
)

// forever is the TTL of answers that never change. kit cache refreshes
// an entry older than its TTL, so this only has to outlast the cache.
const forever = 100 * 365 * 24 * time.Hour

// kindDownloads is the index from an archive URL to its blob, so an
// offline run can reuse an archive it downloaded before.
const kindDownloads = "downloads"

// ttls maps each JSON kind to its TTL.
var ttls = map[string]time.Duration{
	KindVersions:    10 * time.Minute,
	KindMeta:        168 * time.Hour,
	KindChecksums:   forever,
	KindMaintainers: 12 * time.Hour,
	KindOSV:         6 * time.Hour,
	KindKeys:        24 * time.Hour,
}

// TTL returns how long answers of kind are reused; false for a kind
// JSON does not know.
func TTL(kind string) (time.Duration, bool) {
	d, ok := ttls[kind]
	return d, ok
}

// Defaults for GetterConfig fields left at zero.
const (
	DefaultTimeout = 30 * time.Second
	DefaultRetries = 2
	DefaultPerHost = 4
	// MaxJSON is the most bytes read from one JSON answer (PRD 11).
	MaxJSON = 32 << 20
	// downloadSpan is how many request timeouts a whole download may
	// take: an archive streams for longer than one JSON answer, while a
	// stall of one timeout without a byte still ends it.
	downloadSpan = 20
)

// DefaultHosts are the hosts the Getter reaches without any
// configuration: the official registries of PRD 11. Mirrors and private
// registries add theirs through GetterConfig.Bases and Hosts.
func DefaultHosts() []string {
	return []string{
		"api.wordpress.org",
		"downloads.wordpress.org",
		"plugins.svn.wordpress.org",
		"themes.svn.wordpress.org",
		"repo.packagist.org",
		"packagist.org",
		"api.github.com",
		"codeload.github.com",
		"gitlab.com",
		"bitbucket.org",
		"registry.npmjs.org",
		"api.osv.dev",
	}
}

// defaultBases are the official base URLs of each source.
var defaultBases = map[string]string{
	core.BaseWPOrgAPI:       "https://api.wordpress.org",
	core.BaseWPOrgDownloads: "https://downloads.wordpress.org",
	core.BaseWPOrgSVN:       "https://plugins.svn.wordpress.org",
	core.BaseWPOrgThemeSVN:  "https://themes.svn.wordpress.org",
	core.BasePackagist:      "https://repo.packagist.org",
	core.BasePackagistMeta:  "https://packagist.org",
	core.BaseGitHubAPI:      "https://api.github.com",
	core.BaseGitHubCodeload: "https://codeload.github.com",
	core.BaseNPM:            "https://registry.npmjs.org",
	core.BaseOSV:            "https://api.osv.dev",
}

// baseEnv names the variable of PRD 8.4 that overrides each base.
var baseEnv = map[string]string{
	core.BaseWPOrgAPI:       "SIGHTREAD_WPORG_API",
	core.BaseWPOrgDownloads: "SIGHTREAD_WPDL_API",
	core.BaseWPOrgSVN:       "SIGHTREAD_WPSVN",
	core.BaseWPOrgThemeSVN:  "SIGHTREAD_WPTHEMESVN",
	core.BasePackagist:      "SIGHTREAD_PACKAGIST",
	core.BasePackagistMeta:  "SIGHTREAD_PACKAGIST_META",
	core.BaseGitHubAPI:      "SIGHTREAD_GITHUB_API",
	core.BaseGitHubCodeload: "SIGHTREAD_GITHUB_CODELOAD",
	core.BaseNPM:            "SIGHTREAD_NPM_REGISTRY",
	core.BaseOSV:            "SIGHTREAD_OSV_API",
}

// DefaultBases returns the official base URL of every source, keyed by
// the core.Base* names.
func DefaultBases() map[string]string { return maps.Clone(defaultBases) }

// BaseEnv returns the environment variable that overrides the base key
// ("SIGHTREAD_NPM_REGISTRY" for core.BaseNPM), or "" for a key without
// one (private scopes and Composer repositories come from config).
func BaseEnv(key string) string { return baseEnv[key] }

// EnvBases returns DefaultBases with every SIGHTREAD_* mirror variable
// that getenv reports applied, trailing slashes removed. The values are
// checked when the Getter is built, not here.
func EnvBases(getenv func(string) string) map[string]string {
	out := DefaultBases()
	for key, env := range baseEnv {
		if v := strings.TrimSpace(getenv(env)); v != "" {
			out[key] = strings.TrimRight(v, "/")
		}
	}
	return out
}

// GitHubTokenEnv are the variables a GitHub token is read from, first
// match wins.
var GitHubTokenEnv = []string{"GITHUB_TOKEN", "RHYTHM_GITHUB_TOKEN"}

// ScopeTokenEnv returns the variable holding the token of a private npm
// scope: "@acme" gives SIGHTREAD_NPM_TOKEN_ACME. Characters a variable
// name can't hold become underscores.
func ScopeTokenEnv(scope string) string {
	s := strings.ToUpper(strings.TrimPrefix(scope, "@"))
	s = strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' {
			return r
		}
		return '_'
	}, s)
	return "SIGHTREAD_NPM_TOKEN_" + s
}

// EnvConfig fills the parts of a GetterConfig that come from the
// environment (PRD 8.4): the mirror bases, the GitHub token, COMPOSER_AUTH
// and the token of every scope in scopes. The caller adds the rest.
func EnvConfig(getenv func(string) string, scopes []string) core.GetterConfig {
	cfg := core.GetterConfig{Bases: EnvBases(getenv), ComposerAuth: getenv("COMPOSER_AUTH")}
	for _, k := range GitHubTokenEnv {
		if v := strings.TrimSpace(getenv(k)); v != "" {
			cfg.GitHubToken = v
			break
		}
	}
	for _, s := range scopes {
		if v := strings.TrimSpace(getenv(ScopeTokenEnv(s))); v != "" {
			if cfg.ScopeTokens == nil {
				cfg.ScopeTokens = map[string]string{}
			}
			cfg.ScopeTokens[s] = v
		}
	}
	return cfg
}

// UserAgent is the User-Agent of a Sightread build at version.
func UserAgent(version string) string {
	if version == "" {
		version = "dev"
	}
	return "rhythm-sightread/" + version + " (+https://github.com/RhythmShahriar/sightread)"
}
