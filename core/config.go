// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

// Config is .sightread/config.yaml (PRD 8.1). Package policy decodes it
// strictly (unknown keys are E12) and validates every value; flags win
// over it. Empty values mean "not set": the defaults live with the
// flags, so a config that leaves a key out never overrides a default.
type Config struct {
	FailOn        string      `yaml:"fail_on" json:"fail_on,omitempty"`
	MinConfidence string      `yaml:"min_confidence" json:"min_confidence,omitempty"`
	MinAge        string      `yaml:"min_age" json:"min_age,omitempty"`
	Ecosystems    []Ecosystem `yaml:"ecosystems" json:"ecosystems,omitempty"`
	Path          string      `yaml:"path" json:"path,omitempty"`
	Transitive    bool        `yaml:"transitive" json:"transitive,omitempty"`
	Pre           bool        `yaml:"pre" json:"pre,omitempty"`
	SVNCheck      bool        `yaml:"svn_check" json:"svn_check,omitempty"`
	// OSV is nil when the key is absent (the default, on).
	OSV         *bool             `yaml:"osv" json:"osv,omitempty"`
	Sources     SourcesConfig     `yaml:"sources" json:"sources"`
	LocalFiles  map[string]string `yaml:"local_files" json:"local_files,omitempty"` // name to a path template with {version}
	AllowFile   string            `yaml:"allow_file" json:"allow_file,omitempty"`
	AllowFrom   []string          `yaml:"allow_from" json:"allow_from,omitempty"`
	TrustedKeys []string          `yaml:"trusted_keys" json:"trusted_keys,omitempty"`
	Signals     SignalConfig      `yaml:"signals" json:"signals"`
	Ignore      []IgnoreEntry     `yaml:"ignore" json:"ignore,omitempty"`
	Soundcheck  SoundcheckConfig  `yaml:"soundcheck" json:"soundcheck"`
}

// SourcesConfig holds mirror and private registry URLs. Each must be
// https://, or http:// on a loopback host. The keys beyond PRD 8.1's
// example match the SIGHTREAD_* variables, so a mirror can be set either
// way.
type SourcesConfig struct {
	WPOrgAPI       string               `yaml:"wporg_api" json:"wporg_api,omitempty"`
	WPOrgDownloads string               `yaml:"wporg_downloads" json:"wporg_downloads,omitempty"`
	WPOrgSVN       string               `yaml:"wporg_svn" json:"wporg_svn,omitempty"`
	WPOrgThemeSVN  string               `yaml:"wporg_theme_svn" json:"wporg_theme_svn,omitempty"`
	Packagist      string               `yaml:"packagist" json:"packagist,omitempty"`
	PackagistMeta  string               `yaml:"packagist_meta" json:"packagist_meta,omitempty"`
	GitHubAPI      string               `yaml:"github_api" json:"github_api,omitempty"`
	GitHubCodeload string               `yaml:"github_codeload" json:"github_codeload,omitempty"`
	OSV            string               `yaml:"osv" json:"osv,omitempty"`
	NPM            NPMSourceConfig      `yaml:"npm" json:"npm"`
	Composer       ComposerSourceConfig `yaml:"composer" json:"composer"`
}

// NPMSourceConfig is the npm registry and private scopes. A scope's
// token comes only from SIGHTREAD_NPM_TOKEN_<SCOPE>, never from config.
type NPMSourceConfig struct {
	Registry string            `yaml:"registry" json:"registry,omitempty"`
	Scopes   map[string]string `yaml:"scopes" json:"scopes,omitempty"` // "@acme" to its registry URL
}

// ComposerSourceConfig lists private Composer repositories. Their
// credentials come only from COMPOSER_AUTH.
type ComposerSourceConfig struct {
	Repositories []string `yaml:"repositories" json:"repositories,omitempty"`
}

// SignalConfig tunes signals.
type SignalConfig struct {
	// Severity overrides a signal's default severity by ID. Unignorable
	// signals can't be lowered below critical.
	Severity map[string]string `yaml:"severity" json:"severity,omitempty"`
	// DomainsOK are host globs outbound-new-domain treats as known.
	DomainsOK []string `yaml:"domains_ok" json:"domains_ok,omitempty"`
	// Dirs are the --signals folders of extra rule YAML. They come from
	// the flag only.
	Dirs []string `yaml:"-" json:"-"`
}

// SoundcheckConfig is the --soundcheck setup.
type SoundcheckConfig struct {
	Staging    string   `yaml:"staging" json:"staging,omitempty"`
	WP         string   `yaml:"wp" json:"wp,omitempty"`
	Production []string `yaml:"production" json:"production,omitempty"`
	FailOn     string   `yaml:"fail_on" json:"fail_on,omitempty"`
	Args       []string `yaml:"args" json:"args,omitempty"`
}

// IgnoreEntry hides matching findings. ID and Reason are required;
// Package and Path are globs; Until is YYYY-MM-DD.
type IgnoreEntry struct {
	ID      string `yaml:"id" json:"id"`
	Package string `yaml:"package" json:"package,omitempty"`
	Path    string `yaml:"path" json:"path,omitempty"`
	Reason  string `yaml:"reason" json:"reason"`
	Until   string `yaml:"until" json:"until,omitempty"`
}

// AllowEntry is one entry of .sightread/allowed.yaml (PRD 8.2): a
// reviewed version, bound to the sha256 of the archive that was read.
type AllowEntry struct {
	Package      string   `yaml:"package" json:"package"` // "<eco>:<name>"
	Version      string   `yaml:"version" json:"version"`
	SHA256       string   `yaml:"sha256" json:"sha256"`
	Hash         string   `yaml:"hash,omitempty" json:"hash,omitempty"` // "manifest" for WordPress.org
	Signals      []string `yaml:"signals,omitempty" json:"signals,omitempty"`
	Reason       string   `yaml:"reason" json:"reason"`
	By           string   `yaml:"by" json:"by"`
	Date         string   `yaml:"date" json:"date"`
	Until        string   `yaml:"until,omitempty" json:"until,omitempty"`
	ImportedFrom string   `yaml:"imported_from,omitempty" json:"imported_from,omitempty"`
}
