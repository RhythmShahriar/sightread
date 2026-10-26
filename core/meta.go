// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import "time"

// Person is a maintainer, committer or publisher. Email is masked in
// every output.
type Person struct{ Name, Email, Login string }

// Advisory is one OSV record for a version.
type Advisory struct {
	ID        string
	Summary   string
	Malicious bool     // a MAL- record
	FixedIn   []string // versions that fix it
	URL       string
}

// DepInfo is what run learns about a dependency new in this version.
type DepInfo struct {
	Name, Version    string
	Published        time.Time
	Downloads        int64
	HasInstallScript bool
	Popular          bool
}

// ChangelogEntry is one version's changelog text.
type ChangelogEntry struct {
	Version string
	Text    string
	Generic bool // only "compatibility", "tested up to", "bug fixes" and the like
}

// Release is one earlier release, for dormant-release and size-jump.
type Release struct {
	Version   string
	Published time.Time
	Size      int64
	CodeLines int
}

// ArchiveRef says where a version's archive is and what its source
// publishes about its bytes.
type ArchiveRef struct {
	URL        string
	Integrity  string // npm SRI
	Shasum     string // Packagist dist.shasum
	Reference  string // git commit (Composer dist.reference)
	Size       int64
	Signatures []NPMSignature
}

// NPMSignature is one entry of an npm version's dist.signatures.
type NPMSignature struct{ KeyID, Sig string }

// Meta is everything a source says about one version.
type Meta struct {
	Ref              Ref
	Published        time.Time
	Publisher        *Person // npm _npmUser, SVN tag creator
	Maintainers      []Person
	Contributors     []string // WordPress.org readme and info API
	Author           string
	AuthorProfile    string
	Repository       string
	Homepage         string
	License          string
	Type             string            // composer type
	Scripts          map[string]string // npm lifecycle and other scripts
	ComposerScripts  map[string][]string
	AutoloadFiles    []string
	HasInstallScript bool
	Deps             map[string]string
	DevDeps          map[string]string
	DepInfo          map[string]*DepInfo // filled by run for new dependencies
	Provenance       string              // "", "slsa", "trusted-publisher"
	RequiresPHP      string
	Closed           bool
	ClosedReason     string
	Abandoned        bool
	Changelog        []ChangelogEntry // entries newer than the other side, newest first
	Advisories       []Advisory       // OSV, filled by run
	History          []Release        // up to 10 releases before this one
	GitTag           *bool            // nil = not checked
	PublicShadow     string           // --check-confusion: public version of a private name
	Archive          ArchiveRef
	Private          bool
	Latest           string // newest stable on the source, for the header
}
