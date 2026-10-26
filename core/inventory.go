// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"io"
)

// NotCheckedReason is why a component was left out of the review
// (PRD 5.5).
type NotCheckedReason string

// The reasons a component is not checked.
const (
	NoHeader        NotCheckedReason = "no-header"
	NotWPOrg        NotCheckedReason = "not-wporg"
	Private         NotCheckedReason = "private"
	VCS             NotCheckedReason = "vcs"
	UnsupportedLock NotCheckedReason = "unsupported-lock"
	FetchFailed     NotCheckedReason = "fetch-failed"
	MUPlugin        NotCheckedReason = "mu-plugin"
	Core            NotCheckedReason = "core"
	TooLarge        NotCheckedReason = "too-large"
)

// Informational reports whether the reason only tells the reader what
// Sightread never reviews: WordPress core and must-use plugins have no
// update Sightread could review, so listing them must not make every
// WordPress run partial and fail --fail-on.
func (r NotCheckedReason) Informational() bool {
	return r == Core || r == MUPlugin
}

// NotChecked is one component the report lists as not checked. It makes
// the run partial unless its reason is informational.
type NotChecked struct {
	Eco     Ecosystem
	Name    string
	Version string
	Reason  NotCheckedReason
	Text    string
	Hint    string
}

// CountNotChecked counts the entries that make a run partial, leaving
// out the informational ones. It is summary.not_checked.
func CountNotChecked(ncs []NotChecked) int {
	n := 0
	for _, nc := range ncs {
		if !nc.Reason.Informational() {
			n++
		}
	}
	return n
}

// Installed is one installed package, from a site folder, a --wp
// listing, a Tuner report or a lockfile.
type Installed struct {
	Ref          Ref
	Path         string // folder on disk, relative to the target
	Lockfile     string // relative path of the lockfile
	LockLine     int    // 1-based line of the entry, for SARIF
	Integrity    string // npm SRI from the lock
	Reference    string // composer dist/source reference from the lock
	Resolved     string // lock URL as written (never fetched)
	ResolvedKind string // "registry", "git", "file", "tarball", "foreign"
	Constraint   string // from composer.json or package.json
	Direct       bool
	Dev          bool
	UpdateURI    string
	AutoUpdate   bool
	Private      bool
}

// Kinds of Installed.ResolvedKind.
const (
	ResolvedRegistry = "registry"
	ResolvedGit      = "git"
	ResolvedFile     = "file"
	ResolvedTarball  = "tarball"
	ResolvedForeign  = "foreign"
)

// InventoryRequest says where to look for installed packages.
type InventoryRequest struct {
	Root        string
	WP          []string // the --wp command as argv
	TunerReport string
	Lockfiles   []string
	Transitive  bool
	Ecosystems  []Ecosystem
	MaxDepth    int
	// Command is the Sightread command errors name; Log gets one line
	// per --wp call (-v). Both are set by run.
	Command string
	Log     io.Writer
	// Sources is the config's sources: a lockfile entry resolved from
	// the npm mirror, a configured scope or a Composer repository is a
	// registry entry, not a tarball. Nil means the public registries.
	Sources *SourcesConfig
}

// Site is what one target folder holds.
type Site struct {
	Root       string
	Kind       string // "wordpress", "composer", "npm" or "mixed"
	WordPress  string // core version when known
	Installed  []Installed
	NotChecked []NotChecked
	Warnings   []string
}

// ChangesRequest is the input of `changes`: a lockfile at a git ref
// against the working tree, or two lockfiles.
type ChangesRequest struct {
	Repo      string
	Base      string
	Before    string
	After     string
	Lockfiles []string
	// Sources is as for InventoryRequest. Set by run.
	Sources *SourcesConfig
}

// Bump is one package a lockfile change moves. From is nil for a
// package the change adds.
type Bump struct {
	From *Installed
	To   Installed
}

// ChangeSet is what a lockfile change moves: one Bump per package whose
// version, integrity, resolved URL or reference changed and per added
// package. Removed packages are not listed: nothing new runs.
type ChangeSet struct {
	// Base is the ref the working tree was compared with: the --base
	// value, origin/$GITHUB_BASE_REF or the merge-base commit. Empty for
	// --before and --after.
	Base       string
	Bumps      []Bump
	NotChecked []NotChecked
	// Warnings are lines for the report, such as a lockfile that is not
	// at the base so every package in it counts as added.
	Warnings []string
}

// Inventory reads what is installed (package inventory).
type Inventory interface {
	Read(ctx context.Context, req InventoryRequest) (*Site, error)
	Changes(ctx context.Context, req ChangesRequest) (*ChangeSet, error)
	// LocalTree reads an installed folder into a tree, the same shape an
	// archive gives, so it can be diffed and verified.
	LocalTree(ctx context.Context, dir string, blobs BlobStore, lim Limits) (*Tree, error)
}

// TreeVersioner is an Inventory that reads the version a package's own
// files declare: a plugin's main file or a theme's style.css header,
// package.json or composer.json. run names a --to-file or --from-file
// side by it when --to or --from names none. "" when none is declared.
type TreeVersioner interface {
	TreeVersion(eco Ecosystem, name string, t *Tree) string
}

// GitShow returns the contents of path at ref in repo, as
// `git show <ref>:<path>` prints them (inventory/gitref).
type GitShow func(ctx context.Context, repo, ref, path string) ([]byte, error)
