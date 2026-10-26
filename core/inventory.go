// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import "context"

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

// NotChecked is one component the report lists as not checked. It makes
// the run partial.
type NotChecked struct {
	Eco     Ecosystem
	Name    string
	Version string
	Reason  NotCheckedReason
	Text    string
	Hint    string
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
}

// Bump is one package a lockfile change moves. From is nil for a
// package the change adds.
type Bump struct {
	From *Installed
	To   Installed
}

// Inventory reads what is installed (package inventory).
type Inventory interface {
	Read(ctx context.Context, req InventoryRequest) (*Site, error)
	Changes(ctx context.Context, req ChangesRequest) ([]Bump, []NotChecked, error)
	// LocalTree reads an installed folder into a tree, the same shape an
	// archive gives, so it can be diffed and verified.
	LocalTree(ctx context.Context, dir string, blobs BlobStore, lim Limits) (*Tree, error)
}

// GitShow returns the contents of path at ref in repo, as
// `git show <ref>:<path>` prints them (inventory/gitref).
type GitShow func(ctx context.Context, repo, ref, path string) ([]byte, error)
