// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import "time"

// Verdict is the outcome for one update (PRD 5.6).
type Verdict string

// The verdicts, worst first.
const (
	Hold       Verdict = "hold"
	Review     Verdict = "review"
	Routine    Verdict = "routine"
	Allowed    Verdict = "allowed"
	Unverified Verdict = "unverified"
)

// Side is one version of an update as the report shows it.
type Side struct {
	Version    string
	Source     string // "wordpress.org", "packagist.org", "registry.npmjs.org", "local file"
	URL        string
	SHA256     string // hex
	HashKind   string // HashArchive or HashManifest
	Verified   VerifiedBy
	Method     string
	Released   time.Time
	Publisher  []string
	Latest     bool
	Wanted     bool
	Constraint string
}

// InstalledInfo is where the installed version lives.
type InstalledInfo struct {
	Path       string
	Lockfile   string
	LockLine   int
	Drift      bool
	DriftFiles []string
}

// SoundcheckResult is what --soundcheck did on the staging copy.
type SoundcheckResult struct {
	Staging, RoadieVerify, Snapshot, Report, Applied string
	Broke, New, Changed                              int
	RolledBack                                       bool
}

// ErrorEntry is an error the report records for one package.
type ErrorEntry struct {
	Eco     Ecosystem
	Name    string
	Code    ErrorCode
	Message string
}

// Update is one reviewed update.
type Update struct {
	Eco       Ecosystem
	Name      string
	From, To  Side
	Installed InstalledInfo
	Verdict   Verdict
	Diff      DiffStats
	Changelog []ChangelogEntry
	Findings  []Finding
	// Hidden are the findings --id, --exclude-id and --severity left out
	// of the report. They still count for the verdict and the gate, so a
	// display filter never turns a REVIEW into a ROUTINE. A report read
	// back from JSON keeps only their number.
	Hidden     []Finding
	Hunks      []Hunk // flagged hunks always; every hunk with --diff or HTML
	Soundcheck *SoundcheckResult
	Errors     []ErrorEntry
	Sites      []string // fleet runs: the sites this update applies to
	FromCache  bool
}

// Summary holds the counts of the report header; every one is always
// written, zero included.
type Summary struct {
	Updates, Hold, Review, Routine, Allowed, Unverified                 int
	Critical, High, Medium, Low, Info                                   int
	Baselined, AllowedFindings, Ignored, Demoted, NotChecked, FromCache int
	Hidden                                                              int // left out by --id, --exclude-id or --severity
}

// Report is one review run, the data of a kind review document.
type Report struct {
	Kind          string // "review"
	Target        Target
	Started       time.Time
	Duration      time.Duration // written as duration_ms
	StoppedBy     string        // "", "interrupted", "deadline"
	SignalPack    string
	NamesPack     string
	FailOn        string
	MinConfidence string
	Complete      bool
	Summary       Summary
	Updates       []Update
	NotChecked    []NotChecked
	Warnings      []string
	Errors        []ErrorEntry
	Notes         []string // e.g. "--skip-roadie-verify was used"
}

// Target is what a run reviewed.
type Target struct {
	Path string
	// RepoPath is Path relative to the git repository that holds it,
	// with forward slashes ("." for the root); "" outside one. A
	// report whose Path was redacted or merged still finds its files in
	// the repository through it (SARIF).
	RepoPath  string
	Kind      string
	WordPress string
	Sites     []string
}

// KindReview is Report.Kind for a review run.
const KindReview = "review"

// Schema is the JSON schema name of every Sightread document.
const Schema = "rhythm-sightread/v1"

// FingerprintKey is the SARIF partialFingerprints key.
const FingerprintKey = "sightreadFinding/v1"
