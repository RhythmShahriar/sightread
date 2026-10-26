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

// Side.Source of a side read from disk instead of a registry.
const (
	SourceLocalFile     = "local file"     // --from-file, --to-file
	SourceInstalledCopy = "installed copy" // the copy on the site, for --to-file
)

// Local reports whether the side was read from disk. Such a side is
// never in the archive cache: explain has only the report's hunks.
func (s Side) Local() bool { return s.Source == SourceLocalFile || s.Source == SourceInstalledCopy }

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
	// Error is why --soundcheck stopped after it touched the staging
	// copy; "" when it finished. NotCompared is true when it stopped
	// before the comparison, so Broke, New and Changed mean nothing and
	// the report shows no summary.
	Error       string
	NotCompared bool
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

// PairErrors matches the report's errors with its Not checked entries.
// A package that failed to download is a fetch-failed Not checked entry
// and an error carrying its code: one problem, which writers list and
// count once. codes[i] is the code of the error NotChecked[i] stands
// for ("" when none); rest are the errors no entry stands for, in order.
func (r *Report) PairErrors() (codes []ErrorCode, rest []ErrorEntry) {
	codes = make([]ErrorCode, len(r.NotChecked))
	used := make([]bool, len(r.Errors))
	for i, nc := range r.NotChecked {
		if nc.Reason != FetchFailed {
			continue
		}
		for j, e := range r.Errors {
			if !used[j] && e.Eco == nc.Eco && e.Name == nc.Name {
				used[j], codes[i] = true, e.Code
				break
			}
		}
	}
	for j, e := range r.Errors {
		if !used[j] {
			rest = append(rest, e)
		}
	}
	return codes, rest
}

// ErrorCount is how many errors the report's incomplete line counts:
// the errors no Not checked entry stands for, plus the errors of the
// updates that were reviewed. An unverified update's error is its
// verdict, which the line counts on its own.
func (r *Report) ErrorCount() int {
	_, rest := r.PairErrors()
	n := len(rest)
	for i := range r.Updates {
		if r.Updates[i].Verdict != Unverified {
			n += len(r.Updates[i].Errors)
		}
	}
	return n
}
