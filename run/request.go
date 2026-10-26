// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run

import (
	"io"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

// Defaults of PRD section 7 that the pipeline applies when a request
// leaves a value zero.
const (
	DefaultJobs     = 4
	DefaultDeadline = 30 * time.Minute
	DefaultMinAge   = "72h"
	// MaxUncompressed caps the uncompressed size of one package whatever
	// --max-size says.
	MaxUncompressed = int64(1) << 30
	// RunsKept is how many reports runs/ keeps for explain and watch.
	RunsKept = 20
	// MaxNewDeps bounds the registry lookups for dependencies new in one
	// version, so a hostile manifest with thousands of entries can't turn
	// one review into thousands of requests.
	MaxNewDeps = 50
	// hunkContext is the context lines around a flagged hunk.
	hunkContext = 3
)

// Request is one review: what to look at and every flag that shapes it.
// Flag values come in as given; Review merges .sightread/config.yaml
// under them, so a key the user left out takes the config's value and a
// flag always wins.
type Request struct {
	Command string // the command, for error texts: "plugin", "all", "changes"
	Version string // the tool's version, for the saved report

	// Eco limits the review to one ecosystem (plugin, theme, composer,
	// npm); empty for all and changes.
	Eco core.Ecosystem
	// Names are the packages named on the command line. Each is reviewed
	// whether or not the inventory lists it; a missing one is E1.
	Names []string
	// Changes, when set, reviews what a lockfile change moves.
	Changes *core.ChangesRequest
	// Sites, when set, reviews every site of a fleet file (all --sites).
	Sites []Site

	// Inventory says where installed versions are: --path, --wp,
	// --from-tuner and the lockfiles.
	Inventory core.InventoryRequest

	To, From         string // --to and --from
	ToFile, FromFile string // --to-file and --from-file: zip, tgz or folder
	AllowDowngrade   bool
	Pre, Transitive  bool
	Only, Skip       []string

	// Getter is built from the flags and the environment (tokens,
	// SIGHTREAD_* mirrors). Review fills the Bases a variable left unset
	// from config sources.
	Getter          core.GetterConfig
	MaxSize         int64 // --max-size; 0 means core.DefaultLimits
	Options         core.SourceOptions
	NoOSV           bool
	AllowUnverified bool
	Jobs            int
	Deadline        time.Duration

	ConfigFile   string // --config
	NoConfig     bool
	ConfigStart  string // where the config search starts; "" is the current folder
	Baseline     string
	NoAllow      bool
	TrustPRAllow bool

	// FailOn, MinConfidence and MinAge are the flag values; empty keeps
	// the config's value.
	FailOn, MinConfidence, MinAge string

	SignalDirs      []string // --signals
	NoSignalUpdates bool
	IDs, ExcludeIDs []string     // globs on signal IDs, applied after Score
	Severity        cli.Severity // hide findings below this, after Score
	AllHunks        bool         // --diff or an HTML output: keep every hunk

	// Set names the flags given on the command line, as flag.Visit sees
	// them, so a boolean config key fills only a flag left out.
	Set map[string]bool

	CacheDir string    // the Sightread cache; "" means config.CacheDir("sightread")
	Log      io.Writer // -v
	Progress io.Writer // "reviewing 3 of 8: ..." lines; nil prints none
	// OnUpdate is called once per update as it finishes, from one
	// goroutine at a time (--jsonl).
	OnUpdate func(core.Update)
	// HardStop ends the run at once when closed (the second Ctrl-C). The
	// context passed to Review is the soft stop: once it is done no new
	// package starts and the ones under way finish.
	HardStop <-chan struct{}
	Now      func() time.Time
}

// Site is one entry of a sites file.
type Site struct {
	Name      string
	Inventory core.InventoryRequest
	AllowFile string // the site's own allowed.yaml, merged into allow_from
}

func (r *Request) set(name string) bool { return r.Set[name] }

func (r *Request) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}
