// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package stage

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/internal/proc"
)

// The report notes --soundcheck adds (PRD 15).
const (
	NoteRan        = "the staging site ran the update; Sightread did not"
	NoteSkipRoadie = "--skip-roadie-verify was used: the staging copy wasn't checked by rhythm roadie verify, so outbound mail is not known to be sealed"
	NoteApplied    = "applied by your command; the applied bytes were not checked against the reviewed ones"
	NoteNoRollback = "--rollback reinstalls only a version Sightread installed and reviewed; put the old version back with your own command"
)

// The --soundcheck-fail-on classes.
const (
	ClassBroke   = "broke"
	ClassNew     = "new"
	ClassChanged = "changed"
)

// Plan is what --soundcheck was asked to do.
type Plan struct {
	Command string   // "plugin", for messages
	Staging string   // the staging site's URL
	WP      []string // the --wp command (or config soundcheck.wp) as argv
	Apply   []string // the --apply command as argv
	FailOn  string   // ClassBroke, ClassNew or ClassChanged
	// Rollback reinstalls the reviewed old version when the comparison
	// has changes at FailOn.
	Rollback bool
	// Anyway installs an update on HOLD; SkipRoadie skips rhythm-roadie
	// verify (and says so in the report).
	Anyway, SkipRoadie bool
	Args               []string // arguments after --, for rhythm-soundcheck snapshot
	// Production lists the config's soundcheck.production entries; the
	// nearest .soundcheck/config.yaml at or above Dir adds its own.
	Production []string
	Dir        string
	// Tree returns the verified tree the review read for a version, from
	// the archive cache; Blobs is the store it lives in.
	Tree  func(ref core.Ref) (*core.Tree, bool)
	Blobs core.BlobStore
	// Soundcheck and Roadie are the helper programs; "" finds
	// rhythm-soundcheck and rhythm-roadie on PATH.
	Soundcheck, Roadie string
	Lookup             Resolver  // nil uses the system resolver
	Log                io.Writer // -v
}

// stager carries one --soundcheck run.
type stager struct {
	p                  Plan
	host               string // the staging host, for messages
	soundcheck, roadie string
	u                  *core.Update
	applied            bool // the update is on the copy
}

func (s *stager) ref() string { return s.u.Name + " " + s.u.To.Version }

// Run carries out --soundcheck for the one update of rep (PRD 15 steps 1
// to 7) and fills its Soundcheck block and the report notes. tripped is
// true when the comparison has changes at FailOn, which fails the run
// with exit 1. Every refusal comes before anything is installed; the
// error is a *core.Error with its PRD section 10 code and exit.
func Run(ctx context.Context, p Plan, rep *core.Report) (tripped bool, err error) {
	if len(rep.Updates) != 1 {
		return false, nil // nothing to install: up to date, or the run reviewed nothing
	}
	s := &stager{p: p, u: &rep.Updates[0]}
	u := s.u
	if err := Precheck(p.Command, u.Eco, p.Staging, len(p.Apply) > 0); err != nil {
		return false, err
	}
	staging, _ := url.Parse(p.Staging) // Precheck parsed it
	s.host = strings.ToLower(staging.Hostname())
	ref := core.Ref{Eco: u.Eco, Name: u.Name, Version: u.To.Version}

	// 1. HOLD.
	if u.Verdict == core.Hold && !p.Anyway {
		return false, &core.Error{Code: core.ESoundcheckOnHold, Exit: cli.ExitFindings, Command: p.Command,
			What: fmt.Sprintf("%s %s is on HOLD, so --soundcheck won't install it", u.Name, u.To.Version),
			Hint: []string{"review the findings first; --soundcheck-anyway installs it on the staging copy regardless"}}
	}
	// How it will be applied, before anything runs.
	wp := u.Eco == core.WPPlugin || u.Eco == core.WPTheme
	switch {
	case len(p.Apply) > 0 || !wp:
	case len(p.WP) == 0:
		return false, &core.Error{Code: core.EBadFlag, Exit: cli.ExitUsage, Command: p.Command,
			What: "--soundcheck needs the staging site's wp command to install the verified zip",
			Hint: []string{"give it with --wp \"wp --path=/srv/staging\" (or soundcheck.wp in .sightread/config.yaml)"}}
	case remotePrefix(p.WP):
		return false, &core.Error{Code: core.ERemoteWPSoundcheck, Exit: cli.ExitUsage, Command: p.Command,
			What: "--soundcheck can install the verified zip only through a local wp command",
			Hint: []string{fmt.Sprintf("for a remote staging site give --apply \"<command that installs %s %s>\"; "+
				"the report then says the applied bytes were not checked", u.Name, u.To.Version)}}
	}
	// 2. Production, by name.
	prods := make([]production, 0, len(p.Production))
	for _, e := range p.Production {
		prods = append(prods, production{entry: e, from: ".sightread/config.yaml (soundcheck.production)"})
	}
	more, err := soundcheckProduction(cmp.Or(p.Dir, "."))
	if err != nil {
		return false, &core.Error{Code: core.EBadConfig, Exit: cli.ExitUsage, What: err.Error()}
	}
	prods = append(prods, more...)
	if err := s.notProduction(prods); err != nil {
		return false, err
	}
	// The helpers.
	if err := s.findHelpers(); err != nil {
		return false, err
	}
	// 3. Roadie.
	sc := &core.SoundcheckResult{Staging: p.Staging, RoadieVerify: "skipped"}
	if p.SkipRoadie {
		rep.Notes = append(rep.Notes, NoteSkipRoadie)
	} else {
		prodURL, err := s.roadieVerify(ctx)
		if err != nil {
			return false, err
		}
		sc.RoadieVerify = "ok"
		if prodURL != "" {
			prods = append(prods, production{entry: prodURL, from: "the Roadie verify report"})
			if err := s.notProduction(prods[len(prods)-1:]); err != nil {
				return false, err
			}
		}
	}
	lookup := p.Lookup
	if lookup == nil {
		lookup = defaultResolver
	}
	if pr, ip, same := sameAddress(ctx, lookup, s.host, prods); same {
		return false, &core.Error{Code: core.EProduction, Exit: cli.ExitUsage, Command: p.Command,
			What: fmt.Sprintf("%s resolves to %s, the address of production %s (%s)", s.host, ip, hostOf(pr.entry), pr.from),
			Hint: []string{"--soundcheck applies the update to the site; point it at a staging copy (rhythm roadie copy makes one)"}}
	}

	// 4. Snapshot.
	sc.Snapshot = snapshotName(u.Name, u.From.Version)
	if err := s.snapshot(ctx, sc.Snapshot); err != nil {
		return false, err
	}
	u.Soundcheck = sc
	// 5. Apply.
	if len(p.Apply) > 0 {
		if err := s.runApply(ctx, p.Apply, proc.PurposeApply, ref); err != nil {
			return false, err
		}
		sc.Applied = "your command"
		rep.Notes = append(rep.Notes, NoteApplied)
	} else {
		if err := s.installVerified(ctx, ref, u.To.SHA256); err != nil {
			return false, err
		}
		sc.Applied = "verified archive " + short(u.To.SHA256)
	}
	s.applied = true
	rep.Notes = append(rep.Notes, NoteRan)
	// 6. Compare.
	c, err := s.compare(ctx, sc.Snapshot)
	if err != nil {
		return false, err
	}
	sc.Broke, sc.New, sc.Changed, sc.Report = c.Summary.Broke, c.Summary.New, c.Summary.Changed, c.After.Dir
	tripped = c.trips(cmp.Or(p.FailOn, ClassBroke))
	// 7. Rollback.
	if tripped && p.Rollback {
		if sc.RolledBack, err = s.rollback(ctx, rep); err != nil {
			return tripped, err
		}
	}
	return tripped, nil
}

// Precheck refuses what can be refused before a review starts: a
// staging URL that isn't one and a Composer or npm package without the
// --apply command that installs it.
func Precheck(command string, eco core.Ecosystem, stagingURL string, apply bool) error {
	staging, err := url.Parse(stagingURL)
	if err != nil || staging.Hostname() == "" || (staging.Scheme != "https" && staging.Scheme != "http") {
		return &core.Error{Code: core.EBadFlag, Exit: cli.ExitUsage,
			What: fmt.Sprintf("--soundcheck %q: want the staging site's URL, such as https://staging.shop.test", stagingURL)}
	}
	if !apply && (eco == core.Composer || eco == core.NPM) {
		return &core.Error{Code: core.EBadFlag, Exit: cli.ExitUsage, Command: command,
			What: "--soundcheck needs --apply \"<command that installs the update on staging>\" for Composer and npm packages"}
	}
	return nil
}

// notProduction refuses a staging host that a production entry names
// (E14).
func (s *stager) notProduction(prods []production) error {
	for _, pr := range prods {
		if pr.matches(s.host) {
			return &core.Error{Code: core.EProduction, Exit: cli.ExitUsage, Command: s.p.Command,
				What: fmt.Sprintf("%s is listed as production in %s", s.host, pr.from),
				Hint: []string{"--soundcheck applies the update to the site; point it at a staging copy (rhythm roadie copy makes one)"}}
		}
	}
	return nil
}

// findHelpers finds rhythm-soundcheck and, unless skipped,
// rhythm-roadie (E15 when they are missing).
func (s *stager) findHelpers() error {
	s.soundcheck, s.roadie = s.p.Soundcheck, s.p.Roadie
	var missing []string
	if s.soundcheck == "" {
		if s.soundcheck, _ = proc.LookPath("rhythm-soundcheck"); s.soundcheck == "" {
			missing = append(missing, "soundcheck")
		}
	}
	if s.roadie == "" && !s.p.SkipRoadie {
		if s.roadie, _ = proc.LookPath("rhythm-roadie"); s.roadie == "" {
			missing = append(missing, "roadie")
		}
	}
	switch len(missing) {
	case 0:
		return nil
	case 1:
		return &core.Error{Code: core.ESoundcheckMissing, Exit: cli.ExitUnavailable,
			What: "--soundcheck needs rhythm-" + missing[0], Hint: []string{"install it with: rhythm install " + missing[0]}}
	}
	return &core.Error{Code: core.ESoundcheckMissing, Exit: cli.ExitUnavailable,
		What: "--soundcheck needs rhythm-soundcheck and rhythm-roadie", Hint: []string{"install them with: rhythm install soundcheck roadie"}}
}

// installVerified installs the reviewed archive of ref through WP-CLI.
func (s *stager) installVerified(ctx context.Context, ref core.Ref, sha string) error {
	zipPath, done, err := s.verifiedZip(ref, sha)
	if err != nil {
		return err
	}
	defer done()
	return s.installZip(ctx, s.u.Eco, ref, zipPath)
}

// rollback reinstalls the reviewed old version. Only an update Sightread
// installed itself can go back that way: after --apply the old bytes
// are the user's to put back. It reports whether it rolled back.
func (s *stager) rollback(ctx context.Context, rep *core.Report) (bool, error) {
	u := s.u
	if len(s.p.Apply) > 0 || u.From.Version == "" {
		rep.Notes = append(rep.Notes, NoteNoRollback)
		return false, nil
	}
	old := core.Ref{Eco: u.Eco, Name: u.Name, Version: u.From.Version}
	if err := s.installVerified(ctx, old, u.From.SHA256); err != nil {
		return false, err
	}
	return true, nil
}

// short is the first 12 hex digits of a sha256, as reports show it.
func short(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
