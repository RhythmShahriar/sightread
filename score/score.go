// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package score

import (
	"cmp"
	"context"
	"fmt"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

func init() { core.SetScorer(New()) }

// Scorer implements core.Scorer.
type Scorer struct {
	// Now is the clock that expires ignore entries.
	Now func() time.Time

	mu sync.Mutex
	// notes holds the Report.Notes lines Score found for an update until
	// Summarise sees the report: Score gets one update, Summarise the
	// report. Keyed by the update's identity, not its address, as the
	// pipeline may copy an update between the two.
	notes map[string][]string
	// configName is the config the unanalysed note names.
	configName string
}

// maxNoteUpdates bounds notes for a caller that scores without ever
// summarising, such as a long watch: past it the oldest run's notes are
// dropped. A real run holds far fewer updates.
const maxNoteUpdates = 1 << 16

// SetConfigPath names the config file the header notes cite, as the user
// should see it (--config may name any file). Empty means the usual
// .sightread/config.yaml.
func (s *Scorer) SetConfigPath(p string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configName = p
}

// New returns a Scorer on the real clock.
func New() *Scorer { return &Scorer{Now: time.Now} }

var _ core.Scorer = (*Scorer)(nil)

func (s *Scorer) now() time.Time {
	if s.Now == nil {
		return time.Now()
	}
	return s.Now()
}

// unanalysedNote is the header line for a lowered unanalysed
// signal (PRD 0): the severity, then the config file.
const unanalysedNote = "unanalysed lowered to %s by %s"

// defaultConfigName is the config the notes name when SetConfigPath was
// not called.
const defaultConfigName = ".sightread/config.yaml"

// inChangeNote is the header line for an allow entry the change under
// review added itself.
const inChangeNote = "%s: allowed in this change, not counted (--trust-pr-allow counts it)"

// Score applies, in order: catalogue defaults, signals.severity
// overrides, the context rules of PRD 12.2 (owner change raises, same
// function raises, vendored paths demote), ignore entries, the allow
// entry for this archive, the baseline and --min-confidence. Then it
// fingerprints and sorts the findings and sets the verdict. Unignorable
// signals are never lowered below critical, ignored, allowed, demoted
// or baselined.
func (s *Scorer) Score(_ context.Context, u *core.Update, cfg *core.Config, allow core.AllowSet, baseline map[string]bool) {
	if cfg == nil {
		cfg = &core.Config{}
	}
	// Scoring an update again replaces what it noted before.
	s.takeNotes(u)
	overrides := severityOverrides(cfg)
	for i := range u.Findings {
		f := &u.Findings[i]
		fillDefaults(f)
		if sev, ok := overrides[f.ID]; ok && (sev == cli.SeverityCritical || !core.Unignorable(f.ID)) {
			f.Severity = sev
		}
	}
	if sev, ok := overrides["unanalysed"]; ok && sev < defaultSeverity("unanalysed") {
		s.note(u, fmt.Sprintf(unanalysedNote, sev, s.configShown()))
	}

	raiseOwnerChange(u.Findings)
	raiseSameFunction(u.Findings)
	demoteVendored(u.Eco, u.Findings)

	s.ignore(u, cfg.Ignore)
	s.allow(u, allow)

	for i := range u.Findings {
		f := &u.Findings[i]
		f.Fingerprint = core.Fingerprint(u.Eco, u.Name, u.To.Version, f.ID, f.File, f.Evidence)
		if baseline[f.Fingerprint] && f.Counted() && !core.Unignorable(f.ID) {
			f.Baselined = true
		}
	}
	if cfg.MinConfidence == string(core.Confirmed) {
		for i := range u.Findings {
			f := &u.Findings[i]
			if f.Confidence == core.Likely && f.Counted() && !core.Unignorable(f.ID) {
				f.BelowConfidence = true
			}
		}
	}
	SortFindings(u.Findings)
	u.Verdict = Verdict(u)
}

// fillDefaults fills what a detector left empty from the catalogue and
// the explain text.
func fillDefaults(f *core.Finding) {
	info, ok := core.Signal(f.ID)
	if !ok {
		return
	}
	if f.Title == "" {
		f.Title = info.Title
	}
	if f.Severity == cli.SeverityNone {
		f.Severity = info.Severity
	}
	if f.Confidence == "" {
		f.Confidence = info.Confidence
	}
	if f.Advice == "" {
		if e, ok := core.ExplainFor(f.ID); ok {
			f.Advice = e.Advice
		}
	}
	if info.Unignorable && f.Severity < cli.SeverityCritical {
		f.Severity = cli.SeverityCritical
	}
}

func defaultSeverity(id string) cli.Severity {
	info, _ := core.Signal(id)
	return info.Severity
}

// severityOverrides parses signals.severity. Package policy validated it;
// a value that still doesn't parse is skipped rather than guessed.
func severityOverrides(cfg *core.Config) map[string]cli.Severity {
	out := map[string]cli.Severity{}
	for id, v := range cfg.Signals.Severity {
		if sev, err := cli.ParseFailOn(v); err == nil && sev != cli.SeverityNone {
			out[id] = sev
		}
	}
	return out
}

// ignore marks findings an active ignore entry covers.
func (s *Scorer) ignore(u *core.Update, list []core.IgnoreEntry) {
	if len(list) == 0 {
		return
	}
	today := s.now().Format(time.DateOnly)
	pkg := string(u.Eco) + ":" + u.Name
	for i := range u.Findings {
		f := &u.Findings[i]
		if core.Unignorable(f.ID) {
			continue
		}
		for _, ig := range list {
			if ig.Until != "" && ig.Until < today {
				continue
			}
			if ig.ID != f.ID || !matchPackage(ig.Package, pkg) || !matchPath(ig.Path, f.File) {
				continue
			}
			f.Ignored = true
			break
		}
	}
}

// matchPackage matches an ignore package glob against "<eco>:<name>".
// The input shorthands plugin: and theme: work here too.
func matchPackage(pattern, pkg string) bool {
	if pattern == "" {
		return true
	}
	if eco, rest, ok := strings.Cut(pattern, ":"); ok {
		if e, err := core.ParseEcosystem(eco); err == nil {
			pattern = string(e) + ":" + rest
		}
	}
	ok, _ := path.Match(pattern, pkg)
	return ok
}

// matchPath matches an ignore path glob against a file inside the
// package. A pattern that matches a folder covers what is inside it, so
// "src/Admin/*" covers src/Admin/Notes/feed.php as well. A leading slash
// is optional on both.
func matchPath(pattern, file string) bool {
	if pattern == "" {
		return true
	}
	pattern = strings.TrimPrefix(pattern, "/")
	file = strings.TrimPrefix(strings.ReplaceAll(file, `\`, "/"), "/")
	for p := file; p != "" && p != "."; p = path.Dir(p) {
		if ok, _ := path.Match(pattern, p); ok {
			return true
		}
		if !strings.Contains(p, "/") {
			break
		}
	}
	return false
}

// kindMatcher is an allow set that can compare only entries recording
// the same hash kind as the update (policy.AllowSet). core.AllowSet has
// no kind, so the scorer asks for it.
type kindMatcher interface {
	MatchKind(eco core.Ecosystem, name, version, sha256, kind string) (*core.AllowEntry, bool, *core.AllowEntry)
}

// allow applies the allow entry for this exact archive, or adds
// approved-version-changed when an entry records another hash for the
// same version.
func (s *Scorer) allow(u *core.Update, allow core.AllowSet) {
	if allow == nil || u.To.SHA256 == "" {
		// Without a hash there is nothing to bind an entry to; an
		// unverified update is never allowed.
		return
	}
	var match, conflict *core.AllowEntry
	var counted bool
	if k, ok := allow.(kindMatcher); ok && u.To.HashKind != "" {
		match, counted, conflict = k.MatchKind(u.Eco, u.Name, u.To.Version, u.To.SHA256, u.To.HashKind)
	} else {
		match, counted, conflict = allow.Match(u.Eco, u.Name, u.To.Version, u.To.SHA256)
	}
	if match != nil && !counted {
		// Shown, never applied: a change can't approve its own update.
		s.note(u, fmt.Sprintf(inChangeNote, core.Ref{Eco: u.Eco, Name: u.Name, Version: u.To.Version}))
	}
	if match != nil && counted {
		am := &core.AllowMatch{By: match.By, Reason: match.Reason, Date: match.Date, Until: match.Until}
		if src, ok := allow.(interface{ Source(*core.AllowEntry) string }); ok {
			am.Source = src.Source(match)
		}
		for i := range u.Findings {
			f := &u.Findings[i]
			if !f.Counted() || core.Unignorable(f.ID) {
				continue
			}
			if len(match.Signals) == 0 || slices.Contains(match.Signals, f.ID) {
				a := *am
				f.Allowed = &a
			}
		}
	}
	if conflict != nil {
		f := core.Finding{
			ID:       "approved-version-changed",
			Evidence: core.NewSnippet(fmt.Sprintf("allowed on %s by %s with sha256 %s; now %s", conflict.Date, conflict.By, short(conflict.SHA256), short(u.To.SHA256))),
		}
		fillDefaults(&f)
		u.Findings = append(u.Findings, f)
	}
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

func (s *Scorer) configShown() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.configName == "" {
		return defaultConfigName
	}
	return s.configName
}

func (s *Scorer) note(u *core.Update, line string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := updateKey(u)
	if s.notes == nil || len(s.notes) >= maxNoteUpdates && s.notes[k] == nil {
		s.notes = map[string][]string{}
	}
	if !slices.Contains(s.notes[k], line) {
		s.notes[k] = append(s.notes[k], line)
	}
}

// takeNotes returns and forgets the notes Score left for u.
func (s *Scorer) takeNotes(u *core.Update) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := updateKey(u)
	n := s.notes[k]
	delete(s.notes, k)
	return n
}

func updateKey(u *core.Update) string {
	return strings.Join([]string{string(u.Eco), u.Name, u.From.Version, u.To.Version, u.To.SHA256}, "|")
}

// SortFindings orders findings as every output shows them (PRD 12.2
// rule 5): severity, worst first, then confidence, file, line, signal ID
// and fingerprint, so the order never depends on timing.
func SortFindings(fs []core.Finding) {
	conf := func(c core.Confidence) int {
		if c == core.Confirmed {
			return 0
		}
		return 1
	}
	slices.SortStableFunc(fs, func(a, b core.Finding) int {
		return cmp.Or(
			cmp.Compare(b.Severity, a.Severity),
			cmp.Compare(conf(a.Confidence), conf(b.Confidence)),
			strings.Compare(a.File, b.File),
			cmp.Compare(a.Line, b.Line),
			strings.Compare(a.ID, b.ID),
			strings.Compare(a.Fingerprint, b.Fingerprint),
		)
	})
}

// Verdict decides an update's verdict from its findings (PRD 5.6). Only
// counted findings decide: any critical is HOLD, any high or medium
// REVIEW. When nothing counts and at least one finding was allowed it is
// ALLOWED, otherwise ROUTINE. A side verified by nothing makes it
// UNVERIFIED whatever the findings say; it is still scored with
// --allow-unverified and the gate still sees its findings.
func Verdict(u *core.Update) core.Verdict {
	if u.To.Verified == core.ByNone || u.From.Version != "" && u.From.Verified == core.ByNone {
		return core.Unverified
	}
	worst, allowed := cli.SeverityNone, 0
	for _, f := range u.Findings {
		if f.Allowed != nil {
			allowed++
		}
		if f.Counted() {
			worst = max(worst, f.Severity)
		}
	}
	switch {
	case worst == cli.SeverityCritical:
		return core.Hold
	case worst >= cli.SeverityMedium:
		return core.Review
	case worst == cli.SeverityNone && allowed > 0:
		return core.Allowed
	}
	return core.Routine
}
