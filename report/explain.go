// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package report

import (
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

func init() { core.SetExplainRenderer(Explainer{}) }

// Explainer renders `explain` (PRD 6.5) in the layout of rhythm-tuner
// explain: the signal's name and facts, then Why it matters, How to
// review, False alarms, Incidents and More. cmd reaches it through
// core.GetExplainRenderer.
type Explainer struct{}

var _ core.ExplainRenderer = Explainer{}

// The lines explain prints word for word.
const (
	// archiveMissing is printed when the cached archives of a finding's
	// update are gone, so its hunk can't be shown (PRD 6.5).
	archiveMissing = "archive not in cache: run the review again (it is cached for 30 days)"
	// localMissing is printed instead when a side was a local file,
	// which is never cached; the report holds no hunk of the file either.
	localMissing = "a local file's diff is never cached and the report holds no hunk of this file: " +
		"run the review again with the same local files, with -o review.html for the full diff"
	// inLockfile follows the lockfile path of a finding there: it is
	// not in the package, so no archive has a diff of it.
	inLockfile = " is the project's lockfile, not a file in the package, so there is no package diff to show"
	// explainMissing is printed for a catalogue signal with no explain
	// text linked. A release never shows it: a test of the linked binary
	// fails on it.
	explainMissing = "No explain text is linked for this signal."
)

// RenderSignal writes what id means and how to review it. An ID outside
// the catalogue is an E13 usage error with a suggestion.
func (Explainer) RenderSignal(w io.Writer, id string, o core.WriteOptions, asJSON bool) error {
	s, ok := core.Signal(id)
	if !ok {
		return unknownSignal(id, o)
	}
	e, has := explainFor(id)
	if asJSON {
		return writeExplainJSON(w, core.ExplainData{Signal: s, Explain: e}, has, o)
	}
	ew := newExplainWriter(o)
	ew.signal(s, e, has)
	_, err := io.WriteString(w, ew.b.String())
	return err
}

// RenderFinding writes one finding of a saved report: its facts, its
// evidence, raised or demoted notes, the hunks that hold it and then the
// signal's explain text. sel is the finding's 1-based number in report
// order (updates as listed, then their findings) or its fingerprint.
// hunks are the changed file's hunks with 6 lines of context, read from
// the cached archives, or the report's own hunks of the file; nil means
// neither had them (a local file is never cached, so it says so). A
// finding in the project's lockfile has no hunks and says so.
func (Explainer) RenderFinding(w io.Writer, r *core.Report, sel string, hunks []core.Hunk, o core.WriteOptions, asJSON bool) error {
	u, f, n, total, err := selectFinding(r, sel)
	if err != nil {
		return err
	}
	s, ok := core.Signal(f.ID)
	if !ok {
		// A rule from a --signals folder: describe it from the finding.
		s = core.SignalInfo{ID: f.ID, Title: f.Title, Severity: f.Severity, Confidence: f.Confidence, Ecosystems: []core.Ecosystem{u.Eco}}
	}
	e, has := explainFor(f.ID)
	shown := findingHunks(f, hunks)
	if asJSON {
		d := core.ExplainData{Signal: s, Explain: e, Finding: f, Hunks: shown}
		return writeExplainJSON(w, d, has && (f.File == "" || f.InLockfile() || hunks != nil), o)
	}
	ew := newExplainWriter(o)
	ew.finding(u, f, n, total)
	switch {
	case f.File == "":
	case f.InLockfile():
		ew.section("Diff", where(f)+inLockfile)
	case hunks == nil && (u.From.Local() || u.To.Local()):
		ew.section("Diff", localMissing)
	case hunks == nil:
		ew.section("Diff", archiveMissing)
	case len(shown) == 0:
		ew.section("Diff", "no change in "+tt(f.File)+" in this update's diff")
	default:
		ew.hunks(shown)
	}
	ew.b.WriteString("\n")
	ew.signal(s, e, has)
	_, err = io.WriteString(w, ew.b.String())
	return err
}

// explainFor is core.ExplainFor with empty text counted as missing.
func explainFor(id string) (core.Explain, bool) {
	e, ok := core.ExplainFor(id)
	return e, ok && e != (core.Explain{})
}

// writeExplainJSON writes a kind explain document. complete is false
// when explain text or the hunks are missing.
func writeExplainJSON(w io.Writer, d core.ExplainData, complete bool, o core.WriteOptions) error {
	return JSONWriter{}.WriteDocument(w, core.Envelope{Kind: core.KindExplain, Complete: complete, Verdict: core.VerdictOK, Data: d}, o)
}

// unknownSignal is the E13 error for an ID outside the catalogue.
func unknownSignal(id string, o core.WriteOptions) *core.Error {
	e := &core.Error{Code: core.EBadFlag, Exit: cli.ExitUsage, Command: "explain", What: "no signal \"" + tt(id) + "\""}
	if s := core.SuggestSignal(id); s != "" {
		e.What += " (did you mean " + s + "?)"
	} else {
		e.Hint = []string{tt(programName(o.Program)) + " signals lists them"}
	}
	return e
}

// selectFinding finds sel in r. It returns the update, the finding, its
// 1-based number and the number of findings.
func selectFinding(r *core.Report, sel string) (*core.Update, *core.Finding, int, int, error) {
	total := 0
	for i := range r.Updates {
		total += len(r.Updates[i].Findings)
	}
	sel = strings.TrimSpace(sel)
	// A fingerprint is 16 hex characters, so a short run of digits is a
	// number.
	want, numErr := strconv.Atoi(sel)
	byNumber := numErr == nil && len(sel) <= 5
	n := 0
	for i := range r.Updates {
		u := &r.Updates[i]
		for j := range u.Findings {
			n++
			f := &u.Findings[j]
			if byNumber && n == want || !byNumber && strings.EqualFold(f.Fingerprint, sel) {
				return u, f, n, total, nil
			}
		}
	}
	e := &core.Error{Code: core.EBadFlag, Exit: cli.ExitUsage, Command: "explain"}
	switch {
	case byNumber:
		e.What = fmt.Sprintf("the report has no finding %d (it has %s)", want, plural(total, "finding", "findings"))
		e.Hint = []string{"findings are numbered from 1 in report order; a fingerprint from the JSON works too"}
	default:
		e.What = "the report has no finding with fingerprint \"" + tt(sel) + "\""
		e.Hint = []string{"give a number from 1 to " + strconv.Itoa(total) + " or a fingerprint from the JSON report"}
	}
	return nil, nil, 0, total, e
}

// findingHunks returns the hunks of f's file that hold one of its lines,
// or every hunk of the file when none does.
func findingHunks(f *core.Finding, hunks []core.Hunk) []core.Hunk {
	if f.File == "" {
		return nil
	}
	var same, cover []core.Hunk
	for _, h := range hunks {
		if h.Path != f.File {
			continue
		}
		same = append(same, h)
		if covers(h, f) {
			cover = append(cover, h)
		}
	}
	if len(cover) > 0 {
		return cover
	}
	return same
}

// explainWriter builds explain's text.
type explainWriter struct {
	b     strings.Builder
	o     core.WriteOptions
	width int
}

func newExplainWriter(o core.WriteOptions) *explainWriter {
	cols := o.Width
	if cols <= 0 {
		cols = termDefaultColumns
	}
	return &explainWriter{o: o, width: max(cols, 40)}
}

// field writes "  Label:      value" when value is set.
func (e *explainWriter) field(label, value string) {
	if value == "" {
		return
	}
	pad := 13
	lines := wrap(value, e.width-2-pad)
	for i, l := range lines {
		if i == 0 {
			fmt.Fprintf(&e.b, "  %-*s%s\n", pad, label+":", l)
		} else {
			fmt.Fprintf(&e.b, "  %s%s\n", strings.Repeat(" ", pad), l)
		}
	}
}

// numbered matches a numbered step, which wraps under its text.
var numbered = regexp.MustCompile(`^\d+\. `)

// section writes a heading and its body indented by two spaces. Each
// line of the body is wrapped on its own, so steps and incidents keep
// one per line; a numbered step wraps under its text.
func (e *explainWriter) section(title, body string) {
	body = strings.TrimSpace(body)
	if body == "" {
		return
	}
	fmt.Fprintf(&e.b, "\n%s\n", title)
	for _, line := range strings.Split(tt(body), "\n") {
		line = strings.TrimRight(line, " \t")
		if line == "" {
			e.b.WriteString("\n")
			continue
		}
		hang := ""
		if m := numbered.FindString(line); m != "" {
			hang = strings.Repeat(" ", len(m))
		}
		for i, l := range wrap(line, e.width-2-len(hang)) {
			if i > 0 {
				l = hang + l
			}
			e.b.WriteString("  " + l + "\n")
		}
	}
}

// signal writes a signal's facts and explain text.
func (e *explainWriter) signal(s core.SignalInfo, x core.Explain, has bool) {
	fmt.Fprintf(&e.b, "%s: %s\n", tt(s.ID), tt(s.Title))
	e.field("Severity", s.Severity.String())
	e.field("Confidence", string(s.Confidence))
	ecos := make([]string, 0, len(s.Ecosystems))
	for _, eco := range s.Ecosystems {
		ecos = append(ecos, string(eco))
	}
	e.field("Ecosystems", strings.Join(ecos, ", "))
	if s.Unignorable {
		e.field("Unignorable", "yes: it can't be ignored, allowed or lowered below critical")
	}
	if !has {
		e.b.WriteString("\n" + explainMissing + "\n")
	}
	e.section("Why it matters", x.Why)
	e.section("How to review", x.HowToReview)
	e.section("False alarms", x.FalseAlarms)
	e.section("Incidents", x.Incidents)
	more := strings.TrimSpace(x.More)
	if more == "" {
		more = helpURI(s.ID)
	}
	e.section("More", more)
}

// finding writes one finding's facts, evidence and advice.
func (e *explainWriter) finding(u *core.Update, f *core.Finding, n, total int) {
	fmt.Fprintf(&e.b, "Finding %d of %d: %s: %s\n", n, total, tt(f.ID), tt(f.Title))
	from := ""
	if u.From.Version != "" {
		from = tt(u.From.Version) + " → "
	}
	e.field("Update", tt(string(u.Eco))+" "+tt(u.Name)+" "+from+tt(u.To.Version)+" ("+strings.ToUpper(string(u.Verdict))+")")
	sev := f.Severity.String()
	if len(f.RaisedBy) > 0 {
		sev += " (raised by " + tt(strings.Join(f.RaisedBy, ", ")) + ")"
	}
	if f.Demoted != "" {
		sev += " (demoted: " + tt(f.Demoted) + ")"
	}
	e.field("Severity", sev)
	e.field("Confidence", string(f.Confidence))
	where := where(f)
	if where != "" && f.EndLine > f.Line {
		where += "-" + strconv.Itoa(f.EndLine)
	}
	e.field("Where", where)
	e.field("Domains", tt(strings.Join(f.Domains, ", ")))
	e.field("Fingerprint", tt(f.Fingerprint))
	e.field("Counted", countedText(f))
	e.section("Evidence", f.Evidence.String())
	e.section("Advice", f.Advice)
}

// countedText says whether a finding counts and why not.
func countedText(f *core.Finding) string {
	switch {
	case f.Allowed != nil:
		a := f.Allowed
		s := "no: allowed by " + tt(a.By)
		if a.Date != "" {
			s += " on " + tt(a.Date)
		}
		if a.Reason != "" {
			s += ": " + tt(a.Reason)
		}
		return s
	case f.Baselined:
		return "no: in the baseline"
	case f.Ignored:
		return "no: ignored by config"
	case f.BelowConfidence:
		return "no: below --min-confidence"
	}
	return "yes"
}

// hunks writes the diff hunks, one output line per hunk line.
func (e *explainWriter) hunks(hs []core.Hunk) {
	e.b.WriteString("\nDiff\n")
	for _, h := range hs {
		e.b.WriteString("  " + hunkTitle(h, tt(h.Path)) + "\n")
		for _, l := range h.Lines {
			e.b.WriteString("  " + strings.NewReplacer("\r", `\r`, "\n", `\n`).Replace(tt(l)) + "\n")
		}
	}
}
