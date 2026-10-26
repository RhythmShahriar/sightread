// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package report

import (
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/ui"
	"github.com/RhythmShahriar/sightread/core"
)

func init() { core.RegisterWriter(TerminalWriter{}) }

// TerminalWriter writes the report for a person at a terminal (PRD 9.1),
// in Tuner's look: a ♪ header and rule, ▸ facts, severity groups with ▌
// bars, a rounded verdict box, ! notes and → next steps. With
// WriteOptions.Plain it drops color, boxes and glyphs for logs and
// screen readers; with Quiet it prints the table and findings only.
type TerminalWriter struct{}

var _ core.Writer = TerminalWriter{}

// Format returns "terminal".
func (TerminalWriter) Format() string { return core.FormatTerminal }

// The lines PRD 9.1 fixes word for word.
const (
	readOnlyLine       = "Read-only. Sightread changes nothing on your site and never runs the code it downloads."
	readOnlySoundcheck = "Read-only here. --soundcheck installs the update on the staging copy, where its code runs."
	cleanLine          = "No risk signals found. This is a static diff, not proof the update is safe."
	moreLine           = "(see -o review.html)"
)

const (
	// The report is as wide as the terminal less a margin, within these
	// bounds, as in Tuner: narrower breaks the card layout, wider is hard
	// to read.
	termMinWidth, termMaxWidth = 56, 100
	termDefaultColumns         = 80 // when WriteOptions.Width is unset

	factLabel      = 13 // the label column of a ▸ fact
	badgeWidth     = 10 // " CRITICAL "
	titleIndent    = badgeWidth + 2
	evidenceLines  = 3  // evidence lines a card shows
	minFindingsCol = 12 // the FINDINGS column keeps at least this much
)

// Write writes r for a terminal.
func (TerminalWriter) Write(w io.Writer, r *core.Report, o core.WriteOptions) error {
	t := newTermView(r, o)
	t.render()
	_, err := io.WriteString(w, t.b.String())
	return err
}

// termView renders one report.
type termView struct {
	b     strings.Builder
	r     *core.Report
	o     core.WriteOptions
	p     paths
	cols  int // the terminal's columns
	width int // content width: the rule is this wide

	brand, bold, muted, mutedBold, warn, good, danger lipgloss.Style
	re                                                *lipgloss.Renderer
}

func newTermView(r *core.Report, o core.WriteOptions) *termView {
	cols := o.Width
	if cols <= 0 {
		cols = termDefaultColumns
	}
	// A renderer of its own: the color profile comes from the options,
	// never from whatever the process's stdout happens to be; it also
	// never queries the terminal for its background.
	re := lipgloss.NewRenderer(io.Discard)
	re.SetHasDarkBackground(true)
	if o.Color && !o.Plain {
		re.SetColorProfile(termenv.TrueColor)
	} else {
		re.SetColorProfile(termenv.Ascii)
	}
	t := &termView{r: r, o: o, p: newPaths(r.Target.Path, o.RedactPaths), re: re, cols: cols,
		width: min(max(cols-8, termMinWidth), termMaxWidth)}
	t.brand = re.NewStyle().Foreground(ui.Signal).Bold(true)
	t.bold = re.NewStyle().Bold(true)
	t.muted = re.NewStyle().Foreground(lipgloss.Color(ui.Muted))
	t.mutedBold = t.muted.Bold(true)
	t.warn = re.NewStyle().Foreground(lipgloss.Color(ui.Warn)).Bold(true)
	t.good = re.NewStyle().Foreground(lipgloss.Color(ui.Ok))
	t.danger = re.NewStyle().Foreground(lipgloss.Color(ui.Danger)).Bold(true)
	return t
}

// line writes one line.
func (t *termView) line(s string) { t.b.WriteString(s + "\n") }

// blank writes an empty line.
func (t *termView) blank() { t.b.WriteString("\n") }

func (t *termView) sevStyle(s cli.Severity) lipgloss.Style {
	return t.re.NewStyle().Foreground(ui.SeverityColor(s.String())).Bold(true)
}

// verdictColors color the verdict words the way the HTML pills do.
var verdictColors = map[core.Verdict]string{
	core.Hold: ui.Danger, core.Review: ui.High, core.Unverified: ui.Warn, core.Allowed: ui.Ok, core.Routine: ui.Ok,
}

func (t *termView) verdictStyle(v core.Verdict) lipgloss.Style {
	c, ok := verdictColors[v]
	if !ok {
		c = ui.Muted
	}
	return t.re.NewStyle().Foreground(lipgloss.Color(c)).Bold(true)
}

// single reports whether the report gets the one-update layout.
func (t *termView) single() bool { return len(t.r.Updates) == 1 }

func (t *termView) render() {
	if t.o.Quiet {
		t.table()
		t.sections()
		return
	}
	t.header()
	if t.single() {
		u := &t.r.Updates[0]
		t.facts(u)
		t.groups(u)
		t.diff(u)
	} else {
		t.multi()
	}
	t.unverifiedList()
	t.notChecked()
	t.box()
	t.footer()
	t.next()
}

// tt is text for the terminal (see termText).
func tt(s string) string { return termText(s) }

// isBidi reports whether r is a bidi control (core.IsBidi).
func isBidi(r rune) bool { return core.IsBidi(r) }

// termText is text for the terminal. SR-50 wants bidi controls shown,
// not dropped: a reviewer must see that a changelog or a name holds one.
// kit term.Sanitize (inside text) drops them, so they are escaped here
// first, as \u202e. Escaping splits the text at each control; when a
// secret spans one, the halves may no longer look like a key, so then
// the masking of the whole text decides and the controls are dropped.
func termText(s string) string {
	if !strings.ContainsFunc(s, isBidi) {
		return text(s)
	}
	var shown, joined strings.Builder
	seg := 0
	for i, r := range s {
		if !isBidi(r) {
			continue
		}
		part := text(s[seg:i])
		shown.WriteString(part + fmt.Sprintf(`\u%04x`, r))
		joined.WriteString(part)
		seg = i + len(string(r))
	}
	part := text(s[seg:])
	shown.WriteString(part)
	joined.WriteString(part)
	if joined.String() != text(s) {
		return text(s)
	}
	return shown.String()
}

// header writes the ♪ line, the rule, the read-only line and the notes.
func (t *termView) header() {
	prog, ver := tt(programName(t.o.Program)), toolVersion(t.o.Version)
	var subject []string
	if t.single() {
		u := &t.r.Updates[0]
		subject = []string{tt(string(u.Eco)) + " " + tt(u.Name), t.fromTo(u)}
	} else {
		if p := t.p.path(t.r.Target.Path); p != "" {
			subject = append(subject, tt(p))
		}
		if wp := t.r.Target.WordPress; wp != "" {
			subject = append(subject, "WordPress "+tt(wp))
		}
		if len(subject) == 0 {
			subject = append(subject, plural(len(t.r.Updates), "update", "updates"))
		}
	}
	readOnly := readOnlyLine
	if t.o.Soundcheck {
		readOnly = readOnlySoundcheck
	}
	if t.o.Plain {
		t.line(prog + " " + ver + " - " + strings.Join(subject, " - "))
		t.line(readOnly)
		for _, n := range t.r.Notes {
			t.line("note: " + tt(n))
		}
		t.blank()
		return
	}
	left := t.brand.Render("♪") + " " + t.bold.Render(prog) + " " + t.muted.Render(ver)
	head := left + "  " + strings.Join(subject, "  ")
	t.blank()
	// The header may use the whole terminal, as in PRD 9.1, so one
	// update's name and versions stay on one line at 80 columns.
	if lipgloss.Width(head) <= t.cols-2 {
		t.line("  " + head)
	} else {
		t.line("  " + left)
		for _, l := range wrap(strings.Join(subject, "  "), t.width-2) {
			t.line("    " + l)
		}
	}
	t.line("  " + t.muted.Render(strings.Repeat("─", t.width)))
	for _, l := range wrap(readOnly, t.width) {
		t.line("  " + l)
	}
	for _, n := range t.r.Notes {
		t.note(tt(n), t.warn)
	}
	t.blank()
}

// note writes a "! " line, wrapped.
func (t *termView) note(s string, style lipgloss.Style) {
	if t.o.Plain {
		t.line("note: " + s)
		return
	}
	for i, l := range wrap(s, t.width-2) {
		lead := "! "
		if i > 0 {
			lead = "  "
		}
		t.line("  " + style.Render(lead+l))
	}
}

// fromTo is "2.6.7 → 2.6.8", "1.0.0 (new)" for a new package, with "to"
// for the arrow in plain mode.
func (t *termView) fromTo(u *core.Update) string {
	if u.From.Version == "" {
		return tt(u.To.Version) + " (new)"
	}
	arrow := " → "
	if t.o.Plain {
		arrow = " to "
	}
	return tt(u.From.Version) + arrow + tt(u.To.Version)
}

// mark is a ✓ or ✗ after a fact; plain mode has none.
func (t *termView) mark(ok bool) string {
	switch {
	case t.o.Plain:
		return ""
	case ok:
		return " " + t.good.Render("✓")
	}
	return " " + t.danger.Render("✗")
}

// dot separates the parts of a fact.
func (t *termView) dot() string {
	if t.o.Plain {
		return ", "
	}
	return " · "
}

// fact writes one ▸ line, its value wrapped under itself.
func (t *termView) fact(label, value string) {
	if t.o.Plain {
		t.line(label + ": " + value)
		return
	}
	indent := strings.Repeat(" ", 4+factLabel+1)
	for i, l := range wrap(value, t.width-factLabel-3) {
		if i == 0 {
			t.line("  " + t.brand.Render("▸") + " " + t.mutedBold.Width(factLabel).Render(label) + " " + l)
		} else {
			t.line(indent + l)
		}
	}
}

func (t *termView) facts(u *core.Update) {
	t.fact("Installed", t.installedText(u))
	t.fact("Candidate", t.candidateText(u))
	t.fact("Integrity", t.integrityFact(u))
	t.fact("Publisher", t.publisherFact(u))
	t.fact("Diff", t.diffText(u))
	t.fact("Changelog", t.changelogText(u))
	if len(u.Sites) > 0 {
		t.fact("Sites", tt(strings.Join(u.Sites, ", ")))
	}
	if s := u.Soundcheck; s != nil {
		v := tt(soundcheckCounts(s))
		if s.Staging != "" {
			v = tt(s.Staging) + ": " + v
		}
		if s.RolledBack {
			v += t.dot() + "rolled back"
		}
		if s.Report != "" {
			v += t.dot() + tt(s.Report)
		}
		if s.Error != "" && !s.NotCompared {
			v += t.dot() + "failed: " + tt(s.Error)
		}
		if s.Applied != "" {
			t.fact("Applied", tt(s.Applied))
		}
		if s.RoadieVerify != "" {
			t.fact("Roadie", tt(s.RoadieVerify))
		}
		t.fact("Soundcheck", v)
	}
	t.blank()
}

// sourceName is where the package comes from, for "matches wordpress.org".
func sourceName(u *core.Update) string {
	for _, s := range []string{u.From.Source, u.To.Source} {
		if s != "" {
			return text(s)
		}
	}
	return "the official copy"
}

func (t *termView) installedText(u *core.Update) string {
	if u.From.Version == "" {
		return "not installed: a new package"
	}
	v := tt(u.From.Version)
	switch in := u.Installed; {
	case in.Path != "":
		v += " in " + tt(t.p.path(in.Path))
	case in.Lockfile != "" && in.LockLine > 0:
		v += " in " + tt(t.p.path(in.Lockfile)) + ":" + strconv.Itoa(in.LockLine)
	case in.Lockfile != "":
		v += " in " + tt(t.p.path(in.Lockfile))
	}
	switch {
	case u.Installed.Drift:
		d := "differs from the " + sourceName(u) + " copy"
		if n := len(u.Installed.DriftFiles); n > 0 {
			d = plural(n, "file differs", "files differ") + " from the " + sourceName(u) + " copy"
		}
		v += t.dot() + d + t.mark(false)
	case u.Installed.Path != "" && (u.From.Verified == core.ByChecksums || u.From.Verified == core.BySVN):
		// Only a copy on disk was compared with the source. With --from
		// or --from-tuner the site's files were never read, so the line
		// says nothing about them (PRD principle 4).
		v += t.dot() + "matches " + sourceName(u) + t.mark(true)
	}
	return v
}

func (t *termView) candidateText(u *core.Update) string {
	parts := []string{tt(u.To.Version)}
	if !u.To.Released.IsZero() {
		parts = append(parts, "released "+u.To.Released.UTC().Format(time.DateOnly))
	}
	switch {
	case u.To.Latest:
		parts = append(parts, "latest")
	case u.To.Wanted && u.To.Constraint != "":
		parts = append(parts, "newest allowed by "+tt(u.To.Constraint))
	case u.To.Wanted:
		parts = append(parts, "wanted")
	}
	return strings.Join(parts, t.dot())
}

// verified reports whether a side was checked against its source.
func verified(s core.Side) bool {
	return s.Verified != "" && s.Verified != core.ByNone && s.Verified != core.ByFailed
}

func (t *termView) integrityFact(u *core.Update) string {
	v := integrityText(u)
	switch {
	case u.To.Verified == core.ByFailed || u.From.Verified == core.ByFailed:
		return v + t.mark(false)
	case verified(u.To) && (u.From.Version == "" || verified(u.From)):
		return v + t.mark(true)
	}
	return v
}

func (t *termView) publisherFact(u *core.Update) string {
	from, to := tt(strings.Join(u.From.Publisher, ", ")), tt(strings.Join(u.To.Publisher, ", "))
	switch {
	case from == "" && to == "":
		return "not known"
	case u.From.Version != "" && from == "":
		// The installed copy was never looked up: that is not a change.
		return to + " (no publisher known for " + tt(u.From.Version) + ")"
	case u.From.Version != "" && from != to:
		arrow := " → "
		if t.o.Plain {
			arrow = " to "
		}
		return "changed: " + orNone(from) + arrow + orNone(to)
	case u.From.Version != "":
		return "unchanged (" + to + ")"
	}
	return to
}

func (t *termView) diffText(u *core.Update) string {
	d := u.Diff
	if d == (core.DiffStats{}) {
		if u.Verdict == core.Unverified {
			return "not diffed: the update is unverified"
		}
		return "no files changed"
	}
	files := plural(d.FilesChanged, "file changed", "files changed")
	if d.FilesAdded > 0 {
		files += fmt.Sprintf(", %d added", d.FilesAdded)
	}
	if d.FilesRemoved > 0 {
		files += fmt.Sprintf(", %d removed", d.FilesRemoved)
	}
	minus, arrow := "−", " → "
	if t.o.Plain {
		minus, arrow = "-", " to "
	}
	lines := "+" + thousands(d.LinesAdded) + " " + minus + thousands(d.LinesRemoved) + " lines"
	return files + t.dot() + lines + t.dot() + humanBytes(d.BytesFrom) + arrow + humanBytes(d.BytesTo)
}

// thousands writes n with a comma every three digits: 2,184.
func thousands(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteByte(',')
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

func (t *termView) changelogText(u *core.Update) string {
	if len(u.Changelog) == 0 || strings.TrimSpace(u.Changelog[0].Text) == "" {
		return "none for this version"
	}
	c := u.Changelog[0]
	return tt(c.Version) + ": \"" + tt(firstLine(c.Quote(), 200)) + "\""
}

// limited returns the counted findings of u the terminal shows and how
// many it leaves out (WriteOptions.MaxFindings, 0 for all).
func (t *termView) limited(u *core.Update) (shown []*core.Finding, more int) {
	fs := counted(u)
	if n := t.o.MaxFindings; n > 0 && len(fs) > n {
		return fs[:n], len(fs) - n
	}
	return fs, 0
}

// groups writes the findings of one update by severity: a card for
// critical, high and medium, one line for low and info.
func (t *termView) groups(u *core.Update) {
	fs, more := t.limited(u)
	for _, sev := range severities {
		var group []*core.Finding
		for _, f := range fs {
			if f.Severity == sev {
				group = append(group, f)
			}
		}
		if len(group) == 0 {
			continue
		}
		if !t.o.Plain {
			label := t.sevStyle(sev).Render(strings.ToUpper(sev.String()) + "  " + strconv.Itoa(len(group)))
			t.line("  " + label + " " + t.muted.Render(strings.Repeat("─", max(2, t.width-lipgloss.Width(label)-1))))
			t.blank()
		}
		for _, f := range group {
			t.finding(f)
		}
		if !t.o.Plain && sev < cli.SeverityMedium {
			t.blank()
		}
	}
	t.afterFindings(u, more)
}

// afterFindings writes the "… N more" and "Not counted" lines.
func (t *termView) afterFindings(u *core.Update, more int) {
	if more > 0 {
		if t.o.Plain {
			t.line(fmt.Sprintf("... %d more %s", more, moreLine))
		} else {
			t.line("    " + t.muted.Render(fmt.Sprintf("… %d more %s", more, moreLine)))
		}
	}
	if l := notCountedLine(u); l != "" {
		if t.o.Plain {
			t.line(l)
		} else {
			t.line("  " + t.muted.Render(l))
		}
	}
	if more > 0 || notCountedLine(u) != "" || t.o.Plain && len(counted(u)) > 0 {
		t.blank()
	}
}

// where is a finding's file:line, "" when it has no file.
func where(f *core.Finding) string {
	if f.File == "" {
		return ""
	}
	if f.Line > 0 {
		return tt(f.File) + ":" + strconv.Itoa(f.Line)
	}
	return tt(f.File)
}

// finding writes one finding in the form its severity takes.
func (t *termView) finding(f *core.Finding) {
	switch {
	case t.o.Plain:
		t.plainFinding(f)
	case f.Severity >= cli.SeverityMedium:
		t.card(f)
		t.blank()
	default:
		t.compact(f)
	}
}

// plainFinding is "[CRITICAL] <title> - <file>:<line>" and its details.
func (t *termView) plainFinding(f *core.Finding) {
	label := strings.ToUpper(f.Severity.String())
	if f.Confidence == core.Likely {
		label += ", likely"
	}
	head := "[" + label + "] " + tt(f.Title)
	if w := where(f); w != "" {
		head += " - " + w
	}
	t.line(head)
	for _, l := range t.evidence(f, 0) {
		t.line("  evidence: " + l)
	}
	if len(f.RaisedBy) > 0 {
		t.line("  raised by: " + tt(strings.Join(f.RaisedBy, ", ")))
	}
	if f.Demoted != "" {
		t.line("  demoted: " + tt(f.Demoted))
	}
	if a := strings.TrimSpace(f.Advice); a != "" {
		t.line("  advice: " + tt(a))
	}
}

// evidence returns up to evidenceLines lines of a finding's evidence,
// wrapped to n cells (0 for no wrapping).
func (t *termView) evidence(f *core.Finding, n int) []string {
	ev := strings.TrimSpace(f.Evidence.String())
	if ev == "" {
		return nil
	}
	var out []string
	for _, l := range strings.Split(tt(ev), "\n") {
		if l = strings.TrimSpace(l); l == "" {
			continue
		}
		if n > 0 {
			out = append(out, wrapHard(l, n)...)
		} else {
			out = append(out, l)
		}
	}
	if len(out) > evidenceLines {
		out = out[:evidenceLines]
		last := out[evidenceLines-1]
		if n > 0 {
			last = ui.Truncate(last, n-1)
		}
		out[evidenceLines-1] = strings.TrimSuffix(last, "…") + "…"
	}
	return out
}

// badge renders a severity label: filled for a confirmed finding,
// outlined (text in its color) for a likely one, as in Tuner.
func (t *termView) badge(f *core.Finding) string {
	label := " " + ui.Pad(strings.ToUpper(f.Severity.String()), badgeWidth-2) + " "
	if f.Confidence == core.Likely {
		return t.sevStyle(f.Severity).Render(label)
	}
	return t.re.NewStyle().Background(ui.SeverityColor(f.Severity.String())).
		Foreground(lipgloss.Color("#0B0B0C")).Bold(true).Render(label)
}

// card writes a critical, high or medium finding behind a ▌ bar in its
// severity's color: title and place, evidence, notes and → advice.
func (t *termView) card(f *core.Finding) {
	content := t.width - 1 // " ▌ " plus content spans the rule's width
	col := content - titleIndent
	title, loc := tt(f.Title), where(f)
	var body []string
	if loc != "" && lipgloss.Width(title)+2+lipgloss.Width(loc) <= col {
		body = append(body, t.badge(f)+"  "+ui.Pad(t.bold.Render(title), col-lipgloss.Width(loc))+t.muted.Render(loc))
	} else {
		lines := append(wrap(title, col), "")
		body = append(body, t.badge(f)+"  "+t.bold.Render(lines[0]))
		indent := strings.Repeat(" ", titleIndent)
		for _, l := range lines[1 : len(lines)-1] {
			body = append(body, indent+t.bold.Render(l))
		}
		for _, l := range wrapHard(loc, col) {
			body = append(body, indent+t.muted.Render(l))
		}
	}
	indent := strings.Repeat(" ", titleIndent)
	for _, l := range t.evidence(f, col) {
		body = append(body, indent+t.muted.Render(l))
	}
	var notes []string
	if len(f.RaisedBy) > 0 {
		notes = append(notes, "raised by "+tt(strings.Join(f.RaisedBy, ", ")))
	}
	if f.Demoted != "" {
		notes = append(notes, "demoted: "+tt(f.Demoted))
	}
	if f.Confidence == core.Likely {
		notes = append(notes, "likely: a heuristic, not an exact pattern")
	}
	for _, n := range notes {
		for _, l := range wrap(n, col) {
			body = append(body, indent+t.muted.Render(l))
		}
	}
	if a := strings.TrimSpace(f.Advice); a != "" {
		for i, l := range wrap(tt(a), col-2) {
			lead := "  "
			if i == 0 {
				lead = t.brand.Render("→") + " "
			}
			body = append(body, indent+lead+l)
		}
	}
	bar := t.sevStyle(f.Severity).Render("▌")
	for _, l := range body {
		t.line(" " + bar + " " + l)
	}
}

// glyphs mark low and info findings without relying on color.
var glyphs = map[cli.Severity]string{cli.SeverityLow: "●", cli.SeverityInfo: "·"}

// compact writes a low or info finding on one line.
func (t *termView) compact(f *core.Finding) {
	g, ok := glyphs[f.Severity]
	if !ok {
		g = "·"
	}
	lead := "    " + t.sevStyle(f.Severity).Render(g) + "  "
	col := t.width - 5
	title, loc := tt(f.Title), where(f)
	if loc != "" && lipgloss.Width(title)+2+lipgloss.Width(loc) <= col {
		t.line(lead + ui.Pad(title, col-lipgloss.Width(loc)) + t.muted.Render(loc))
		return
	}
	t.line(lead + ui.Truncate(title, col))
	for _, l := range wrapHard(loc, col) {
		t.line("       " + t.muted.Render(l))
	}
}

// multi writes the table, then a section per update with findings.
func (t *termView) multi() {
	if len(t.r.Updates) == 0 {
		t.line("  No updates to review.")
		t.blank()
		return
	}
	t.table()
	t.sections()
}

// sections writes a section per update with findings and, with --diff,
// one per other update that changed.
func (t *termView) sections() {
	secs := t.sectioned()
	for _, u := range secs {
		t.updateSection(u)
		t.diff(u)
	}
	if !t.o.ShowDiff {
		return
	}
	for _, u := range byVerdict(t.r) {
		if len(u.Hunks) > 0 && !slices.Contains(secs, u) {
			t.updateHeading(u)
			t.diff(u)
		}
	}
}

// diff writes every hunk of u for --diff. Each hunk line is one line,
// wrapped at the edge rather than cut, so nothing at the end of a long
// line is hidden.
func (t *termView) diff(u *core.Update) {
	if !t.o.ShowDiff || len(u.Hunks) == 0 {
		return
	}
	t.sectionHead("DIFF", len(u.Hunks), t.mutedBold)
	add := t.re.NewStyle().Foreground(lipgloss.Color(ui.Ok))
	del := t.re.NewStyle().Foreground(lipgloss.Color(ui.Danger))
	for _, h := range u.Hunks {
		head := hunkTitle(h, tt(h.Path))
		if t.o.Plain {
			t.line(head)
		} else {
			t.line("    " + t.muted.Render(head))
		}
		for _, l := range h.Lines {
			l = strings.NewReplacer("\r", `\r`, "\n", `\n`).Replace(tt(l))
			if t.o.Plain {
				t.line(l)
				continue
			}
			style := t.re.NewStyle()
			switch {
			case noteLine(l):
				style = t.muted
			case strings.HasPrefix(l, "+"):
				style = add
			case strings.HasPrefix(l, "-"):
				style = del
			}
			for _, part := range cutCells(l, t.width-2) {
				t.line("    " + style.Render(part))
			}
		}
	}
	t.blank()
}

// sectioned are the updates with their own section: HOLD, REVIEW and an
// UNVERIFIED one with counted findings, as in the Markdown report.
func (t *termView) sectioned() []*core.Update { return mdReport{r: t.r, o: t.o}.sectioned() }

// fleet reports whether any update lists the sites it applies to.
func (t *termView) fleet() bool {
	for i := range t.r.Updates {
		if len(t.r.Updates[i].Sites) > 0 {
			return true
		}
	}
	return false
}

// tableFindings is the FINDINGS cell: "2 critical, 1 high", "1 allowed",
// "not verified" (an update that was not diffed) or empty.
func tableFindings(u *core.Update) string {
	s := findingCounts(u)
	switch {
	case u.Verdict == core.Unverified && s == "none" && !diffed(u):
		return "not verified"
	case s == "none":
		return ""
	}
	return s
}

// diffed reports whether run diffed u. An unverified update is diffed
// only with --allow-unverified. A diff always has the new side's size,
// so empty stats mean it was not.
func diffed(u *core.Update) bool { return u.Diff != (core.DiffStats{}) }

// table writes VERDICT UPDATE FROM TO FINDINGS, worst first, with the
// ROUTINE rows folded into one line when there are over ten. A fleet
// run writes "<name> <from> → <to>  <VERDICT> on <n> sites" instead.
func (t *termView) table() {
	ups := byVerdict(t.r)
	routine := 0
	if countVerdict(ups, core.Routine) > routineFold {
		kept := ups[:0:0]
		for _, u := range ups {
			if quiet(u) {
				routine++
			} else {
				kept = append(kept, u)
			}
		}
		ups = kept
	}
	if t.fleet() {
		t.fleetTable(ups)
	} else {
		t.plainTable(ups)
	}
	if routine > 0 {
		s := plural(routine, "update", "updates") + " with no risk signals"
		if t.o.Plain {
			t.line(s)
		} else {
			t.line("  " + t.muted.Render(s))
		}
	}
	t.blank()
}

// joinCells pads each cell but the last to its column and joins them.
func joinCells(widths []int, cs []string) string {
	var b strings.Builder
	for i, c := range cs {
		if i == len(cs)-1 {
			b.WriteString(c)
			break
		}
		b.WriteString(ui.Pad(c, widths[i]) + "  ")
	}
	return strings.TrimRight(b.String(), " ")
}

func (t *termView) plainTable(ups []*core.Update) {
	if len(ups) == 0 {
		return
	}
	head := []string{"VERDICT", "UPDATE", "FROM", "TO", "FINDINGS"}
	rows := make([][]string, 0, len(ups))
	for _, u := range ups {
		from := tt(u.From.Version)
		if from == "" {
			from = "new"
		}
		rows = append(rows, []string{strings.ToUpper(string(u.Verdict)), tt(u.Name), from, tt(u.To.Version), tableFindings(u)})
	}
	widths := make([]int, len(head))
	for i, h := range head {
		widths[i] = lipgloss.Width(h)
		for _, r := range rows {
			widths[i] = max(widths[i], lipgloss.Width(r[i]))
		}
	}
	// The name column gives way first, then FINDINGS is cut at the edge.
	// Plain output is for logs, which have no edge.
	widths[0] = max(widths[0], len("UNVERIFIED"))
	if !t.o.Plain {
		fixed := widths[0] + widths[2] + widths[3] + 4*2
		widths[1] = min(widths[1], max(12, t.width-fixed-minFindingsCol))
	}
	t.tableRows(widths, head, rows, ups)
}

func (t *termView) fleetTable(ups []*core.Update) {
	if len(ups) == 0 {
		return
	}
	head := []string{"UPDATE", "VERDICT", "FINDINGS"}
	rows := make([][]string, 0, len(ups))
	for _, u := range ups {
		v := strings.ToUpper(string(u.Verdict))
		if n := len(u.Sites); n > 0 {
			v += " on " + plural(n, "site", "sites")
		}
		rows = append(rows, []string{tt(u.Name) + " " + t.fromTo(u), v, tableFindings(u)})
	}
	widths := []int{len(head[0]), len(head[1]), len(head[2])}
	for _, r := range rows {
		for i := range r {
			widths[i] = max(widths[i], lipgloss.Width(r[i]))
		}
	}
	if !t.o.Plain {
		widths[0] = min(widths[0], max(20, t.width-widths[1]-2*2-minFindingsCol))
	}
	t.tableRows(widths, head, rows, ups)
}

// tableRows writes the header and rows, cutting cells to their column
// and the last cell at the report's edge. The verdict cell has its color.
func (t *termView) tableRows(widths []int, head []string, rows [][]string, ups []*core.Update) {
	vcol := 0
	if t.fleet() {
		vcol = 1
	}
	used := 0
	for _, w := range widths[:len(widths)-1] {
		used += w + 2
	}
	last := max(8, t.width-used)
	if t.o.Plain {
		last = 1 << 20
	}
	if t.o.Plain {
		t.line(joinCells(widths, head))
	} else {
		t.line("  " + t.mutedBold.Render(joinCells(widths, head)))
	}
	for i, r := range rows {
		cs := make([]string, len(r))
		for j, c := range r {
			if j == len(r)-1 {
				cs[j] = ui.Truncate(c, last)
				continue
			}
			if !t.o.Plain {
				c = ui.Truncate(c, widths[j])
			}
			if j == vcol && !t.o.Plain {
				c = t.verdictStyle(ups[i].Verdict).Render(c)
			}
			cs[j] = c
		}
		if t.o.Plain {
			t.line(joinCells(widths, cs))
		} else {
			t.line("  " + joinCells(widths, cs))
		}
	}
}

// updateHeading writes "HOLD  name 1.0 → 1.1 ───".
func (t *termView) updateHeading(u *core.Update) {
	name := tt(u.Name) + " " + t.fromTo(u)
	if n := len(u.Sites); n > 0 {
		name += " on " + plural(n, "site", "sites")
	}
	verdict := strings.ToUpper(string(u.Verdict))
	if t.o.Plain {
		t.line(verdict + ": " + name)
		return
	}
	head := t.verdictStyle(u.Verdict).Render(verdict) + "  " + t.bold.Render(name)
	t.line("  " + head + " " + t.muted.Render(strings.Repeat("─", max(2, t.width-lipgloss.Width(head)-1))))
}

// updateSection writes one update's heading and its findings.
func (t *termView) updateSection(u *core.Update) {
	t.updateHeading(u)
	fs, more := t.limited(u)
	for _, f := range fs {
		t.finding(f)
	}
	if !t.o.Plain && len(fs) > 0 && fs[len(fs)-1].Severity < cli.SeverityMedium {
		t.blank()
	}
	t.afterFindings(u, more)
	if t.o.Plain && len(fs) == 0 && more == 0 && notCountedLine(u) == "" {
		t.blank()
	}
}

// unverifiedList names each UNVERIFIED update of a multi-update run and
// why; the one-update layout says it in the verdict box.
func (t *termView) unverifiedList() {
	if t.single() {
		return
	}
	var lines []string
	notDiffed := 0
	for _, u := range byVerdict(t.r) {
		if u.Verdict != core.Unverified {
			continue
		}
		if !diffed(u) {
			notDiffed++
		}
		lines = append(lines, tt(u.Name)+" "+tt(u.To.Version)+" ("+tt(string(u.Eco))+"): "+unverifiedWhy(u))
	}
	if len(lines) == 0 {
		return
	}
	t.sectionHead("UNVERIFIED", len(lines), t.warn)
	for _, l := range lines {
		t.item(l, "")
	}
	// The hint is for updates left undiffed: with --allow-unverified
	// they were reviewed and their findings are above.
	if notDiffed > 0 {
		t.item("", unverifiedHint(len(lines), notDiffed))
	}
	t.blank()
}

// unverifiedHint is the line under n unverified updates when notDiffed
// of them were not diffed.
func unverifiedHint(n, notDiffed int) string {
	if notDiffed == n {
		return "--allow-unverified reviews them anyway"
	}
	return "--allow-unverified reviews the ones not diffed anyway"
}

// unverifiedWhy is the first error of an unverified update, or a stock
// reason.
func unverifiedWhy(u *core.Update) string {
	if len(u.Errors) > 0 && u.Errors[0].Message != "" {
		return tt(u.Errors[0].Message)
	}
	return "its integrity could not be checked"
}

// sectionHead writes "LABEL  n ───" (plain: "LABEL (n):").
func (t *termView) sectionHead(label string, n int, style lipgloss.Style) {
	if t.o.Plain {
		t.line(fmt.Sprintf("%s (%d):", label, n))
		return
	}
	head := style.Render(label + "  " + strconv.Itoa(n))
	t.line("  " + head + " " + t.muted.Render(strings.Repeat("─", max(2, t.width-lipgloss.Width(head)-1))))
	t.blank()
}

// item writes a list line and an optional → hint under it.
func (t *termView) item(s, hint string) {
	if t.o.Plain {
		if s != "" {
			t.line("  " + s)
		}
		if hint != "" {
			t.line("    " + hint)
		}
		return
	}
	for _, l := range wrap(s, t.width-4) {
		t.line("    " + l)
	}
	for i, l := range wrap(hint, t.width-8) {
		lead := "  "
		if i == 0 {
			lead = t.brand.Render("→") + " "
		}
		t.line("      " + lead + t.muted.Render(l))
	}
}

// notChecked lists what the run did not check and the report's errors.
func (t *termView) notChecked() {
	// A package that failed to download is one entry with its error's
	// code, not an entry and an error.
	codes, rest := t.r.PairErrors()
	n := len(t.r.NotChecked) + len(rest)
	if n == 0 {
		return
	}
	t.sectionHead("NOT CHECKED", n, t.mutedBold)
	for i, nc := range t.r.NotChecked {
		s := tt(nc.Name)
		if nc.Version != "" {
			s += " " + tt(nc.Version)
		}
		if nc.Eco != "" {
			s += " (" + tt(string(nc.Eco)) + ")"
		}
		s += ": " + tt(nc.Text)
		if codes[i] != "" {
			s += " (" + tt(string(codes[i])) + ")"
		}
		t.item(s, tt(nc.Hint))
	}
	for _, e := range rest {
		s := tt(e.Name)
		if e.Eco != "" {
			s += " (" + tt(string(e.Eco)) + ")"
		}
		t.item(s+": "+tt(t.p.text(e.Message))+" ("+tt(string(e.Code))+")", "")
	}
	t.blank()
}

// severityCounts are the counted findings by severity, worst first.
func severityCounts(s core.Summary) []struct {
	sev cli.Severity
	n   int
} {
	return []struct {
		sev cli.Severity
		n   int
	}{{cli.SeverityCritical, s.Critical}, {cli.SeverityHigh, s.High}, {cli.SeverityMedium, s.Medium}, {cli.SeverityLow, s.Low}, {cli.SeverityInfo, s.Info}}
}

// countsLine is "■ 2 critical   ■ 1 high" (plain: "2 critical, 1 high"),
// "" when nothing counts.
func (t *termView) countsLine(s core.Summary) string {
	var parts []string
	for _, c := range severityCounts(s) {
		if c.n == 0 {
			continue
		}
		if t.o.Plain {
			parts = append(parts, fmt.Sprintf("%d %s", c.n, c.sev))
		} else {
			parts = append(parts, t.sevStyle(c.sev).Render("■")+fmt.Sprintf(" %d %s", c.n, c.sev))
		}
	}
	if s.AllowedFindings > 0 {
		parts = append(parts, fmt.Sprintf("%d allowed", s.AllowedFindings))
	}
	if s.Hidden > 0 {
		parts = append(parts, fmt.Sprintf("%d hidden", s.Hidden))
	}
	if t.o.Plain {
		return strings.Join(parts, ", ")
	}
	return strings.Join(parts, "   ")
}

// updateSummary counts one update the way Summarise counts a report.
func updateSummary(u *core.Update) core.Summary {
	var s core.Summary
	for i := range u.Findings {
		f := &u.Findings[i]
		switch {
		case f.Counted():
			switch f.Severity {
			case cli.SeverityCritical:
				s.Critical++
			case cli.SeverityHigh:
				s.High++
			case cli.SeverityMedium:
				s.Medium++
			case cli.SeverityLow:
				s.Low++
			case cli.SeverityInfo:
				s.Info++
			}
		case f.Allowed != nil:
			s.AllowedFindings++
		}
	}
	s.Hidden = len(u.Hidden)
	return s
}

// box writes the verdict box.
func (t *termView) box() {
	inner := t.width - 6
	var top, color string
	var lines []string
	s := t.r.Summary
	if t.single() {
		u := &t.r.Updates[0]
		s = updateSummary(u)
		v := strings.ToUpper(string(u.Verdict))
		color = verdictColors[u.Verdict]
		if t.o.Plain {
			top = "Verdict: " + v
		} else {
			top = t.bold.Render("VERDICT") + strings.Repeat(" ", max(1, inner-len("VERDICT")-len(v))) + t.verdictStyle(u.Verdict).Render(v)
		}
		if u.Verdict == core.Unverified {
			lines = append(lines, "Not verified: "+strings.TrimSuffix(unverifiedWhy(u), ".")+".")
			if !diffed(u) {
				lines = append(lines, "Not diffed; --allow-unverified reviews it anyway.")
			}
		}
	} else {
		n := len(t.r.Updates)
		label := plural(n, "UPDATE", "UPDATES")
		var parts []string
		for _, p := range []struct {
			n int
			v core.Verdict
		}{{s.Hold, core.Hold}, {s.Review, core.Review}, {s.Routine, core.Routine}, {s.Allowed, core.Allowed}, {s.Unverified, core.Unverified}} {
			if p.n == 0 {
				continue
			}
			w := fmt.Sprintf("%d %s", p.n, p.v)
			if !t.o.Plain {
				w = t.verdictStyle(p.v).Render(w)
			}
			parts = append(parts, w)
		}
		color = ui.Ok
		switch {
		case s.Hold > 0:
			color = ui.Danger
		case s.Review > 0:
			color = ui.High
		case s.Unverified > 0:
			color = ui.Warn
		}
		if t.o.Plain {
			top = strings.ToLower(label)
			if len(parts) > 0 {
				top += ": " + strings.Join(parts, ", ")
			}
		} else {
			right := strings.Join(parts, t.muted.Render(" · "))
			top = t.bold.Render(label) + strings.Repeat(" ", max(2, inner-len(label)-lipgloss.Width(right))) + right
		}
	}
	if c := t.countsLine(s); c != "" {
		lines = append(lines, c)
	}
	unverified := s.Unverified > 0 || t.single() && t.r.Updates[0].Verdict == core.Unverified
	if s.Critical+s.High+s.Medium+s.Low+s.Info == 0 && s.AllowedFindings == 0 && s.Hidden == 0 && !unverified && len(t.r.Updates) > 0 {
		lines = append(lines, cleanLine)
	}
	incomplete := incompleteText(t.r)
	if incomplete != "" {
		lines = append(lines, incomplete)
	}
	lines = append(lines, intentLine)

	if t.o.Plain {
		t.line(top)
		for _, l := range lines {
			t.line(l)
		}
		return
	}
	body := []string{top}
	if lipgloss.Width(top) > inner {
		// The verdict counts of a run with every kind of verdict don't fit
		// beside the label; they go on a line of their own.
		label, right, _ := strings.Cut(top, "  ")
		body = []string{label}
		body = append(body, wrap(strings.TrimSpace(right), inner)...)
	}
	for _, l := range lines {
		ls := []string{l}
		if lipgloss.Width(l) > inner {
			ls = wrap(l, inner)
		}
		if l == incomplete {
			for i := range ls {
				ls[i] = t.warn.Render(ls[i])
			}
		}
		body = append(body, ls...)
	}
	if color == "" {
		color = ui.Muted
	}
	box := t.re.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color(color)).
		Padding(0, 2).MarginLeft(1).Width(inner + 4)
	t.line(box.Render(strings.Join(body, "\n")))
}

// archivesVerified counts the sides that were checked against their
// source.
func archivesVerified(r *core.Report) int {
	n := 0
	for i := range r.Updates {
		u := &r.Updates[i]
		if u.From.Version != "" && verified(u.From) {
			n++
		}
		if verified(u.To) {
			n++
		}
	}
	return n
}

// footer writes "N updates reviewed · M archives verified · K from cache
// · Ts" and the warnings.
func (t *termView) footer() {
	parts := []string{
		plural(len(t.r.Updates), "update reviewed", "updates reviewed"),
		plural(archivesVerified(t.r), "archive verified", "archives verified"),
		strconv.Itoa(t.r.Summary.FromCache) + " from cache",
		t.r.Duration.Round(100 * time.Millisecond).String(),
	}
	if t.o.Plain {
		t.line(strings.Join(parts, ", "))
	} else {
		t.line("  " + t.muted.Render(strings.Join(parts, " · ")))
	}
	for _, w := range t.r.Warnings {
		t.note(tt(t.p.text(w)), t.muted)
	}
	t.blank()
}

// next writes the → next steps.
func (t *termView) next() {
	var steps [][2]string
	worst := t.worstFinding()
	if worst != nil {
		switch {
		case t.o.Demo:
			// Only the demo reaches the demo's packages.
			steps = append(steps, [2]string{"every finding and the full diff", tt(programName(t.o.Program)) + " demo -o review.html --open"})
		case t.single():
			u := &t.r.Updates[0]
			c := tt(programName(t.o.Program)) + " " + ecoCommand(u.Eco) + " " + shellArg(tt(u.Name))
			for _, a := range t.o.RerunFlags {
				// The run's own flags, so the command reviews the same
				// copy: without --path it would look in this folder.
				c += " " + shellArg(tt(a))
			}
			steps = append(steps, [2]string{"the full diff", c + " -o review.html --open"})
		default:
			steps = append(steps, [2]string{"every finding and the full diff", "run again with -o review.html --open"})
		}
		steps = append(steps, [2]string{"explain a finding", tt(programName(t.o.Program)) + " explain " + shellArg(tt(worst.ID))})
	}
	if t.o.Demo {
		// The demo's packages are made up: an update or allow command
		// would ask a real registry for them.
		t.writeSteps(steps)
		return
	}
	label := "update the routine ones"
	if t.single() {
		label = "update it"
	}
	for _, c := range t.updateCommands() {
		steps = append(steps, [2]string{label, c})
	}
	for _, u := range t.sectioned() {
		if allowRefusal(u) == "" {
			steps = append(steps, [2]string{"record a review", mdReport{r: t.r, o: t.o}.allowCommand(u)})
			break
		}
	}
	t.writeSteps(steps)
}

// writeSteps writes the → next steps, each a label and a command.
func (t *termView) writeSteps(steps [][2]string) {
	for _, s := range steps {
		if t.o.Plain {
			t.line("next: " + s[0] + ": " + s[1])
			continue
		}
		lead := "  " + t.brand.Render("→") + " " + t.muted.Render(s[0]+":")
		if lipgloss.Width(lead)+1+lipgloss.Width(s[1]) <= t.cols-2 {
			t.line(lead + " " + s[1])
			continue
		}
		// A command is never wrapped, so it can be copied whole; a long
		// one gets a line of its own.
		t.line(lead)
		t.line("    " + s[1])
	}
	if len(steps) > 0 {
		t.blank()
	}
}

// worstFinding is the first counted finding of the worst update.
func (t *termView) worstFinding() *core.Finding {
	for _, u := range byVerdict(t.r) {
		if fs := counted(u); len(fs) > 0 {
			return fs[0]
		}
	}
	return nil
}

// ecoCommand is the subcommand that reviews one package of eco.
func ecoCommand(eco core.Ecosystem) string {
	switch eco {
	case core.WPPlugin:
		return "plugin"
	case core.WPTheme:
		return "theme"
	}
	return string(eco)
}

// updateCommands are the commands that install the ROUTINE and ALLOWED
// updates, one per tool: WP-CLI, Composer and npm. Sightread prints
// them and never runs them.
func (t *termView) updateCommands() []string {
	names := map[core.Ecosystem][]string{}
	var one *core.Update
	for _, u := range byVerdict(t.r) {
		// An update with hidden findings is not offered: the reader
		// hasn't seen what they say.
		if u.Verdict != core.Routine && u.Verdict != core.Allowed || u.To.Version == "" || len(u.Hidden) > 0 {
			continue
		}
		one = u
		arg := shellArg(tt(u.Name))
		if u.Eco == core.NPM {
			arg = shellArg(tt(u.Name) + "@" + tt(u.To.Version))
		}
		names[u.Eco] = append(names[u.Eco], arg)
	}
	var out []string
	for _, eco := range core.Ecosystems() {
		ns := names[eco]
		if len(ns) == 0 {
			continue
		}
		args := strings.Join(ns, " ")
		switch eco {
		case core.WPPlugin, core.WPTheme:
			c := "wp " + ecoCommand(eco) + " update " + args
			if t.single() && one != nil {
				c += " --version=" + shellArg(tt(one.To.Version))
			}
			out = append(out, c)
		case core.Composer:
			out = append(out, "composer update "+args)
		case core.NPM:
			out = append(out, "npm install "+args)
		}
	}
	return out
}

// plainArg matches an argument that needs no quoting in a shell.
var plainArg = regexp.MustCompile(`^[A-Za-z0-9@%+=:,./_-]+$`)

// shellArg quotes s for a POSIX shell unless it is plainly safe, so a
// name from a hostile report can't add a command to a copied line.
func shellArg(s string) string {
	if plainArg.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// wrap breaks s into lines of at most n cells at spaces. A word longer
// than n gets a line of its own and is never cut, so it can be copied.
func wrap(s string, n int) []string {
	if n < 1 {
		n = 1
	}
	var lines []string
	line := ""
	for _, word := range strings.Fields(s) {
		switch {
		case line == "":
			line = word
		case lipgloss.Width(line)+1+lipgloss.Width(word) <= n:
			line += " " + word
		default:
			lines = append(lines, line)
			line = word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	return lines
}

// cutCells splits s into pieces of at most n cells, keeping every space,
// for diff lines whose indentation matters.
func cutCells(s string, n int) []string {
	if n < 1 {
		n = 1
	}
	var out []string
	for lipgloss.Width(s) > n {
		cut, w := 0, 0
		for i, r := range s {
			rw := lipgloss.Width(string(r))
			if w+rw > n {
				break
			}
			w += rw
			cut = i + len(string(r))
		}
		if cut == 0 {
			break
		}
		out = append(out, s[:cut])
		s = s[cut:]
	}
	return append(out, s)
}

// wrapHard is wrap that also cuts a word longer than n, for paths and
// evidence, which would otherwise run past the edge.
func wrapHard(s string, n int) []string {
	if s == "" {
		return nil
	}
	if n < 1 {
		n = 1
	}
	var out []string
	for _, l := range wrap(s, n) {
		out = append(out, cutCells(l, n)...)
	}
	return out
}

// soundcheckCounts is the result of a --soundcheck run: its counts, or
// why it has none when it stopped before the comparison.
func soundcheckCounts(s *core.SoundcheckResult) string {
	if s.NotCompared {
		if s.Error == "" {
			return "not compared"
		}
		return "not compared: " + s.Error
	}
	return fmt.Sprintf("%d broke, %d new, %d changed", s.Broke, s.New, s.Changed)
}
