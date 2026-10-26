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

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/term"
	"github.com/RhythmShahriar/sightread/core"
)

func init() { core.RegisterWriter(MarkdownWriter{}) }

// MarkdownWriter writes the report for a pull request comment or a job
// summary (PRD 9.4). Package text goes through term.EscapeMarkdown, or
// term.MarkdownCode with its domains defanged, so a mention, a link, an
// image or raw HTML from a package renders as text. It is the one
// writer with emoji: GitHub shows them as status icons.
type MarkdownWriter struct{}

var _ core.Writer = MarkdownWriter{}

// Format returns "md".
func (MarkdownWriter) Format() string { return core.FormatMarkdown }

// markdownMax keeps a report under GitHub's 65,536 character limit for
// a comment, with room for what a bot adds around it.
const markdownMax = 60000

// maxSectionFindings is how many findings an update keeps once the
// report has to be trimmed.
const maxSectionFindings = 5

// routineFold is how many ROUTINE rows the table shows before they fold
// into one <details>.
const routineFold = 10

// The lines PRD 9.4 and 18 fix word for word.
const (
	honestyLine = "Static diff of official releases; Sightread never ran this code. Not proof an update is safe."
	intentLine  = "Sightread reports what changed. It does not judge intent."
	trimmedNote = "trimmed: see the HTML report"
)

// Write writes r as Markdown, trimming hunks first, then findings past
// five per update, then whole update sections, until it fits.
func (MarkdownWriter) Write(w io.Writer, r *core.Report, o core.WriteOptions) error {
	m := mdReport{r: r, o: o}
	footer := m.footer()
	budget := markdownMax - len(footer)
	var out string
	for _, t := range []mdTrim{{hunks: true, findings: -1, sections: -1}, {findings: -1, sections: -1}, {findings: maxSectionFindings, sections: -1}} {
		if out = m.body(t); len(out) <= budget {
			break
		}
	}
	if len(out) > budget {
		// Halve the update sections until the rest fits; the table still
		// lists every update.
		n := len(m.sectioned())
		for n > 0 {
			n /= 2
			if out = m.body(mdTrim{findings: maxSectionFindings, sections: n}); len(out) <= budget {
				break
			}
		}
	}
	if len(out) > budget {
		out = cutLines(out, budget-len(trimmedNote)-8) + "\n> " + trimmedNote + "\n\n"
	}
	_, err := io.WriteString(w, out+footer)
	return err
}

// mdTrim says how much of the report goes in.
type mdTrim struct {
	hunks    bool // the flagged hunks
	findings int  // per update, -1 for all
	sections int  // update sections, -1 for all
}

// trimmed reports whether t leaves anything out.
func (t mdTrim) trimmed() bool { return !t.hunks || t.findings >= 0 || t.sections >= 0 }

type mdReport struct {
	r *core.Report
	o core.WriteOptions
}

// verdictOrder ranks verdicts worst first for the table.
var verdictOrder = map[core.Verdict]int{core.Hold: 0, core.Review: 1, core.Unverified: 2, core.Allowed: 3, core.Routine: 4}

var verdictEmoji = map[core.Verdict]string{
	core.Hold: "🛑", core.Review: "⚠️", core.Unverified: "⚠️", core.Allowed: "✅", core.Routine: "✅",
}

// sorted returns the updates worst first, then by name.
func (m mdReport) sorted() []*core.Update { return byVerdict(m.r) }

func rank(v core.Verdict) int {
	if r, ok := verdictOrder[v]; ok {
		return r
	}
	return len(verdictOrder)
}

// sectioned are the updates that get a section: HOLD, REVIEW and an
// UNVERIFIED one with a finding that counts (reviewed with
// --allow-unverified). ROUTINE findings are low or info and stay in the
// table count; the HTML report has them in full.
func (m mdReport) sectioned() []*core.Update {
	var out []*core.Update
	for _, u := range m.sorted() {
		if u.Verdict == core.Hold || u.Verdict == core.Review || u.Verdict == core.Unverified && len(counted(u)) > 0 {
			out = append(out, u)
		}
	}
	return out
}

// counted returns the findings of u that count, in report order.
func counted(u *core.Update) []*core.Finding {
	var out []*core.Finding
	for i := range u.Findings {
		if u.Findings[i].Counted() {
			out = append(out, &u.Findings[i])
		}
	}
	return out
}

// md escapes package text for Markdown prose and table cells.
func md(s string) string { return term.EscapeMarkdown(text(s)) }

// mdInline is md for text that never starts a line, such as a version in
// a table cell or after a heading's icon. EscapeMarkdown guards "2.6.7"
// as "2\.6.7" in case it starts an ordered list; mid-line that can't
// happen and the backslash only makes the raw comment harder to read.
func mdInline(s string) string {
	out := md(s)
	if n := len(out) - len(strings.TrimLeft(out, "0123456789")); n > 0 && strings.HasPrefix(out[n:], `\.`) {
		out = out[:n] + out[n+1:]
	}
	return out
}

// mdCode puts package text in a code span with its domains and URLs
// defanged. Pipes are escaped because GitHub splits table cells on them
// even inside a code span.
func mdCode(s string) string {
	return strings.ReplaceAll(term.MarkdownCode(defang(text(s))), "|", `\|`)
}

var (
	urlScheme = regexp.MustCompile(`(?i)\bhttp(s?)://`)
	// hostName is a dotted name whose last label starts with a letter.
	hostName = regexp.MustCompile(`(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}[a-z0-9]\b`)
)

// fileExts are last labels that name a file type, not a domain, so
// "class-api.php" stays as it is. Real TLDs among them (.sh, .md, .py,
// .zip) lose little: such a name still reads as one.
var fileExts = map[string]bool{
	"php": true, "phtml": true, "inc": true, "js": true, "mjs": true, "cjs": true, "jsx": true, "ts": true, "tsx": true,
	"css": true, "scss": true, "less": true, "json": true, "lock": true, "html": true, "htm": true, "xml": true,
	"txt": true, "md": true, "yml": true, "yaml": true, "map": true, "min": true, "png": true, "jpg": true, "jpeg": true,
	"gif": true, "svg": true, "webp": true, "ico": true, "woff": true, "woff2": true, "ttf": true, "eot": true,
	"zip": true, "gz": true, "tgz": true, "tar": true, "sh": true, "py": true, "go": true, "vue": true, "pot": true,
	"po": true, "mo": true, "sql": true, "log": true, "dist": true, "bak": true, "orig": true, "twig": true,
}

// defangScheme turns http:// and https:// into hxxp:// and hxxps://.
func defangScheme(s string) string {
	return urlScheme.ReplaceAllStringFunc(s, func(m string) string { return "hxxp" + strings.ToLower(m[4:]) })
}

// defang makes URLs and domains unclickable and harmless to paste:
// "https://a.example/x" becomes "hxxps://a[.]example/x".
func defang(s string) string {
	s = defangScheme(s)
	return hostName.ReplaceAllStringFunc(s, func(h string) string {
		i := strings.LastIndexByte(h, '.')
		if fileExts[strings.ToLower(h[i+1:])] {
			return h
		}
		return h[:i] + "[.]" + h[i+1:]
	})
}

func (m mdReport) heading() string {
	s := m.r.Summary
	var parts []string
	if s.Hold > 0 {
		parts = append(parts, fmt.Sprintf("%d to hold", s.Hold))
	}
	if s.Review > 0 {
		parts = append(parts, fmt.Sprintf("%d to review", s.Review))
	}
	if s.Unverified > 0 {
		parts = append(parts, fmt.Sprintf("%d unverified", s.Unverified))
	}
	switch {
	case len(parts) > 0:
		return "## Sightread: " + joinAnd(parts)
	case len(m.r.Updates) == 0:
		return "## Sightread: no updates to review"
	case s.Hidden > 0:
		// Hidden findings may be the very risk signals; the note says
		// which flags hid them.
		return fmt.Sprintf("## Sightread: %s, %s", plural(len(m.r.Updates), "update", "updates"),
			plural(s.Hidden, "finding hidden", "findings hidden"))
	}
	return fmt.Sprintf("## Sightread: no risk signals in %s", plural(len(m.r.Updates), "update", "updates"))
}

// joinAnd writes "a", "a and b" or "a, b and c".
func joinAnd(parts []string) string {
	if len(parts) < 2 {
		return strings.Join(parts, "")
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// severities lists the levels worst first.
var severities = []cli.Severity{cli.SeverityCritical, cli.SeverityHigh, cli.SeverityMedium, cli.SeverityLow, cli.SeverityInfo}

// findingCounts is "2 critical, 1 high", "1 allowed", "3 hidden" or
// "none".
func findingCounts(u *core.Update) string {
	n := map[cli.Severity]int{}
	allowed := 0
	for i := range u.Findings {
		f := &u.Findings[i]
		switch {
		case f.Counted():
			n[f.Severity]++
		case f.Allowed != nil:
			allowed++
		}
	}
	var parts []string
	for _, s := range severities {
		if n[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n[s], s))
		}
	}
	if allowed > 0 {
		parts = append(parts, fmt.Sprintf("%d allowed", allowed))
	}
	if n := len(u.Hidden); n > 0 {
		parts = append(parts, fmt.Sprintf("%d hidden", n))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}

func (m mdReport) row(b *strings.Builder, u *core.Update) {
	name := md(u.Name) + " (" + md(string(u.Eco)) + ")"
	if len(u.Sites) > 0 {
		name += " on " + plural(len(u.Sites), "site", "sites")
	}
	from := mdInline(u.From.Version)
	if from == "" {
		from = "new"
	}
	fmt.Fprintf(b, "| %s %s | %s | %s | %s | %s |\n", verdictEmoji[u.Verdict], md(strings.ToUpper(string(u.Verdict))),
		name, from, mdInline(u.To.Version), findingCounts(u))
}

const tableHead = "| Verdict | Update | From | To | Findings |\n|---|---|---|---|---|\n"

func (m mdReport) table(b *strings.Builder) {
	ups := m.sorted()
	var routine []*core.Update
	if n := countVerdict(ups, core.Routine); n > routineFold {
		kept := ups[:0:0]
		for _, u := range ups {
			if quiet(u) {
				routine = append(routine, u)
			} else {
				kept = append(kept, u)
			}
		}
		ups = kept
	}
	if len(ups) > 0 {
		b.WriteString(tableHead)
		for _, u := range ups {
			m.row(b, u)
		}
		b.WriteString("\n")
	}
	if len(routine) > 0 {
		fmt.Fprintf(b, "<details><summary>%s with no risk signals</summary>\n\n%s", plural(len(routine), "update", "updates"), tableHead)
		for _, u := range routine {
			m.row(b, u)
		}
		b.WriteString("\n</details>\n\n")
	}
}

// quiet reports whether u folds into the "with no risk signals" line: a
// ROUTINE update with no finding hidden, since a hidden one may be a
// risk signal.
func quiet(u *core.Update) bool { return u.Verdict == core.Routine && len(u.Hidden) == 0 }

func countVerdict(ups []*core.Update, v core.Verdict) int {
	n := 0
	for _, u := range ups {
		if u.Verdict == v {
			n++
		}
	}
	return n
}

// body is everything above the footer.
func (m mdReport) body(t mdTrim) string {
	var b strings.Builder
	b.WriteString(m.heading() + "\n\n")
	for _, n := range m.r.Notes {
		b.WriteString("> " + md(n) + "\n")
	}
	if len(m.r.Notes) > 0 {
		b.WriteString("\n")
	}
	if line := m.incomplete(); line != "" {
		b.WriteString(line + "\n\n")
	}
	m.table(&b)
	secs := m.sectioned()
	shown := secs
	if t.sections >= 0 && t.sections < len(secs) {
		shown = secs[:t.sections]
	}
	for _, u := range shown {
		m.section(&b, u, t)
	}
	if left := len(secs) - len(shown); left > 0 {
		fmt.Fprintf(&b, "%s not shown here.\n\n", plural(left, "more update with findings is", "more updates with findings are"))
	}
	m.unverified(&b)
	m.notChecked(&b)
	if len(m.r.Warnings) > 0 {
		b.WriteString("### Warnings\n\n")
		for _, s := range m.r.Warnings {
			b.WriteString("- " + md(s) + "\n")
		}
		b.WriteString("\n")
	}
	if t.trimmed() {
		b.WriteString("> " + trimmedNote + "\n\n")
	}
	return b.String()
}

// incomplete says why a run is partial, so a reviewer of a green
// summary sees what it didn't cover.
func (m mdReport) incomplete() string {
	if m.r.Complete {
		return ""
	}
	parts := incompleteParts(m.r)
	for i := range parts {
		parts[i] = term.EscapeMarkdown(parts[i])
	}
	if len(parts) == 0 {
		return "**Incomplete review.**"
	}
	return "**Incomplete review:** " + joinAnd(parts) + "."
}

func (m mdReport) section(b *strings.Builder, u *core.Update, t mdTrim) {
	from := ""
	if u.From.Version != "" {
		from = mdInline(u.From.Version) + " → "
	}
	fmt.Fprintf(b, "### %s %s %s%s", verdictEmoji[u.Verdict], mdInline(u.Name), from, mdInline(u.To.Version))
	if len(u.Sites) > 0 {
		fmt.Fprintf(b, " on %s", plural(len(u.Sites), "site", "sites"))
	}
	b.WriteString("\n\n")
	if len(u.Sites) > 0 {
		b.WriteString("Sites: " + md(strings.Join(u.Sites, ", ")) + "\n\n")
	}
	b.WriteString(integrityLine(u) + " " + publisherLine(u) + "\n")
	b.WriteString(changelogLine(u) + "\n\n")

	fs := counted(u)
	b.WriteString("| Severity | Signal | Where | Evidence |\n|---|---|---|---|\n")
	limit := len(fs)
	if t.findings >= 0 && t.findings < limit {
		limit = t.findings
	}
	for _, f := range fs[:limit] {
		signal := md(f.Title)
		if len(f.RaisedBy) > 0 {
			signal += " (raised by " + md(strings.Join(f.RaisedBy, ", ")) + ")"
		}
		if f.Demoted != "" {
			signal += " (demoted: " + md(f.Demoted) + ")"
		}
		where := "n/a"
		if f.File != "" {
			loc := f.File
			if f.Line > 0 {
				loc += ":" + strconv.Itoa(f.Line)
			}
			where = mdCode(loc)
		}
		ev := "n/a"
		if e := f.Evidence.String(); e != "" {
			ev = mdCode(e)
		}
		fmt.Fprintf(b, "| %s | %s | %s | %s |\n", f.Severity, signal, where, ev)
	}
	if more := len(fs) - limit; more > 0 {
		fmt.Fprintf(b, "\n%s not shown.\n", plural(more, "more finding", "more findings"))
	}
	if line := notCountedLine(u); line != "" {
		b.WriteString("\n" + line + "\n")
	}
	b.WriteString("\n")
	if t.hunks {
		m.hunks(b, u, fs)
	}
	if m.o.Demo {
		return // the demo's packages are made up: nothing to allow
	}
	if why := allowRefusal(u); why != "" {
		b.WriteString(why + "\n\n")
		return
	}
	fmt.Fprintf(b, "Record your review: %s\n\n", term.MarkdownCode(m.allowCommand(u)))
}

// The texts shown in place of the allow command for a version allow
// would refuse (E18), so nobody copies a command that fails.
const (
	allowUnverified = "This version isn't verified, so it can't be allowed yet."
	allowMismatch   = "This version doesn't match its published hash, so it can't be allowed."
	allowChanged    = "This allowed version now has other bytes, so it can't be allowed again until you know why."
)

// allowRefusal is why u's new version can't be allowed, or "" when the
// allow command works: a local copy, an unverified or tampered archive
// and an allowed version whose bytes changed are refused.
func allowRefusal(u *core.Update) string {
	has := func(id string) bool {
		return slices.ContainsFunc(u.Findings, func(f core.Finding) bool { return f.ID == id })
	}
	switch {
	case u.To.Verified == core.ByFailed || has("integrity-mismatch"):
		return allowMismatch
	case has("approved-version-changed"):
		return allowChanged
	case !verified(u.To) || u.To.Version == "":
		return allowUnverified
	}
	return ""
}

// allowCommand is the one-line allow for the reviewed version.
func (m mdReport) allowCommand(u *core.Update) string {
	return allowLine(m.o.Program, u)
}

// allowLine is the allow command for u's new version, shared by every
// format. The ref is shell quoted because a hostile plugin folder, tag or
// saved report could otherwise add a command to the line users paste.
func allowLine(program string, u *core.Update) string {
	ref := core.Ref{Eco: u.Eco, Name: u.Name, Version: u.To.Version}
	// Only a URL scheme is defanged: a real package name never holds one,
	// while defanging its dots would break names such as socket.io.
	return text(programName(program)) + " allow " + shellArg(defangScheme(text(ref.String()))) + ` --reason "..."`
}

// programName is the name commands are shown with: the option, else kit
// cli.Name() ("rhythm sightread" through the router).
func programName(p string) string {
	if p != "" {
		return p
	}
	return cli.Name()
}

func integrityLine(u *core.Update) string {
	to := methodText(u.To)
	if u.From.Version == "" {
		return "Integrity: " + term.EscapeMarkdown(to) + "."
	}
	from := methodText(u.From)
	if from == to {
		return "Integrity (both versions): " + term.EscapeMarkdown(to) + "."
	}
	return "Integrity: " + mdInline(u.From.Version) + ": " + term.EscapeMarkdown(from) + "; " + mdInline(u.To.Version) + ": " + term.EscapeMarkdown(to) + "."
}

func publisherLine(u *core.Update) string {
	from, to := strings.Join(u.From.Publisher, ", "), strings.Join(u.To.Publisher, ", ")
	switch {
	case to == "" && from == "":
		return "Publisher: not known."
	case u.From.Version != "" && from == "":
		return "Publisher: " + md(to) + " (no publisher known for " + mdInline(u.From.Version) + ")."
	case u.From.Version != "" && from != to:
		return "Publisher changed: " + md(orNone(from)) + " → " + md(orNone(to)) + "."
	}
	return "Publisher: " + md(to) + "."
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func changelogLine(u *core.Update) string {
	if len(u.Changelog) == 0 || strings.TrimSpace(u.Changelog[0].Text) == "" {
		return "Changelog: none for this version."
	}
	c := u.Changelog[0]
	return "Changelog: " + mdInline(c.Version) + ": \"" + md(firstLine(c.Text, 200)) + "\""
}

// firstLine is the first line of s, cut to max runes.
func firstLine(s string, max int) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	if r := []rune(s); len(r) > max {
		s = string(r[:max]) + "…"
	}
	return s
}

// notCountedLine lists findings that were set aside.
func notCountedLine(u *core.Update) string {
	var allowed, baselined, ignored, below int
	for i := range u.Findings {
		f := &u.Findings[i]
		switch {
		case f.Allowed != nil:
			allowed++
		case f.Baselined:
			baselined++
		case f.Ignored:
			ignored++
		case f.BelowConfidence:
			below++
		}
	}
	var parts []string
	for _, p := range []struct {
		n    int
		what string
	}{{allowed, "allowed"}, {baselined, "in the baseline"}, {ignored, "ignored by config"}, {below, "below --min-confidence"}} {
		if p.n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", p.n, p.what))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "Not counted: " + joinAnd(parts) + "."
}

// flagged returns the hunks that hold a finding of fs: the same path and,
// when the finding has a line, a range that covers it. A finding no hunk
// covers (its line sits just past the context the differ kept) takes the
// hunks of its file instead, so the reader still sees what changed there.
func flagged(u *core.Update, fs []*core.Finding) []core.Hunk {
	take := make([]bool, len(u.Hunks))
	for _, f := range fs {
		if f.File == "" {
			continue
		}
		found := false
		for i, h := range u.Hunks {
			if h.Path == f.File && covers(h, f) {
				take[i], found = true, true
			}
		}
		if !found {
			for i, h := range u.Hunks {
				if h.Path == f.File {
					take[i] = true
				}
			}
		}
	}
	var out []core.Hunk
	for i, h := range u.Hunks {
		if take[i] {
			out = append(out, h)
		}
	}
	return out
}

// covers reports whether the new side of h holds a line of f. A hunk of
// tokens numbers tokens, not lines, so it never covers a line (flagged
// then takes every hunk of the file).
func covers(h core.Hunk, f *core.Finding) bool {
	if f.Line == 0 {
		return true
	}
	if h.Tokens {
		return false
	}
	end := max(f.EndLine, f.Line)
	return f.Line < h.NewStart+max(h.NewLines, 1) && end >= h.NewStart
}

func (m mdReport) hunks(b *strings.Builder, u *core.Update, fs []*core.Finding) {
	hs := flagged(u, fs)
	if len(hs) == 0 {
		return
	}
	var body strings.Builder
	for _, h := range hs {
		body.WriteString(hunkTitle(h, defang(text(h.Path))) + "\n")
		for _, l := range h.Lines {
			// One hunk line is one output line, whatever it holds.
			body.WriteString(defang(strings.NewReplacer("\r", `\r`, "\n", `\n`).Replace(text(l))) + "\n")
		}
	}
	fence := strings.Repeat("`", max(3, longestRun(body.String(), '`')+1))
	b.WriteString("<details><summary>Diff of the flagged lines</summary>\n\n")
	b.WriteString(fence + "diff\n" + body.String() + fence + "\n</details>\n\n")
}

// longestRun is the longest run of c in s.
func longestRun(s string, c byte) int {
	longest, run := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			run++
			longest = max(longest, run)
		} else {
			run = 0
		}
	}
	return longest
}

func (m mdReport) unverified(b *strings.Builder) {
	var lines []string
	notDiffed := 0
	for _, u := range m.sorted() {
		if u.Verdict != core.Unverified {
			continue
		}
		if !diffed(u) {
			notDiffed++
		}
		why := "its integrity could not be checked"
		if len(u.Errors) > 0 {
			why = md(u.Errors[0].Message)
		}
		lines = append(lines, "- "+md(u.Name)+" "+mdInline(u.To.Version)+" ("+md(string(u.Eco))+"): "+why)
	}
	if len(lines) == 0 {
		return
	}
	b.WriteString("### Unverified\n\n" + strings.Join(lines, "\n") + "\n\n")
	switch {
	case notDiffed == 0:
		// --allow-unverified was used: their findings are above.
		b.WriteString("Reviewed with `--allow-unverified`: these releases could not be verified.\n\n")
	case notDiffed == len(lines):
		b.WriteString("Not reviewed as verified releases; `--allow-unverified` reviews them anyway.\n\n")
	default:
		b.WriteString("Some were not diffed; `--allow-unverified` reviews the ones not diffed anyway.\n\n")
	}
}

func (m mdReport) notChecked(b *strings.Builder) {
	if len(m.r.NotChecked) == 0 && len(m.r.Errors) == 0 {
		return
	}
	b.WriteString("### Not checked\n\n")
	codes, rest := m.r.PairErrors()
	for i, n := range m.r.NotChecked {
		line := "- " + md(n.Name)
		if n.Version != "" {
			line += " " + mdInline(n.Version)
		}
		if n.Eco != "" {
			line += " (" + md(string(n.Eco)) + ")"
		}
		line += ": " + md(n.Text)
		if codes[i] != "" {
			line += " (" + md(string(codes[i])) + ")"
		}
		if n.Hint != "" {
			line += ". " + md(capitalise(n.Hint))
		}
		b.WriteString(line + "\n")
	}
	for _, e := range rest {
		line := "- " + md(e.Name)
		if e.Eco != "" {
			line += " (" + md(string(e.Eco)) + ")"
		}
		b.WriteString(line + ": " + md(e.Message) + " (" + md(string(e.Code)) + ")\n")
	}
	b.WriteString("\n")
}

func capitalise(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func (m mdReport) footer() string {
	var b strings.Builder
	b.WriteString("---\n\n" + honestyLine + "\n\n" + intentLine + "\n\n")
	if m.o.Signed != "" {
		b.WriteString("Signed JSON report sha256: " + term.MarkdownCode(text(m.o.Signed)) + "\n\n")
	}
	fmt.Fprintf(&b, "[Signal reference](%s) · rhythm-sightread %s\n", signalReference, mdInline(toolVersion(m.o.Version)))
	return b.String()
}

// cutLines cuts s to at most n bytes at a line end.
func cutLines(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n < 0 {
		n = 0
	}
	s = s[:n]
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		s = s[:i+1]
	}
	return s
}
