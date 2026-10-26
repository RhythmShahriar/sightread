// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package report

import (
	"crypto/sha256"
	_ "embed" // the page template and its script
	"encoding/base64"
	"fmt"
	"html/template"
	"io"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

func init() { core.RegisterWriter(HTMLWriter{}) }

// HTMLWriter writes one self-contained page (PRD 9.5): inline CSS with
// light and dark themes and one inline script whose hash is the only
// script the Content-Security-Policy allows. Every value from a package
// goes through html/template as text; nothing from a package becomes
// markup, a link or an attribute that loads anything.
type HTMLWriter struct{}

var _ core.Writer = HTMLWriter{}

// Format returns "html".
func (HTMLWriter) Format() string { return core.FormatHTML }

var (
	//go:embed html.tmpl
	htmlSource string
	//go:embed html.js
	htmlScript string

	htmlPage = template.Must(template.New("html").Funcs(template.FuncMap{
		"upper": strings.ToUpper,
		"lower": strings.ToLower,
	}).Parse(htmlSource))

	// htmlCSP allows the one inline script by its hash, inline styles and
	// data: images; nothing else: no fetch, no frame, no form target.
	htmlCSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; script-src 'sha256-" + scriptHash(htmlScript) + "'"
)

// scriptHash is the CSP source hash of an inline script: base64 of the
// SHA-256 of the exact bytes between <script> and </script>.
func scriptHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// Write renders r as HTML.
func (HTMLWriter) Write(w io.Writer, r *core.Report, o core.WriteOptions) error {
	return htmlPage.Execute(w, newHTMLView(r, o))
}

// htmlView is everything the template shows, already made safe as text.
type htmlView struct {
	CSP     string
	Script  template.JS // our own embedded script, never package text
	Title   string
	Target  string
	Date    string
	Version string
	Packs   string
	Fleet   bool
	Sites   []string

	Pills      []htmlPill
	Notes      []string
	Incomplete string
	Rows       []htmlRow
	Cards      []htmlCard
	HasDiff    bool
	Soundcheck []htmlSoundcheck
	NotChecked []string
	Errors     []string
	Warnings   []string

	Honesty, Intent, Signed, Program, Reference string
}

type htmlPill struct {
	Class, Label string
	N            int
}

type htmlRow struct {
	Anchor, Verdict, Name, Eco, From, To, Findings string
	Rank, Worst, Sites                             int
}

type htmlCard struct {
	Anchor, Verdict, Class, Name, Eco, From, To string
	Sites                                       []string
	Installed, Source, URL, SHA256, Integrity   string
	Verified                                    bool
	Publisher                                   string
	PublisherChanged                            bool
	Changelog, ChangelogVersion                 string
	Adds                                        []htmlCount
	DiffLine                                    string
	SizeFrom, SizeTo                            string
	FromPct, ToPct                              int
	Findings, Set                               []htmlFinding
	SetLine                                     string
	Flagged                                     []htmlFile
	Rest                                        []htmlDir
	RestCount                                   int
	Allow, AllowSHA                             string
	// AllowWhy is why allow would refuse the version, shown in place of
	// the command: one of Sightread's own fixed texts, never package text.
	AllowWhy template.HTML
	Errors   []string
}

type htmlCount struct {
	Label string
	N     int
}

type htmlFinding struct {
	ID, Title, Severity, Confidence, Where, Evidence, Advice, Raised, Demoted, Status string
	Domains                                                                           []string
	Why, HowToReview, FalseAlarms                                                     string
}

type htmlFile struct {
	Path     string
	Minified string
	Hunks    []htmlHunk
}

type htmlDir struct {
	Dir   string
	Files []htmlFile
}

type htmlHunk struct{ Lines []htmlLine }

// htmlLine is one row of a unified diff. K is the row kind the script
// reads to build the side by side view: "@", "+", "-" or " ".
type htmlLine struct {
	K, Class, Old, New, Text string
}

type htmlSoundcheck struct {
	Name, Staging, Applied, Report, Counts string
	RolledBack                             bool
}

func newHTMLView(r *core.Report, o core.WriteOptions) htmlView {
	p := newPaths(r.Target.Path, o.RedactPaths)
	v := htmlView{
		CSP: htmlCSP, Script: template.JS(htmlScript), //nolint:gosec // G203: the embedded script, hashed into the CSP
		Version: toolVersion(o.Version), Fleet: len(r.Target.Sites) > 0, Sites: texts(r.Target.Sites),
		Honesty: honestyLine, Intent: intentLine, Signed: text(o.Signed), Program: text(programName(o.Program)),
		Reference: signalReference,
	}
	v.Target = text(p.path(r.Target.Path))
	if v.Target == "" {
		v.Target = text(r.Target.Kind)
	}
	v.Title = "Sightread review"
	if v.Target != "" {
		v.Title += ": " + v.Target
	}
	if !r.Started.IsZero() {
		v.Date = r.Started.UTC().Format("2006-01-02 15:04 UTC")
	}
	if packs := packLine(r); packs != "" {
		v.Packs = packs
	}
	s := r.Summary
	v.Pills = []htmlPill{{"hold", "hold", s.Hold}, {"review", "review", s.Review}, {"routine", "routine", s.Routine}, {"allowed", "allowed", s.Allowed}}
	if s.Unverified > 0 {
		v.Pills = append(v.Pills, htmlPill{"unverified", "unverified", s.Unverified})
	}
	for _, n := range r.Notes {
		v.Notes = append(v.Notes, p.text(text(n)))
	}
	v.Incomplete = incompleteText(r)

	for i, u := range byVerdict(r) {
		anchor := "u" + strconv.Itoa(i+1)
		v.Rows = append(v.Rows, htmlRow{Anchor: anchor, Verdict: strings.ToUpper(string(u.Verdict)), Rank: rank(u.Verdict),
			Name: text(u.Name), Eco: text(string(u.Eco)), From: orText(u.From.Version, "new"), To: text(u.To.Version),
			Findings: findingCounts(u), Worst: worst(u), Sites: len(u.Sites)})
		c := newHTMLCard(u, anchor, p, o)
		if len(c.Flagged) > 0 || len(c.Rest) > 0 {
			v.HasDiff = true
		}
		v.Cards = append(v.Cards, c)
		if sc := u.Soundcheck; sc != nil {
			v.Soundcheck = append(v.Soundcheck, htmlSoundcheck{Name: text(u.Name) + " " + text(u.To.Version), Staging: text(sc.Staging),
				Applied: text(sc.Applied), Report: text(p.path(sc.Report)), RolledBack: sc.RolledBack,
				Counts: fmt.Sprintf("%d broke, %d new, %d changed", sc.Broke, sc.New, sc.Changed)})
		}
	}
	codes, rest := r.PairErrors()
	for i, n := range r.NotChecked {
		line := text(n.Name)
		if n.Version != "" {
			line += " " + text(n.Version)
		}
		if n.Eco != "" {
			line += " (" + text(string(n.Eco)) + ")"
		}
		line += ": " + p.text(text(n.Text))
		if codes[i] != "" {
			line += " (" + text(string(codes[i])) + ")"
		}
		if n.Hint != "" {
			line += ". " + capitalise(p.text(text(n.Hint)))
		}
		v.NotChecked = append(v.NotChecked, line)
	}
	for _, e := range rest {
		line := text(e.Name)
		if e.Eco != "" {
			line += " (" + text(string(e.Eco)) + ")"
		}
		v.Errors = append(v.Errors, line+": "+p.text(text(e.Message))+" ("+text(string(e.Code))+")")
	}
	for _, w := range r.Warnings {
		v.Warnings = append(v.Warnings, p.text(text(w)))
	}
	return v
}

// packLine names the data packs the run used.
func packLine(r *core.Report) string {
	var parts []string
	if r.SignalPack != "" {
		parts = append(parts, "signals "+text(r.SignalPack))
	}
	if r.NamesPack != "" {
		parts = append(parts, "names "+text(r.NamesPack))
	}
	return strings.Join(parts, " · ")
}

func orText(s, none string) string {
	if s == "" {
		return none
	}
	return text(s)
}

// byVerdict returns the updates worst first, then by name, keeping the
// pipeline's order among equals.
func byVerdict(r *core.Report) []*core.Update {
	ups := make([]*core.Update, 0, len(r.Updates))
	for i := range r.Updates {
		ups = append(ups, &r.Updates[i])
	}
	slices.SortStableFunc(ups, func(a, b *core.Update) int {
		if d := rank(a.Verdict) - rank(b.Verdict); d != 0 {
			return d
		}
		return strings.Compare(a.Name, b.Name)
	})
	return ups
}

// worst ranks the worst counted finding for sorting: 0 critical, 5 none.
func worst(u *core.Update) int {
	best := len(severities)
	for _, f := range counted(u) {
		if i := slices.Index(severities, f.Severity); i >= 0 && i < best {
			best = i
		}
	}
	return best
}

// incompleteText says why a run is partial, as plain text.
func incompleteText(r *core.Report) string {
	if r.Complete {
		return ""
	}
	if parts := incompleteParts(r); len(parts) > 0 {
		return "Incomplete review: " + joinAnd(parts) + "."
	}
	return "Incomplete review."
}

// incompleteParts lists what a partial run left out, so a reader of a
// green report sees what it didn't cover.
func incompleteParts(r *core.Report) []string {
	s := r.Summary
	var parts []string
	if s.Unverified > 0 {
		parts = append(parts, plural(s.Unverified, "update couldn't be verified", "updates couldn't be verified"))
	}
	if n := core.CountNotChecked(r.NotChecked); n > 0 {
		parts = append(parts, plural(n, "package wasn't checked", "packages weren't checked"))
	}
	if errs := r.ErrorCount(); errs > 0 {
		parts = append(parts, plural(errs, "error", "errors"))
	}
	switch r.StoppedBy {
	case "":
	case "deadline":
		parts = append(parts, "the run hit its --deadline")
	default:
		parts = append(parts, "the run was "+text(r.StoppedBy))
	}
	return parts
}

func newHTMLCard(u *core.Update, anchor string, p paths, o core.WriteOptions) htmlCard {
	c := htmlCard{Anchor: anchor, Verdict: strings.ToUpper(string(u.Verdict)), Class: string(u.Verdict),
		Name: text(u.Name), Eco: text(string(u.Eco)), From: text(u.From.Version), To: text(u.To.Version),
		Sites: texts(u.Sites), Source: text(u.To.Source), URL: defang(text(u.To.URL)), SHA256: text(u.To.SHA256),
		Verified: u.To.Verified != "" && u.To.Verified != core.ByNone && u.To.Verified != core.ByFailed}
	switch {
	case u.Installed.Lockfile != "":
		c.Installed = text(p.path(u.Installed.Lockfile))
		if u.Installed.LockLine > 0 {
			c.Installed += ":" + strconv.Itoa(u.Installed.LockLine)
		}
	case u.Installed.Path != "":
		c.Installed = text(p.path(u.Installed.Path))
	}
	c.Integrity = integrityText(u)
	c.Publisher, c.PublisherChanged = publisherText(u)
	if len(u.Changelog) > 0 && strings.TrimSpace(u.Changelog[0].Text) != "" {
		c.ChangelogVersion = text(u.Changelog[0].Version)
		c.Changelog = firstLine(text(u.Changelog[0].Text), 400)
	}
	c.Adds = adds(u)
	d := u.Diff
	if d.FilesChanged+d.FilesAdded+d.FilesRemoved+d.LinesAdded+d.LinesRemoved > 0 {
		c.DiffLine = fmt.Sprintf("%s changed, %d added, %d removed; +%d -%d lines",
			plural(d.FilesChanged, "file", "files"), d.FilesAdded, d.FilesRemoved, d.LinesAdded, d.LinesRemoved)
	}
	if d.BytesFrom > 0 || d.BytesTo > 0 {
		c.SizeFrom, c.SizeTo = humanBytes(d.BytesFrom), humanBytes(d.BytesTo)
		top := max(d.BytesFrom, d.BytesTo)
		c.FromPct, c.ToPct = pct(d.BytesFrom, top), pct(d.BytesTo, top)
	}
	for i := range u.Findings {
		f := &u.Findings[i]
		hf := newHTMLFinding(f)
		if f.Counted() {
			c.Findings = append(c.Findings, hf)
		} else {
			c.Set = append(c.Set, hf)
		}
	}
	c.SetLine = notCountedText(u)
	c.Flagged, c.Rest, c.RestCount = diffFiles(u)
	// HOLD, REVIEW and UNVERIFIED are what someone reviews; ALLOWED is
	// already on record and ROUTINE has nothing to accept.
	if (u.Verdict == core.Hold || u.Verdict == core.Review || u.Verdict == core.Unverified) && u.To.Version != "" && !o.Demo {
		c.Allow = allowLine(o.Program, u)
		why := allowRefusal(u)
		//nolint:gosec // a fixed text of this package, kept unescaped so the apostrophes stay as typed
		if c.AllowWhy = template.HTML(why); why == "" {
			c.AllowSHA = c.SHA256
		}
	}
	for _, e := range u.Errors {
		c.Errors = append(c.Errors, p.text(text(e.Message)))
	}
	return c
}

func pct(n, top int64) int {
	if top <= 0 || n <= 0 {
		return 0
	}
	return int(max(1, n*100/top))
}

// humanBytes writes a size the way the terminal does: 48 KB, 1.2 MB.
func humanBytes(n int64) string {
	switch {
	case n < 1024:
		return strconv.FormatInt(n, 10) + " B"
	case n < 1024*1024:
		return strconv.FormatInt((n+512)/1024, 10) + " KB"
	}
	return strconv.FormatFloat(float64(n)/(1024*1024), 'f', 1, 64) + " MB"
}

func integrityText(u *core.Update) string {
	to := methodText(u.To)
	if u.From.Version == "" {
		return to
	}
	from := methodText(u.From)
	if from == to {
		return "both versions: " + to
	}
	return text(u.From.Version) + ": " + from + "; " + text(u.To.Version) + ": " + to
}

// methodText says how one side was verified: the source's Method text,
// else a short phrase from Verified.
func methodText(s core.Side) string {
	if m := strings.TrimSpace(s.Method); m != "" {
		return text(m)
	}
	switch s.Verified {
	case "", core.ByNone:
		return "not verified"
	case core.ByFailed:
		return "does not match the published hash"
	}
	return "verified by " + text(string(s.Verified))
}

func publisherText(u *core.Update) (string, bool) {
	from, to := text(strings.Join(u.From.Publisher, ", ")), text(strings.Join(u.To.Publisher, ", "))
	switch {
	case to == "" && from == "":
		return "not known", false
	case u.From.Version != "" && from == "":
		return to + " (no publisher known for " + text(u.From.Version) + ")", false
	case u.From.Version != "" && from != to:
		return orNone(from) + " → " + orNone(to), true
	}
	return to, false
}

// featureKinds groups signals by what they show the new code doing, for
// the "what the diff adds" list beside the changelog. A signal may sit
// in two groups (fetching remote code is network and execution).
var featureKinds = []struct {
	label string
	ids   []string
}{
	{"network", []string{"remote-fetch-exec", "outbound-new-domain", "data-exfil", "rest-open-route", "bot-cloaking"}},
	{"execution", []string{"remote-fetch-exec", "decode-exec", "eval-dynamic", "obfuscation", "input-unserialize", "code-in-asset",
		"npm-install-script-new", "composer-plugin-new", "composer-autoload-files", "unicode-hidden"}},
	{"files", []string{"write-outside-package", "files-removed", "archive-path-escape", "archive-link", "archive-collision"}},
	{"users", []string{"admin-user-create", "admin-user-hidden", "capability-change", "credential-access"}},
	{"cron", []string{"cron-new-hook"}},
	{"dependencies", []string{"dependency-new", "typosquat", "dependency-confusion", "lockfile-source-change", "known-vulnerable", "php-requirement"}},
}

// adds counts the findings of every kind, set aside ones included: the
// list describes the code, not the verdict.
func adds(u *core.Update) []htmlCount {
	out := make([]htmlCount, 0, len(featureKinds))
	for _, k := range featureKinds {
		n := 0
		for i := range u.Findings {
			if slices.Contains(k.ids, u.Findings[i].ID) {
				n++
			}
		}
		out = append(out, htmlCount{k.label, n})
	}
	return out
}

func newHTMLFinding(f *core.Finding) htmlFinding {
	hf := htmlFinding{ID: text(f.ID), Title: text(f.Title), Severity: f.Severity.String(), Confidence: string(f.Confidence),
		Evidence: defang(text(f.Evidence.String())), Advice: text(f.Advice), Demoted: text(f.Demoted)}
	if !slices.Contains(severities, f.Severity) {
		hf.Severity = cli.SeverityInfo.String()
	}
	if f.File != "" {
		hf.Where = text(f.File)
		if f.Line > 0 {
			hf.Where += ":" + strconv.Itoa(f.Line)
		}
	}
	if len(f.RaisedBy) > 0 {
		hf.Raised = text(strings.Join(f.RaisedBy, ", "))
	}
	for _, d := range f.Domains {
		hf.Domains = append(hf.Domains, defang(text(d)))
	}
	switch {
	case f.Allowed != nil:
		hf.Status = "allowed by " + text(f.Allowed.By) + " on " + text(f.Allowed.Date)
		if f.Allowed.Reason != "" {
			hf.Status += ": " + text(f.Allowed.Reason)
		}
	case f.Baselined:
		hf.Status = "in the baseline"
	case f.Ignored:
		hf.Status = "ignored by config"
	case f.BelowConfidence:
		hf.Status = "below --min-confidence"
	}
	if e, ok := core.ExplainFor(f.ID); ok {
		hf.Why, hf.HowToReview, hf.FalseAlarms = text(e.Why), text(e.HowToReview), text(e.FalseAlarms)
	}
	return hf
}

// notCountedText is notCountedLine without Markdown.
func notCountedText(u *core.Update) string {
	return strings.TrimPrefix(notCountedLine(u), "Not counted: ")
}

// minifiedLine is a line length no hand-written source reaches.
const minifiedLine = 1000

// diffFiles splits the hunks into the files with a counted finding
// (shown open) and the rest, grouped by folder (collapsed).
func diffFiles(u *core.Update) (flaggedFiles []htmlFile, rest []htmlDir, restCount int) {
	hot := flagged(u, counted(u))
	isHot := func(h core.Hunk) bool {
		for _, x := range hot {
			if x.Path == h.Path && x.NewStart == h.NewStart && x.OldStart == h.OldStart {
				return true
			}
		}
		return false
	}
	var hotFiles, coldFiles []htmlFile
	add := func(files []htmlFile, h core.Hunk) []htmlFile {
		p := text(h.Path)
		if n := len(files); n > 0 && files[n-1].Path == p {
			files[n-1].Hunks = append(files[n-1].Hunks, htmlHunkOf(h))
			return files
		}
		return append(files, htmlFile{Path: p, Hunks: []htmlHunk{htmlHunkOf(h)}})
	}
	for _, h := range u.Hunks {
		if isHot(h) {
			hotFiles = add(hotFiles, h)
		} else {
			coldFiles = add(coldFiles, h)
		}
	}
	for i := range hotFiles {
		summariseMinified(u, &hotFiles[i])
	}
	slices.SortStableFunc(coldFiles, func(a, b htmlFile) int { return strings.Compare(a.Path, b.Path) })
	for _, f := range coldFiles {
		summariseMinified(u, &f)
		dir := path.Dir(f.Path)
		if n := len(rest); n > 0 && rest[n-1].Dir == dir {
			rest[n-1].Files = append(rest[n-1].Files, f)
		} else {
			rest = append(rest, htmlDir{Dir: dir, Files: []htmlFile{f}})
		}
	}
	return hotFiles, rest, len(coldFiles)
}

// summariseMinified replaces a minified file's hunks with one line:
// "minified, 48 KB, not shown; 2 new domains in it".
func summariseMinified(u *core.Update, f *htmlFile) {
	name := strings.ToLower(f.Path)
	minified := strings.HasSuffix(name, ".min.js") || strings.HasSuffix(name, ".min.css") || strings.HasSuffix(name, ".bundle.js")
	var size int64
	for _, h := range f.Hunks {
		for _, l := range h.Lines {
			if l.K == "@" {
				continue
			}
			size += int64(len(l.Text))
			if len(l.Text) > minifiedLine {
				minified = true
			}
		}
	}
	if !minified {
		return
	}
	domains := map[string]bool{}
	for i := range u.Findings {
		if text(u.Findings[i].File) == f.Path {
			for _, d := range u.Findings[i].Domains {
				domains[d] = true
			}
		}
	}
	f.Minified = "minified, " + humanBytes(size) + ", not shown"
	if len(domains) > 0 {
		f.Minified += "; " + plural(len(domains), "new domain", "new domains") + " in it"
	}
	f.Hunks = nil
}

func htmlHunkOf(h core.Hunk) htmlHunk {
	var out htmlHunk
	if head := hunkHead(h); head != "" {
		out.Lines = append(out.Lines, htmlLine{K: "@", Class: "hunk", Text: head})
	}
	oldN, newN := h.OldStart, h.NewStart
	for _, raw := range h.Lines {
		l := defang(strings.NewReplacer("\r", `\r`, "\n", `\n`).Replace(text(raw)))
		if noteLine(l) {
			// Sightread's note: no line of either side, no number.
			out.Lines = append(out.Lines, htmlLine{K: `\`, Class: "note", Text: strings.TrimPrefix(l, notePrefix)})
			continue
		}
		k, body := " ", l
		if l != "" && (l[0] == '+' || l[0] == '-' || l[0] == ' ') {
			k, body = l[:1], l[1:]
		}
		line := htmlLine{K: k, Text: body}
		switch k {
		case "+":
			line.Class, line.New = "add", strconv.Itoa(newN)
			newN++
		case "-":
			line.Class, line.Old = "del", strconv.Itoa(oldN)
			oldN++
		default:
			line.Class, line.Old, line.New = "ctx", strconv.Itoa(oldN), strconv.Itoa(newN)
			oldN++
			newN++
		}
		out.Lines = append(out.Lines, line)
	}
	return out
}
