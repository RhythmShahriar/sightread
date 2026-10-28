// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package report

// Derived from tuner/report/sarif.go (the SARIF shape and level mapping).

import (
	"bytes"
	"cmp"
	"fmt"
	"io"
	"maps"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

func init() { core.RegisterWriter(SARIFWriter{}) }

// SARIF 2.1.0, the subset GitHub code scanning reads.
// https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool        sarifTool         `json:"tool"`
	Invocations []sarifInvocation `json:"invocations"`
	Results     []sarifResult     `json:"results"`
}

// sarifInvocation says whether the run finished. An unverified update
// or an error sets executionSuccessful to false and says why in a
// notification, so a reader of the alerts knows some may be missing.
type sarifInvocation struct {
	ExecutionSuccessful        bool                `json:"executionSuccessful"`
	ToolExecutionNotifications []sarifNotification `json:"toolExecutionNotifications,omitempty"`
}

type sarifNotification struct {
	Level   string    `json:"level"`
	Message sarifText `json:"message"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string            `json:"id"`
	Name                 string            `json:"name"`
	ShortDescription     sarifText         `json:"shortDescription"`
	FullDescription      *sarifText        `json:"fullDescription,omitempty"`
	HelpURI              string            `json:"helpUri"`
	DefaultConfiguration sarifRuleDefaults `json:"defaultConfiguration"`
	Properties           map[string]any    `json:"properties"`
}

type sarifRuleDefaults struct {
	Level string `json:"level"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
	// PartialFingerprints lets code scanning follow an alert across
	// runs: the location is a lockfile line, which moves with every
	// unrelated change to the lockfile.
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Properties          map[string]any    `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

type sarifArtifactLocation struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId"`
}

// srcRoot names the repository root. GitHub's upload action resolves it
// to the checkout. Sightread never writes where it is on disk, so no
// path outside the repository reaches the file.
const srcRoot = "SRCROOT"

// maxSARIFResults is GitHub code scanning's limit per run.
const maxSARIFResults = 25000

// informationURI is the project page the driver links to.
const informationURI = "https://github.com/RhythmShahriar/sightread"

// securitySeverity is the 0 to 10 score GitHub ranks alerts by.
var securitySeverity = map[cli.Severity]string{
	cli.SeverityCritical: "9.5", cli.SeverityHigh: "8.0", cli.SeverityMedium: "5.5", cli.SeverityLow: "3.0", cli.SeverityInfo: "0.0",
}

// sarifLevel maps a severity to a SARIF level: critical and high are
// errors, medium a warning, the rest notes.
func sarifLevel(s cli.Severity) string {
	switch s {
	case cli.SeverityCritical, cli.SeverityHigh:
		return "error"
	case cli.SeverityMedium:
		return "warning"
	}
	return "note"
}

// SARIFWriter writes one SARIF 2.1.0 run for GitHub code scanning
// (PRD 9.3). Only findings that count are results: allowed, ignored,
// baselined and below-confidence findings are not alerts.
type SARIFWriter struct{}

var _ core.Writer = SARIFWriter{}

// Format returns "sarif".
func (SARIFWriter) Format() string { return core.FormatSARIF }

// Write writes r as a SARIF log.
func (SARIFWriter) Write(w io.Writer, r *core.Report, o core.WriteOptions) error {
	run := sarifRun{
		Tool: sarifTool{Driver: sarifDriver{Name: tool, Version: toolVersion(o.Version), InformationURI: informationURI,
			Rules: []sarifRule{}}},
		Results: []sarifResult{},
	}
	loc := newLocator(r.Target)
	seen := map[string]bool{}
	for i := range r.Updates {
		u := &r.Updates[i]
		where := loc.locate(u)
		for j := range u.Findings {
			f := &u.Findings[j]
			if !f.Counted() {
				continue
			}
			seen[f.ID] = true
			run.Results = append(run.Results, sarifResultFor(u, f, where))
		}
	}
	for _, s := range core.Catalog {
		if seen[s.ID] {
			run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRuleFor(s.ID))
			delete(seen, s.ID)
		}
	}
	// IDs outside the catalogue (a --signals rule pack), sorted.
	for _, id := range slices.Sorted(maps.Keys(seen)) {
		run.Tool.Driver.Rules = append(run.Tool.Driver.Rules, sarifRuleFor(id))
	}

	inv := sarifInvocation{ExecutionSuccessful: true}
	notes, failed := sarifNotifications(r)
	inv.ToolExecutionNotifications = notes
	inv.ExecutionSuccessful = !failed
	if n := len(run.Results); n > maxSARIFResults {
		// Worst first, so the alerts that are kept are the ones that matter.
		slices.SortStableFunc(run.Results, func(a, b sarifResult) int { return cmp.Compare(levelRank(a.Level), levelRank(b.Level)) })
		run.Results = run.Results[:maxSARIFResults]
		inv.ToolExecutionNotifications = append(inv.ToolExecutionNotifications, sarifNotification{Level: "warning",
			Message: sarifText{fmt.Sprintf("%d results, over GitHub's limit of %d per run: the first %d, worst first, are kept; the JSON report has them all",
				n, maxSARIFResults, maxSARIFResults)}})
	}
	run.Invocations = []sarifInvocation{inv}
	return encode(w, sarifLog{Schema: "https://json.schemastore.org/sarif-2.1.0.json", Version: "2.1.0", Runs: []sarifRun{run}}, true)
}

func levelRank(l string) int {
	switch l {
	case "error":
		return 0
	case "warning":
		return 1
	}
	return 2
}

func sarifRuleFor(id string) sarifRule {
	rule := sarifRule{ID: text(id), Name: text(id), HelpURI: helpURI(text(id)), Properties: map[string]any{"tags": []string{"security", "supply-chain"}}}
	if info, ok := core.Signal(id); ok {
		rule.ShortDescription = sarifText{info.Title}
		rule.DefaultConfiguration = sarifRuleDefaults{Level: sarifLevel(info.Severity)}
		rule.Properties["security-severity"] = securitySeverity[info.Severity]
	} else {
		rule.ShortDescription = sarifText{text(id)}
		rule.DefaultConfiguration = sarifRuleDefaults{Level: "warning"}
		rule.Properties["security-severity"] = securitySeverity[cli.SeverityMedium]
	}
	if e, ok := core.ExplainFor(id); ok && strings.TrimSpace(e.Why) != "" {
		rule.FullDescription = &sarifText{text(strings.TrimSpace(e.Why))}
	}
	return rule
}

func sarifResultFor(u *core.Update, f *core.Finding, where sarifPhysical) sarifResult {
	fp := f.Fingerprint
	if fp == "" {
		fp = core.Fingerprint(u.Eco, u.Name, u.To.Version, f.ID, f.File, f.Evidence)
	}
	return sarifResult{
		RuleID:              text(f.ID),
		Level:               sarifLevel(f.Severity),
		Message:             sarifText{sarifMessage(u, f)},
		Locations:           []sarifLocation{{PhysicalLocation: where}},
		PartialFingerprints: map[string]string{core.FingerprintKey: text(fp)},
		Properties: map[string]any{
			"ecosystem": text(string(u.Eco)), "package": text(u.Name), "from": text(u.From.Version), "to": text(u.To.Version),
			"package_path": text(f.File), "verdict": text(string(u.Verdict)), "security-severity": securitySeverity[f.Severity],
		},
	}
}

// sarifMessage is "<name> <from> → <to>: <title> (<path>:<line>).
// Verdict <VERDICT>." The path inside the package goes here because the
// location is where the version is pinned.
func sarifMessage(u *core.Update, f *core.Finding) string {
	var b strings.Builder
	b.WriteString(text(u.Name))
	if u.From.Version != "" {
		b.WriteString(" " + text(u.From.Version) + " →")
	}
	b.WriteString(" " + text(u.To.Version) + ": " + text(f.Title))
	if f.File != "" {
		b.WriteString(" (" + text(f.File))
		if f.Line > 0 {
			fmt.Fprintf(&b, ":%d", f.Line)
		}
		b.WriteString(")")
	}
	b.WriteString(". Verdict " + strings.ToUpper(text(string(u.Verdict))) + ".")
	return b.String()
}

// sarifNotifications lists what makes the run partial. failed is true
// when an update is unverified, an error was recorded or the run
// stopped early; packages that were not checked are listed as notes
// without failing the run, as the JSON's complete flag covers them.
func sarifNotifications(r *core.Report) (notes []sarifNotification, failed bool) {
	add := func(level, msg string) {
		notes = append(notes, sarifNotification{Level: level, Message: sarifText{msg}})
	}
	for i := range r.Updates {
		u := &r.Updates[i]
		if u.Verdict == core.Unverified {
			failed = true
			why := "its integrity could not be checked"
			if len(u.Errors) > 0 {
				why = text(u.Errors[0].Message)
			}
			add("error", fmt.Sprintf("%s %s is unverified: %s", text(u.Name), text(u.To.Version), why))
			if len(u.Errors) > 0 {
				for _, e := range u.Errors[1:] {
					add("error", errorText(e))
				}
				continue
			}
		}
		for _, e := range u.Errors {
			failed = true
			add("error", errorText(e))
		}
	}
	for _, e := range r.Errors {
		failed = true
		add("error", errorText(e))
	}
	switch r.StoppedBy {
	case "":
	case "deadline":
		failed = true
		add("error", "the run hit its --deadline; the results are partial")
	default:
		failed = true
		add("error", "the run was "+text(r.StoppedBy)+"; the results are partial")
	}
	for _, n := range r.NotChecked {
		msg := text(n.Name)
		if v := n.Versions("to"); v != "" {
			msg += " " + text(v)
		}
		add("note", msg+" not checked: "+text(cmp.Or(n.Text, string(n.Reason))))
	}
	return notes, failed
}

func errorText(e core.ErrorEntry) string {
	s := text(string(e.Code))
	if e.Name != "" {
		s += " " + text(e.Name)
	}
	return s + ": " + text(e.Message)
}

// locator finds where each update is pinned, relative to the repository
// that holds the target, or to the target when no repository does.
type locator struct {
	target string // absolute target folder, "" for a remote target
	base   string // repository root, or target
	inRepo bool
	// prefix is the target's path inside the repository when the
	// folder itself is not on this machine (a redacted or merged report
	// read elsewhere): URIs are prefix joined with the path.
	prefix string
}

// newLocator finds the target's files. An absolute Path is read as it
// is. A report whose Path was redacted or merged away still carries the
// target's RepoPath: when the working folder is inside a repository
// that holds that folder (report runs in the same checkout), the files
// are read there; else every URI is RepoPath joined with the path.
func newLocator(t core.Target) locator {
	l := locator{}
	if t.Path != "" && filepath.IsAbs(t.Path) {
		l.target = filepath.Clean(t.Path)
		l.base = l.target
		if root := repoRoot(l.target); root != "" {
			l.base, l.inRepo = root, true
		}
		return l
	}
	rp := cleanRepoPath(t.RepoPath)
	if rp == "" {
		return l
	}
	if wd, err := os.Getwd(); err == nil {
		if root := repoRoot(wd); root != "" {
			if dir := filepath.Join(root, filepath.FromSlash(rp)); isDir(dir) {
				return locator{target: dir, base: root, inRepo: true}
			}
		}
	}
	return locator{prefix: rp}
}

// TargetRepoPath is t's RepoPath, worked out from an absolute Path
// when the report doesn't carry one yet.
func TargetRepoPath(t core.Target) string {
	if t.RepoPath != "" || t.Path == "" || !filepath.IsAbs(t.Path) {
		return cleanRepoPath(t.RepoPath)
	}
	dir := filepath.Clean(t.Path)
	root := repoRoot(dir)
	if root == "" {
		return ""
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil {
		return ""
	}
	return cleanRepoPath(filepath.ToSlash(rel))
}

// cleanRepoPath keeps a repository path that stays inside the
// repository: relative, forward slashes, no "..". Anything else is ""
// so a crafted report can't point SARIF outside the repository.
func cleanRepoPath(p string) string {
	if p == "" || strings.Contains(p, `\`) {
		return ""
	}
	c := path.Clean(p)
	if path.IsAbs(c) || c == ".." || strings.HasPrefix(c, "../") {
		return ""
	}
	return c
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// repoRoot is the nearest folder from dir upwards that holds .git.
func repoRoot(dir string) string {
	for d := dir; ; {
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			return ""
		}
		d = parent
	}
}

// locate is the primary location of every result of u: the lockfile
// line of a Composer or npm package, else the plugin or theme main file
// when the site is inside the repository, else the target folder.
func (l locator) locate(u *core.Update) sarifPhysical {
	if (u.Eco == core.Composer || u.Eco == core.NPM) && u.Installed.Lockfile != "" {
		if uri, ok := l.uri(u.Installed.Lockfile); ok {
			p := sarifPhysical{ArtifactLocation: sarifArtifactLocation{URI: uri, URIBaseID: srcRoot}}
			if u.Installed.LockLine > 0 {
				p.Region = &sarifRegion{StartLine: u.Installed.LockLine}
			}
			return p
		}
	}
	if l.inRepo && (u.Eco == core.WPPlugin || u.Eco == core.WPTheme) && u.Installed.Path != "" {
		if main := mainFile(filepath.Join(l.target, filepath.FromSlash(u.Installed.Path)), u.Eco, u.Name); main != "" {
			if uri, ok := l.uri(filepath.Join(u.Installed.Path, main)); ok {
				return sarifPhysical{ArtifactLocation: sarifArtifactLocation{URI: uri, URIBaseID: srcRoot}}
			}
		}
	}
	if l.prefix != "" && (u.Eco == core.WPPlugin || u.Eco == core.WPTheme) && u.Installed.Path != "" {
		// The folder isn't here to find its main file in: point at the
		// plugin or theme folder, which is still the right place.
		if uri, ok := l.uri(u.Installed.Path); ok {
			return sarifPhysical{ArtifactLocation: sarifArtifactLocation{URI: uri, URIBaseID: srcRoot}}
		}
	}
	uri, _ := l.uri(".")
	return sarifPhysical{ArtifactLocation: sarifArtifactLocation{URI: uri, URIBaseID: srcRoot}}
}

// uri turns a path relative to the target into a URI relative to the
// base. ok is false for a path that would leave the repository: no URI
// in the file points outside it.
func (l locator) uri(rel string) (string, bool) {
	rel = filepath.ToSlash(rel)
	if l.target == "" {
		c := path.Clean(rel)
		switch {
		case rel == "" || path.IsAbs(c) || c == ".." || strings.HasPrefix(c, "../"):
			return ".", false
		}
		if c = path.Join(cmp.Or(l.prefix, "."), c); c == "." {
			return ".", true
		}
		return escapeURI(c), true
	}
	// A rooted path such as /etc/composer.lock isn't absolute on Windows,
	// where it lacks a drive letter; it still names no file under
	// the target; neither does a drive-relative C:composer.lock.
	if fp := filepath.FromSlash(rel); filepath.IsAbs(fp) || filepath.VolumeName(fp) != "" || strings.HasPrefix(rel, "/") {
		return ".", false
	}
	abs := filepath.Join(l.target, filepath.FromSlash(rel))
	r, err := filepath.Rel(l.base, abs)
	if err != nil || r == ".." || strings.HasPrefix(r, ".."+string(filepath.Separator)) {
		return ".", false
	}
	if r == "." {
		return ".", true
	}
	return escapeURI(filepath.ToSlash(r)), true
}

func escapeURI(p string) string { return text((&url.URL{Path: p}).String()) }

// mainFile is the file of a plugin or theme folder that carries its
// header: style.css for a theme, <slug>.php or the first top-level PHP
// file with a "Plugin Name:" header for a plugin.
func mainFile(dir string, eco core.Ecosystem, slug string) string {
	if eco == core.WPTheme {
		if fileExists(filepath.Join(dir, "style.css")) {
			return "style.css"
		}
		return ""
	}
	if slug != "" && !strings.ContainsAny(slug, `/\`) && fileExists(filepath.Join(dir, slug+".php")) {
		return slug + ".php"
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() || !strings.EqualFold(filepath.Ext(e.Name()), ".php") {
			continue
		}
		if hasPluginHeader(filepath.Join(dir, e.Name())) {
			return e.Name()
		}
	}
	return ""
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.Mode().IsRegular()
}

// hasPluginHeader reads the first 8 KiB of a PHP file, where WordPress
// looks for headers.
func hasPluginHeader(p string) bool {
	f, err := os.Open(p) //nolint:gosec // a file of the user's own site, read only
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, 8<<10)
	n, _ := io.ReadFull(f, buf)
	return bytes.Contains(buf[:n], []byte("Plugin Name:"))
}
