// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

func init() { core.SetReportReader(ReadReport) }

// maxReportBytes caps a saved report. One with every hunk of a large
// site is tens of megabytes; this leaves room and still stops a file
// that would exhaust memory.
const maxReportBytes = 512 << 20

// readEnvelope is the envelope with the review data typed, for a strict
// decode.
type readEnvelope struct {
	Schema   string          `json:"schema"`
	Kind     string          `json:"kind"`
	Tool     string          `json:"tool"`
	Version  string          `json:"version"`
	Complete bool            `json:"complete"`
	Summary  jsonSummary     `json:"summary"`
	Verdict  string          `json:"verdict"`
	Data     json.RawMessage `json:"data"`
}

// ReadReport parses a kind review document the json writer wrote back
// into a core.Report (core.SetReportReader). It decodes strictly: a
// field this version doesn't know, a severity or a time that doesn't
// parse is an E12, as is a document of another schema or kind. Text is
// cleaned on the way in as on the way out, since a report file is as
// untrusted as the packages it describes.
func ReadReport(r io.Reader) (*core.Report, error) {
	name := "the report"
	if f, ok := r.(interface{ Name() string }); ok && f.Name() != "" {
		name = displayName(f.Name())
	}
	raw, err := io.ReadAll(io.LimitReader(r, maxReportBytes+1))
	if err != nil {
		return nil, notReport(name, fmt.Sprintf("can't be read (%v)", err))
	}
	if len(raw) > maxReportBytes {
		return nil, notReport(name, "is over 512 MiB, more than a report ever needs")
	}
	// The schema and kind first, with nothing else checked, so another
	// tool's JSON gets the plain message.
	var head struct {
		Schema string `json:"schema"`
		Kind   string `json:"kind"`
	}
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, notReport(name, "is not valid JSON ("+jsonProblem(err)+")")
	}
	if head.Schema != core.Schema {
		return nil, notReport(name, "is not a rhythm-sightread report")
	}
	if head.Kind != core.KindReview {
		return nil, notReport(name, fmt.Sprintf("is a rhythm-sightread %q document, not a review report", text(head.Kind)))
	}
	var env readEnvelope
	if err := strict(raw, &env); err != nil {
		return nil, notReport(name, "is not a rhythm-sightread review report ("+jsonProblem(err)+")")
	}
	var data jsonReview
	if err := strict(env.Data, &data); err != nil {
		return nil, notReport(name, "is not a rhythm-sightread review report ("+jsonProblem(err)+")")
	}
	rep, err := reportFromJSON(&env, &data)
	if err != nil {
		return nil, notReport(name, "is not a rhythm-sightread review report ("+err.Error()+")")
	}
	return rep, nil
}

func strict(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("more than one JSON value")
	}
	return nil
}

// jsonProblem turns a decoder error into text for the message.
func jsonProblem(err error) string {
	var syn *json.SyntaxError
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) || errors.As(err, &syn) && strings.Contains(syn.Error(), "unexpected end") {
		return "the file ends early"
	}
	return text(strings.TrimPrefix(err.Error(), "json: "))
}

func notReport(name, what string) *core.Error {
	return &core.Error{Code: core.EBadConfig, Exit: cli.ExitUsage, What: name + " " + what,
		Hint: []string{"give the JSON a review wrote, such as -o sightread.json"}}
}

// displayName shows a file relative to the working folder when it is
// inside it, with forward slashes, as the policy messages do.
func displayName(path string) string {
	if wd, err := os.Getwd(); err == nil && filepath.IsAbs(path) {
		if rel, err := filepath.Rel(wd, path); err == nil && !strings.HasPrefix(rel, "..") {
			path = rel
		}
	}
	return text(filepath.ToSlash(path))
}

func reportFromJSON(env *readEnvelope, d *jsonReview) (*core.Report, error) {
	started, err := parseTime("data.started", d.Started)
	if err != nil {
		return nil, err
	}
	s := env.Summary
	r := &core.Report{
		Kind:          core.KindReview,
		Target:        core.Target{Path: text(d.Target.Path), RepoPath: cleanRepoPath(text(d.Target.RepoPath)), Kind: text(d.Target.Kind), WordPress: text(d.Target.WordPress), Sites: nilIfEmpty(texts(d.Target.Sites))},
		Started:       started,
		Duration:      time.Duration(d.DurationMS) * time.Millisecond,
		StoppedBy:     text(d.StoppedBy),
		SignalPack:    text(d.SignalPack),
		NamesPack:     text(d.NamesPack),
		FailOn:        text(d.FailOn),
		MinConfidence: text(d.MinConfidence),
		Complete:      env.Complete,
		Summary: core.Summary{Updates: s.Updates, Hold: s.Hold, Review: s.Review, Routine: s.Routine, Allowed: s.Allowed,
			Unverified: s.Unverified, Critical: s.Critical, High: s.High, Medium: s.Medium, Low: s.Low, Info: s.Info,
			Baselined: s.Baselined, AllowedFindings: s.AllowedFindings, Ignored: s.Ignored, Demoted: s.Demoted,
			NotChecked: s.NotChecked, FromCache: s.FromCache},
		Warnings: nilIfEmpty(texts(d.Warnings)),
		Notes:    nilIfEmpty(texts(d.Notes)),
		Errors:   errorsFromJSON(d.Errors),
	}
	for _, n := range d.NotChecked {
		r.NotChecked = append(r.NotChecked, core.NotChecked{Eco: core.Ecosystem(text(n.Ecosystem)), Name: text(n.Name),
			Version: text(n.Version), Reason: core.NotCheckedReason(text(n.Reason)), Text: text(n.Text), Hint: text(n.Hint)})
	}
	if d.Updates != nil {
		for i, ju := range *d.Updates {
			u, err := updateFromJSON(&ju)
			if err != nil {
				return nil, fmt.Errorf("data.updates[%d]: %w", i, err)
			}
			r.Updates = append(r.Updates, u)
		}
	}
	return r, nil
}

func parseTime(field, s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%s %q is not an RFC 3339 time", field, text(s))
	}
	return t.UTC(), nil
}

func sideFromJSON(field string, j jsonSide) (core.Side, error) {
	s := core.Side{Version: text(j.Version), Source: text(j.Source), URL: text(j.URL), SHA256: text(j.SHA256),
		HashKind: text(j.Hash), Verified: core.VerifiedBy(text(j.Verified)), Method: text(j.Method),
		Publisher: nilIfEmpty(texts(j.Publisher)), Latest: j.Latest, Wanted: j.Wanted, Constraint: text(j.Constraint)}
	if j.Released != nil {
		t, err := parseTime(field+".released", *j.Released)
		if err != nil {
			return s, err
		}
		s.Released = t
	}
	return s, nil
}

func updateFromJSON(j *jsonUpdate) (core.Update, error) {
	u := core.Update{
		Eco:  core.Ecosystem(text(j.Ecosystem)),
		Name: text(j.Name),
		Installed: core.InstalledInfo{Path: text(j.Installed.Path), Lockfile: text(j.Installed.Lockfile), LockLine: j.Installed.LockLine,
			Drift: j.Installed.Drift, DriftFiles: nilIfEmpty(texts(j.Installed.DriftFiles))},
		Verdict: core.Verdict(text(j.Verdict)),
		Diff: core.DiffStats{FilesChanged: j.Diff.FilesChanged, FilesAdded: j.Diff.FilesAdded, FilesRemoved: j.Diff.FilesRemoved,
			LinesAdded: j.Diff.LinesAdded, LinesRemoved: j.Diff.LinesRemoved, BytesFrom: j.Diff.BytesFrom, BytesTo: j.Diff.BytesTo},
		Errors:    errorsFromJSON(j.Errors),
		Sites:     nilIfEmpty(texts(j.Sites)),
		FromCache: j.FromCache,
	}
	var err error
	if u.From, err = sideFromJSON("from", j.From); err != nil {
		return u, err
	}
	if u.To, err = sideFromJSON("to", j.To); err != nil {
		return u, err
	}
	for _, c := range j.Changelog {
		u.Changelog = append(u.Changelog, core.ChangelogEntry{Version: text(c.Version), Text: text(c.Text), Generic: c.Generic})
	}
	for i := range j.Findings {
		f, err := findingFromJSON(&j.Findings[i])
		if err != nil {
			return u, fmt.Errorf("findings[%d]: %w", i, err)
		}
		u.Findings = append(u.Findings, f)
	}
	for _, h := range j.Hunks {
		u.Hunks = append(u.Hunks, core.Hunk{Path: text(h.Path), OldStart: h.OldStart, OldLines: h.OldLines,
			NewStart: h.NewStart, NewLines: h.NewLines, Lines: nilIfEmpty(texts(h.Lines)), Tokens: h.Tokens})
	}
	if sc := j.Soundcheck; sc != nil {
		u.Soundcheck = &core.SoundcheckResult{Staging: text(sc.Staging), RoadieVerify: text(sc.RoadieVerify), Snapshot: text(sc.Snapshot),
			Report: text(sc.Report), Applied: text(sc.Applied), Broke: sc.Summary.Broke, New: sc.Summary.New, Changed: sc.Summary.Changed,
			RolledBack: sc.RolledBack}
	}
	return u, nil
}

func findingFromJSON(j *jsonFinding) (core.Finding, error) {
	sev, err := parseSeverity(j.Severity)
	if err != nil {
		return core.Finding{}, err
	}
	f := core.Finding{
		ID: text(j.ID), Title: text(j.Name), Severity: sev, Confidence: core.Confidence(text(j.Confidence)),
		File: text(j.File), Line: j.Line, EndLine: j.EndLine, Evidence: core.NewSnippet(j.Evidence),
		Domains: nilIfEmpty(texts(j.Domains)), RaisedBy: nilIfEmpty(texts(j.RaisedBy)), Demoted: text(j.Demoted),
		Advice: text(j.Advice), Fingerprint: text(j.Fingerprint), Func: text(j.Func),
		Baselined: j.Baselined, Ignored: j.Ignored, BelowConfidence: j.BelowConfidence,
	}
	if a := j.Allowed; a != nil {
		f.Allowed = &core.AllowMatch{By: text(a.By), Reason: text(a.Reason), Date: text(a.Date), Until: text(a.Until), Source: text(a.Source)}
	}
	return f, nil
}

// parseSeverity reads a finding's severity; "none" is not one.
func parseSeverity(s string) (cli.Severity, error) {
	sev, err := cli.ParseFailOn(s)
	if err != nil || sev == cli.SeverityNone || s != sev.String() {
		return cli.SeverityNone, fmt.Errorf("severity %q: want info, low, medium, high or critical", text(s))
	}
	return sev, nil
}

func errorsFromJSON(es []jsonError) []core.ErrorEntry {
	var out []core.ErrorEntry
	for _, e := range es {
		out = append(out, core.ErrorEntry{Eco: core.Ecosystem(text(e.Ecosystem)), Name: text(e.Name),
			Code: core.ErrorCode(text(e.Code)), Message: text(e.Message)})
	}
	return out
}

// nilIfEmpty keeps an empty list nil, the zero value a Report built in
// code has, so a report read back compares equal to the one written.
func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}
