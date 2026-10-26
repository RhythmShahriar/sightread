// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package report

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/RhythmShahriar/sightread/core"
)

func init() {
	core.RegisterWriter(JSONWriter{})
	core.RegisterWriter(JSONLWriter{})
}

// tool is the envelope's tool name.
const tool = "rhythm-sightread"

// DocumentWriter writes any kind of rhythm-sightread/v1 document. The
// json writer implements it, so cmd can write the allowed, watch,
// signals, explain, doctor and verify kinds without importing this
// package:
//
//	core.WriterFor(core.FormatJSON).(report.DocumentWriter)
//
// asserted through an interface of the same method set.
type DocumentWriter interface {
	WriteDocument(w io.Writer, env core.Envelope, o core.WriteOptions) error
}

// JSONWriter writes kind review as one indented JSON document (PRD 9.2).
type JSONWriter struct{}

var (
	_ core.Writer    = JSONWriter{}
	_ DocumentWriter = JSONWriter{}
)

// Format returns "json".
func (JSONWriter) Format() string { return core.FormatJSON }

// Write writes r as a kind review envelope.
func (JSONWriter) Write(w io.Writer, r *core.Report, o core.WriteOptions) error {
	return encode(w, reviewEnvelope(r, o, true), true)
}

// WriteDocument writes env with schema, tool and version filled in. Its
// Data is a *core.Report (kind review) or one of the core kinds.go data
// structs; Summary is a core.Summary, or nil for zero counts.
func (JSONWriter) WriteDocument(w io.Writer, env core.Envelope, o core.WriteOptions) error {
	if env.Kind == "" {
		return fmt.Errorf("report: a document needs a kind")
	}
	if r, ok := env.Data.(*core.Report); ok {
		e := reviewEnvelope(r, o, true)
		e.Kind = env.Kind
		return encode(w, e, true)
	}
	data, err := documentData(env.Data, o)
	if err != nil {
		return err
	}
	env.Schema, env.Tool, env.Version = core.Schema, tool, toolVersion(o.Version)
	env.Data = data
	switch s := env.Summary.(type) {
	case nil:
		env.Summary = jsonSummary{}
	case core.Summary:
		env.Summary = summaryJSON(s)
	case *core.Summary:
		env.Summary = summaryJSON(*s)
	}
	if env.Verdict == "" {
		env.Verdict = core.VerdictOK
	}
	return encode(w, env, true)
}

// JSONLWriter writes one line per update as it finishes, then the
// closing envelope without data.updates (PRD 9.2).
type JSONLWriter struct{}

var (
	_ core.Writer       = JSONLWriter{}
	_ core.StreamWriter = JSONLWriter{}
)

// Format returns "jsonl".
func (JSONLWriter) Format() string { return core.FormatJSONL }

// WriteUpdate writes one {"kind":"update", ...} line. It doesn't know
// the target, so with RedactPaths a path inside it stays absolute (only
// the home folder becomes ~); WriteUpdateIn redacts as the json format
// does.
func (j JSONLWriter) WriteUpdate(w io.Writer, u *core.Update, o core.WriteOptions) error {
	return j.WriteUpdateIn(w, u, "", o)
}

// WriteUpdateIn is WriteUpdate for an update of the report on target
// (Report.Target.Path): with RedactPaths a path inside target becomes
// relative to it, as in the json format.
func (JSONLWriter) WriteUpdateIn(w io.Writer, u *core.Update, target string, o core.WriteOptions) error {
	p := newPaths(target, o.RedactPaths)
	return encode(w, jsonUpdateLine{Kind: "update", jsonUpdate: updateJSON(u, p)}, false)
}

// Write writes only the closing envelope: the updates went out line by
// line through WriteUpdate.
func (JSONLWriter) Write(w io.Writer, r *core.Report, o core.WriteOptions) error {
	return encode(w, reviewEnvelope(r, o, false), false)
}

// encode writes v as JSON with HTML characters left as they are. The
// output is data that is never put into a page as is, so "<" can stay
// readable instead of turning into a \u003c escape.
func encode(w io.Writer, v any, indent bool) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if indent {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(v)
}

// envelopeVerdict is "findings" when any finding counts, "error" when
// the run failed (an error was recorded or it was stopped) and "ok"
// otherwise. A run that is only incomplete (a package not checked, an
// unverified update) stays "ok" with complete false, as in Echo.
func envelopeVerdict(r *core.Report) string {
	failed := len(r.Errors) > 0 || r.StoppedBy != ""
	for i := range r.Updates {
		u := &r.Updates[i]
		for j := range u.Findings {
			if u.Findings[j].Counted() {
				return core.VerdictFindings
			}
		}
		if len(u.Errors) > 0 {
			failed = true
		}
	}
	if failed {
		return core.VerdictError
	}
	return core.VerdictOK
}

// reviewEnvelope builds the kind review envelope of r. withUpdates false
// leaves data.updates out (the JSONL closing envelope).
func reviewEnvelope(r *core.Report, o core.WriteOptions, withUpdates bool) core.Envelope {
	p := newPaths(r.Target.Path, o.RedactPaths)
	data := reviewJSON(r, p)
	if withUpdates {
		ups := make([]jsonUpdate, 0, len(r.Updates))
		for i := range r.Updates {
			ups = append(ups, updateJSON(&r.Updates[i], p))
		}
		data.Updates = &ups
	}
	return core.Envelope{
		Schema:   core.Schema,
		Kind:     core.KindReview,
		Tool:     tool,
		Version:  toolVersion(o.Version),
		Complete: r.Complete,
		Summary:  summaryJSON(r.Summary),
		Verdict:  envelopeVerdict(r),
		Data:     data,
	}
}

func summaryJSON(s core.Summary) jsonSummary {
	return jsonSummary{
		Updates: s.Updates, Hold: s.Hold, Review: s.Review, Routine: s.Routine, Allowed: s.Allowed, Unverified: s.Unverified,
		Critical: s.Critical, High: s.High, Medium: s.Medium, Low: s.Low, Info: s.Info,
		Baselined: s.Baselined, AllowedFindings: s.AllowedFindings, Ignored: s.Ignored, Demoted: s.Demoted,
		NotChecked: s.NotChecked, FromCache: s.FromCache, Hidden: s.Hidden,
	}
}

func reviewJSON(r *core.Report, p paths) jsonReview {
	d := jsonReview{
		Target: jsonTarget{Path: text(p.path(r.Target.Path)), RepoPath: text(TargetRepoPath(r.Target)), Kind: text(r.Target.Kind), WordPress: text(r.Target.WordPress),
			Sites: list(texts(r.Target.Sites))},
		Started:       timeText(r.Started),
		DurationMS:    r.Duration.Milliseconds(),
		StoppedBy:     text(r.StoppedBy),
		SignalPack:    text(r.SignalPack),
		NamesPack:     text(r.NamesPack),
		FailOn:        text(r.FailOn),
		MinConfidence: text(r.MinConfidence),
		NotChecked:    []jsonNotChecked{},
		Warnings:      []string{},
		Errors:        errorsJSON(r.Errors, p),
		Notes:         []string{},
	}
	for _, n := range r.NotChecked {
		d.NotChecked = append(d.NotChecked, jsonNotChecked{Ecosystem: text(string(n.Eco)), Name: text(n.Name),
			Version: text(n.Version), Reason: text(string(n.Reason)), Text: text(p.text(n.Text)), Hint: text(p.text(n.Hint))})
	}
	for _, s := range r.Warnings {
		d.Warnings = append(d.Warnings, text(p.text(s)))
	}
	for _, s := range r.Notes {
		d.Notes = append(d.Notes, text(p.text(s)))
	}
	return d
}

func errorsJSON(es []core.ErrorEntry, p paths) []jsonError {
	out := make([]jsonError, 0, len(es))
	for _, e := range es {
		out = append(out, jsonError{Ecosystem: text(string(e.Eco)), Name: text(e.Name), Code: text(string(e.Code)),
			Message: text(p.text(e.Message))})
	}
	return out
}

func sideJSON(s core.Side) jsonSide {
	j := jsonSide{
		Version: text(s.Version), Source: text(s.Source), URL: text(s.URL), SHA256: text(s.SHA256), Hash: text(s.HashKind),
		Verified: text(string(s.Verified)), Method: text(s.Method), Publisher: list(texts(s.Publisher)),
		Latest: s.Latest, Wanted: s.Wanted, Constraint: text(s.Constraint),
	}
	if !s.Released.IsZero() {
		t := timeText(s.Released)
		j.Released = &t
	}
	return j
}

func updateJSON(u *core.Update, p paths) jsonUpdate {
	j := jsonUpdate{
		Ecosystem: text(string(u.Eco)),
		Name:      text(u.Name),
		From:      sideJSON(u.From),
		To:        sideJSON(u.To),
		Installed: jsonInstalled{Path: text(p.path(u.Installed.Path)), Lockfile: text(p.path(u.Installed.Lockfile)),
			LockLine: u.Installed.LockLine, Drift: u.Installed.Drift, DriftFiles: list(texts(u.Installed.DriftFiles))},
		Verdict: text(string(u.Verdict)),
		Diff: jsonDiff{FilesChanged: u.Diff.FilesChanged, FilesAdded: u.Diff.FilesAdded, FilesRemoved: u.Diff.FilesRemoved,
			LinesAdded: u.Diff.LinesAdded, LinesRemoved: u.Diff.LinesRemoved, BytesFrom: u.Diff.BytesFrom, BytesTo: u.Diff.BytesTo},
		Changelog: []jsonChangelog{},
		Findings:  make([]jsonFinding, 0, len(u.Findings)),
		Hunks:     hunksJSON(u.Hunks),
		Errors:    errorsJSON(u.Errors, p),
		Sites:     list(texts(u.Sites)),
		FromCache: u.FromCache,
		Hidden:    len(u.Hidden),
	}
	for _, c := range u.Changelog {
		j.Changelog = append(j.Changelog, jsonChangelog{Version: text(c.Version), Text: text(c.Text), Generic: c.Generic})
	}
	for i := range u.Findings {
		j.Findings = append(j.Findings, findingJSON(&u.Findings[i]))
	}
	if sc := u.Soundcheck; sc != nil {
		j.Soundcheck = &jsonSoundcheck{Staging: text(sc.Staging), RoadieVerify: text(sc.RoadieVerify), Snapshot: text(sc.Snapshot),
			Applied: text(sc.Applied), Summary: jsonSoundcheckSummary{Broke: sc.Broke, New: sc.New, Changed: sc.Changed},
			Report: text(p.path(sc.Report)), RolledBack: sc.RolledBack}
	}
	return j
}

func findingJSON(f *core.Finding) jsonFinding {
	j := jsonFinding{
		ID: text(f.ID), Name: text(f.Title), Severity: f.Severity.String(), Confidence: text(string(f.Confidence)),
		File: text(f.File), Line: f.Line, EndLine: f.EndLine, Evidence: text(f.Evidence.String()),
		Domains: list(texts(f.Domains)), RaisedBy: list(texts(f.RaisedBy)), Demoted: text(f.Demoted),
		Advice: text(f.Advice), HelpURI: helpURI(text(f.ID)), Fingerprint: text(f.Fingerprint), Func: text(f.Func),
		Baselined: f.Baselined, Ignored: f.Ignored, BelowConfidence: f.BelowConfidence,
	}
	if a := f.Allowed; a != nil {
		j.Allowed = &core.AllowMatch{By: text(a.By), Reason: text(a.Reason), Date: text(a.Date), Until: text(a.Until), Source: text(a.Source)}
	}
	return j
}

func hunksJSON(hs []core.Hunk) []jsonHunk {
	out := make([]jsonHunk, 0, len(hs))
	for _, h := range hs {
		out = append(out, jsonHunk{Path: text(h.Path), OldStart: h.OldStart, OldLines: h.OldLines, NewStart: h.NewStart,
			NewLines: h.NewLines, Lines: list(texts(h.Lines)), Tokens: h.Tokens})
	}
	return out
}

func signalJSON(s core.SignalInfo) jsonSignal {
	ecos := make([]string, 0, len(s.Ecosystems))
	for _, e := range s.Ecosystems {
		ecos = append(ecos, string(e))
	}
	return jsonSignal{ID: text(s.ID), Title: text(s.Title), Severity: s.Severity.String(), Confidence: string(s.Confidence),
		Ecosystems: ecos, Emitter: s.Emitter, Unignorable: s.Unignorable, HelpURI: helpURI(text(s.ID))}
}

func explainJSON(e core.Explain) jsonExplain {
	return jsonExplain{Why: text(e.Why), HowToReview: text(e.HowToReview), FalseAlarms: text(e.FalseAlarms),
		Incidents: text(e.Incidents), Advice: text(e.Advice), More: text(e.More)}
}

// documentData converts the data block of a non-review kind to its JSON
// form. Kinds whose core types carry tags are copied with their text
// cleaned and nil lists made empty.
func documentData(data any, o core.WriteOptions) (any, error) {
	p := newPaths("", o.RedactPaths)
	switch d := data.(type) {
	case core.AllowedData:
		return allowedJSON(d, p), nil
	case *core.AllowedData:
		return allowedJSON(*d, p), nil
	case core.SignalsData:
		return signalsJSON(d), nil
	case *core.SignalsData:
		return signalsJSON(*d), nil
	case core.ExplainData:
		return explainDataJSON(d), nil
	case *core.ExplainData:
		return explainDataJSON(*d), nil
	case core.DoctorData:
		return doctorJSON(d, p), nil
	case *core.DoctorData:
		return doctorJSON(*d, p), nil
	case core.VerifyData:
		return verifyJSON(d, p), nil
	case *core.VerifyData:
		return verifyJSON(*d, p), nil
	case core.WatchData:
		return watchJSON(d, p), nil
	case *core.WatchData:
		return watchJSON(*d, p), nil
	}
	return nil, fmt.Errorf("report: no JSON form for %T", data)
}

func allowedJSON(d core.AllowedData, p paths) core.AllowedData {
	out := core.AllowedData{File: text(p.path(d.File)), Entries: make([]core.AllowEntry, 0, len(d.Entries))}
	for _, e := range d.Entries {
		out.Entries = append(out.Entries, core.AllowEntry{Package: text(e.Package), Version: text(e.Version), SHA256: text(e.SHA256),
			Hash: text(e.Hash), Signals: texts(e.Signals), Reason: text(e.Reason), By: text(e.By), Date: text(e.Date),
			Until: text(e.Until), ImportedFrom: text(p.path(e.ImportedFrom))})
	}
	return out
}

func signalsJSON(d core.SignalsData) jsonSignalsData {
	out := jsonSignalsData{Signals: make([]jsonSignal, 0, len(d.Signals))}
	for _, s := range d.Signals {
		out.Signals = append(out.Signals, signalJSON(s))
	}
	return out
}

func explainDataJSON(d core.ExplainData) jsonExplainData {
	out := jsonExplainData{Signal: signalJSON(d.Signal), Explain: explainJSON(d.Explain)}
	if d.Finding != nil {
		f := findingJSON(d.Finding)
		out.Finding = &f
	}
	if len(d.Hunks) > 0 {
		out.Hunks = hunksJSON(d.Hunks)
	}
	return out
}

func doctorJSON(d core.DoctorData, p paths) core.DoctorData {
	out := core.DoctorData{Checks: make([]core.DoctorCheck, 0, len(d.Checks))}
	for _, c := range d.Checks {
		out.Checks = append(out.Checks, core.DoctorCheck{Name: text(c.Name), Status: text(c.Status), Detail: text(p.text(c.Detail))})
	}
	return out
}

func verifyJSON(d core.VerifyData, p paths) core.VerifyData {
	return core.VerifyData{File: text(p.path(d.File)), Key: text(d.Key), Trusted: d.Trusted, Valid: d.Valid}
}

func watchJSON(d core.WatchData, p paths) core.WatchData {
	return core.WatchData{Name: text(d.Name), Sites: d.Sites, Updates: d.Updates, Review: d.Review, Hold: d.Hold,
		Report: text(p.path(d.Report)), Notified: list(texts(d.Notified))}
}
