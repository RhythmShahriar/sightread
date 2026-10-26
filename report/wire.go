// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package report

import (
	"net/url"
	"time"

	"github.com/RhythmShahriar/sightread/core"
)

// The JSON form of a review (PRD 9.2). core types carry no JSON tags, so
// these structs fix the field names and their order; the order is part
// of the format (golden files, people diffing two reports). Fields are
// only ever added within rhythm-sightread/v1. Every list is written as
// [] when empty, never null, so a reader can range over it without a
// check.

// signalReference is the wiki page every signal has a section on.
const signalReference = "https://github.com/RhythmShahriar/rhythm/wiki/Sightread-Signal-Reference"

// helpURI links a signal ID to its section of the Signal Reference.
func helpURI(id string) string { return signalReference + "#" + url.PathEscape(id) }

type jsonSummary struct {
	Updates         int `json:"updates"`
	Hold            int `json:"hold"`
	Review          int `json:"review"`
	Routine         int `json:"routine"`
	Allowed         int `json:"allowed"`
	Unverified      int `json:"unverified"`
	Critical        int `json:"critical"`
	High            int `json:"high"`
	Medium          int `json:"medium"`
	Low             int `json:"low"`
	Info            int `json:"info"`
	Baselined       int `json:"baselined"`
	AllowedFindings int `json:"allowed_findings"`
	Ignored         int `json:"ignored"`
	Demoted         int `json:"demoted"`
	NotChecked      int `json:"not_checked"`
	FromCache       int `json:"from_cache"`
}

type jsonTarget struct {
	Path      string   `json:"path"`
	Kind      string   `json:"kind"`
	WordPress string   `json:"wordpress"`
	Sites     []string `json:"sites"`
}

// jsonReview is the data of kind review. Updates is a pointer so the
// closing envelope of JSONL can leave it out while a review with no
// updates still writes [].
type jsonReview struct {
	Target        jsonTarget       `json:"target"`
	Started       string           `json:"started"`
	DurationMS    int64            `json:"duration_ms"`
	StoppedBy     string           `json:"stopped_by"`
	SignalPack    string           `json:"signal_pack"`
	NamesPack     string           `json:"names_pack"`
	FailOn        string           `json:"fail_on"`
	MinConfidence string           `json:"min_confidence"`
	Updates       *[]jsonUpdate    `json:"updates,omitempty"`
	NotChecked    []jsonNotChecked `json:"not_checked"`
	Warnings      []string         `json:"warnings"`
	Errors        []jsonError      `json:"errors"`
	Notes         []string         `json:"notes"`
}

type jsonSide struct {
	Version    string   `json:"version"`
	Source     string   `json:"source"`
	URL        string   `json:"url"`
	SHA256     string   `json:"sha256"`
	Hash       string   `json:"hash"`
	Verified   string   `json:"verified"`
	Method     string   `json:"method"`
	Released   *string  `json:"released"` // null when the source gave no date
	Publisher  []string `json:"publisher"`
	Latest     bool     `json:"latest"`
	Wanted     bool     `json:"wanted"`
	Constraint string   `json:"constraint"`
}

type jsonInstalled struct {
	Path       string   `json:"path"`
	Lockfile   string   `json:"lockfile"`
	LockLine   int      `json:"lock_line"`
	Drift      bool     `json:"drift"`
	DriftFiles []string `json:"drift_files"`
}

type jsonDiff struct {
	FilesChanged int   `json:"files_changed"`
	FilesAdded   int   `json:"files_added"`
	FilesRemoved int   `json:"files_removed"`
	LinesAdded   int   `json:"lines_added"`
	LinesRemoved int   `json:"lines_removed"`
	BytesFrom    int64 `json:"bytes_from"`
	BytesTo      int64 `json:"bytes_to"`
}

type jsonChangelog struct {
	Version string `json:"version"`
	Text    string `json:"text"`
	Generic bool   `json:"generic"`
}

type jsonFinding struct {
	ID              string           `json:"id"`
	Name            string           `json:"name"`
	Severity        string           `json:"severity"`
	Confidence      string           `json:"confidence"`
	File            string           `json:"file"`
	Line            int              `json:"line"`
	EndLine         int              `json:"end_line"`
	Evidence        string           `json:"evidence"`
	Domains         []string         `json:"domains"`
	RaisedBy        []string         `json:"raised_by"`
	Demoted         string           `json:"demoted"`
	Advice          string           `json:"advice"`
	HelpURI         string           `json:"help_uri"`
	Fingerprint     string           `json:"fingerprint"`
	Allowed         *core.AllowMatch `json:"allowed"`
	Func            string           `json:"func,omitempty"`
	Baselined       bool             `json:"baselined"`
	Ignored         bool             `json:"ignored"`
	BelowConfidence bool             `json:"below_confidence"`
}

type jsonHunk struct {
	Path     string   `json:"path"`
	OldStart int      `json:"old_start"`
	OldLines int      `json:"old_lines"`
	NewStart int      `json:"new_start"`
	NewLines int      `json:"new_lines"`
	Lines    []string `json:"lines"`
}

type jsonSoundcheckSummary struct {
	Broke   int `json:"broke"`
	New     int `json:"new"`
	Changed int `json:"changed"`
}

type jsonSoundcheck struct {
	Staging      string                `json:"staging"`
	RoadieVerify string                `json:"roadie_verify"`
	Snapshot     string                `json:"snapshot"`
	Applied      string                `json:"applied"`
	Summary      jsonSoundcheckSummary `json:"summary"`
	Report       string                `json:"report"`
	RolledBack   bool                  `json:"rolled_back"`
}

type jsonError struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Code      string `json:"code"`
	Message   string `json:"message"`
}

type jsonNotChecked struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Reason    string `json:"reason"`
	Text      string `json:"text"`
	Hint      string `json:"hint"`
}

type jsonUpdate struct {
	Ecosystem  string          `json:"ecosystem"`
	Name       string          `json:"name"`
	From       jsonSide        `json:"from"`
	To         jsonSide        `json:"to"`
	Installed  jsonInstalled   `json:"installed"`
	Verdict    string          `json:"verdict"`
	Diff       jsonDiff        `json:"diff"`
	Changelog  []jsonChangelog `json:"changelog"`
	Findings   []jsonFinding   `json:"findings"`
	Hunks      []jsonHunk      `json:"hunks"`
	Soundcheck *jsonSoundcheck `json:"soundcheck"`
	Errors     []jsonError     `json:"errors"`
	Sites      []string        `json:"sites"`
	FromCache  bool            `json:"from_cache"`
}

// jsonUpdateLine is one JSONL line: the update with "kind" first.
type jsonUpdateLine struct {
	Kind string `json:"kind"`
	jsonUpdate
}

// The JSON forms of the other kinds' data blocks whose core types have
// no tags.

type jsonSignal struct {
	ID          string   `json:"id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Confidence  string   `json:"confidence"`
	Ecosystems  []string `json:"ecosystems"`
	Emitter     string   `json:"emitter"`
	Unignorable bool     `json:"unignorable"`
	HelpURI     string   `json:"help_uri"`
}

type jsonExplain struct {
	Why         string `json:"why"`
	HowToReview string `json:"how_to_review"`
	FalseAlarms string `json:"false_alarms"`
	Incidents   string `json:"incidents"`
	Advice      string `json:"advice"`
	More        string `json:"more"`
}

type jsonSignalsData struct {
	Signals []jsonSignal `json:"signals"`
}

type jsonExplainData struct {
	Signal  jsonSignal   `json:"signal"`
	Explain jsonExplain  `json:"explain"`
	Finding *jsonFinding `json:"finding,omitempty"`
	Hunks   []jsonHunk   `json:"hunks,omitempty"`
}

// timeText writes t as RFC 3339 in UTC, "" for the zero time.
func timeText(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// list returns s, or an empty non-nil slice, so JSON gets [] not null.
func list[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}
