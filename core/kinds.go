// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

// Envelope is every Sightread JSON document (PRD 9.2), in Echo's field
// order. Data holds the kind's data block.
type Envelope struct {
	Schema   string `json:"schema"`
	Kind     string `json:"kind"`
	Tool     string `json:"tool"`
	Version  string `json:"version"`
	Complete bool   `json:"complete"`
	Summary  any    `json:"summary"`
	Verdict  string `json:"verdict"` // "ok", "findings" or "error"
	Data     any    `json:"data"`
}

// Document kinds besides KindReview.
const (
	KindAllowed = "allowed"
	KindWatch   = "watch"
	KindSignals = "signals"
	KindExplain = "explain"
	KindDoctor  = "doctor"
	KindVerify  = "verify"
)

// Envelope verdicts.
const (
	VerdictOK       = "ok"
	VerdictFindings = "findings"
	VerdictError    = "error"
)

// AllowedData is the data of kind allowed (allow list --json).
type AllowedData struct {
	File    string       `json:"file"`
	Entries []AllowEntry `json:"entries"`
}

// SignalsData is the data of kind signals.
type SignalsData struct {
	Signals []SignalInfo `json:"signals"`
}

// ExplainData is the data of kind explain. Finding and Hunks are set for
// `explain <report.json> <n|fingerprint>`.
type ExplainData struct {
	Signal  SignalInfo `json:"signal"`
	Explain Explain    `json:"explain"`
	Finding *Finding   `json:"finding,omitempty"`
	Hunks   []Hunk     `json:"hunks,omitempty"`
}

// Doctor check statuses.
const (
	DoctorOK      = "ok"
	DoctorWarn    = "warn"
	DoctorFail    = "fail"
	DoctorSkipped = "skipped"
)

// DoctorCheck is one line of `doctor`.
type DoctorCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // one of the Doctor* constants
	Detail string `json:"detail"`
}

// DoctorData is the data of kind doctor.
type DoctorData struct {
	Checks []DoctorCheck `json:"checks"`
}

// VerifyData is the data of kind verify (verify-report --json).
type VerifyData struct {
	File    string `json:"file"`
	Key     string `json:"key"`
	Trusted bool   `json:"trusted"`
	Valid   bool   `json:"valid"`
}

// WatchData is the data of kind watch, one per scheduled run.
type WatchData struct {
	Name     string   `json:"name"`
	Sites    int      `json:"sites"`
	Updates  int      `json:"updates"`
	Review   int      `json:"review"`
	Hold     int      `json:"hold"`
	Report   string   `json:"report"`
	Notified []string `json:"notified"`
}
