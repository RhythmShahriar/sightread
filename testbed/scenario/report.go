// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package scenario

import (
	"encoding/json"
	"fmt"
	"io"
)

// Report is the part of a rhythm-sightread/v1 review document the
// evaluation reads (PRD 9.2). Fields it does not need are ignored.
type Report struct {
	Schema  string        `json:"schema"`
	Kind    string        `json:"kind"`
	Verdict string        `json:"verdict"`
	Summary ReportSummary `json:"summary"`
	Data    ReportData    `json:"data"`
}

// ReportSummary is the counts block.
type ReportSummary struct {
	Hold       int `json:"hold"`
	Review     int `json:"review"`
	Routine    int `json:"routine"`
	Allowed    int `json:"allowed"`
	Unverified int `json:"unverified"`
	NotChecked int `json:"not_checked"`
}

// ReportData holds the updates and the not-checked list.
type ReportData struct {
	Updates    []ReportUpdate     `json:"updates"`
	NotChecked []ReportNotChecked `json:"not_checked"`
}

// ReportUpdate is one reviewed update.
type ReportUpdate struct {
	Ecosystem string          `json:"ecosystem"`
	Name      string          `json:"name"`
	Verdict   string          `json:"verdict"`
	Findings  []ReportFinding `json:"findings"`
}

// ReportFinding is one finding of an update.
type ReportFinding struct {
	ID        string          `json:"id"`
	Severity  string          `json:"severity"`
	Allowed   json.RawMessage `json:"allowed"`
	Baselined bool            `json:"baselined"`
	Ignored   bool            `json:"ignored"`
}

// ReportNotChecked is one Not checked entry.
type ReportNotChecked struct {
	Reason string `json:"reason"`
}

// Counted reports whether a finding counts for the verdict and the gate:
// not covered by an allow entry, not baselined and not ignored.
func (f ReportFinding) Counted() bool {
	allowed := len(f.Allowed) != 0 && string(f.Allowed) != "null"
	return !allowed && !f.Baselined && !f.Ignored
}

// ReadReport parses a rhythm-sightread/v1 review document.
func ReadReport(r io.Reader) (*Report, error) {
	var rep Report
	if err := json.NewDecoder(r).Decode(&rep); err != nil {
		return nil, err
	}
	if rep.Schema != "rhythm-sightread/v1" {
		return nil, fmt.Errorf("not a rhythm-sightread/v1 document: schema %q", rep.Schema)
	}
	return &rep, nil
}

// OverallVerdict is the worst verdict across the report's updates,
// derived from the summary counts.
func (r *Report) OverallVerdict() string {
	switch {
	case r.Summary.Hold > 0:
		return "HOLD"
	case r.Summary.Review > 0:
		return "REVIEW"
	case r.Summary.Unverified > 0 && r.Summary.Hold == 0 && r.Summary.Review == 0:
		return "UNVERIFIED"
	case r.Summary.Allowed > 0 && r.Summary.Routine == 0:
		return "ALLOWED"
	default:
		return "ROUTINE"
	}
}

// CountedFindings returns every counted finding across the updates.
func (r *Report) CountedFindings() []ReportFinding {
	var out []ReportFinding
	for _, u := range r.Data.Updates {
		for _, f := range u.Findings {
			if f.Counted() {
				out = append(out, f)
			}
		}
	}
	return out
}
