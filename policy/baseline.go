// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package policy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

// maxBaselineBytes caps a baseline report. A report with every hunk of a
// large site is tens of megabytes.
const maxBaselineBytes = 512 << 20

// baselineDoc is the part of a kind review report a baseline needs.
// Unknown fields are allowed: v1 only ever adds fields.
type baselineDoc struct {
	Schema string `json:"schema"`
	Kind   string `json:"kind"`
	Data   struct {
		Updates []struct {
			Ecosystem core.Ecosystem `json:"ecosystem"`
			Name      string         `json:"name"`
			To        struct {
				Version string `json:"version"`
			} `json:"to"`
			Findings []struct {
				ID          string       `json:"id"`
				File        string       `json:"file"`
				Evidence    core.Snippet `json:"evidence"`
				Fingerprint string       `json:"fingerprint"`
			} `json:"findings"`
		} `json:"updates"`
	} `json:"data"`
}

// LoadBaseline reads a saved kind review report and returns the
// fingerprints of its findings (see core.Policy). A finding saved
// without a fingerprint gets the one core.Fingerprint gives it. A file
// that is not a rhythm-sightread/v1 review report is an E12.
func (s *Store) LoadBaseline(path string) (map[string]bool, error) {
	f, err := os.Open(path) //nolint:gosec // the report the user named
	if err != nil {
		return nil, badFile(path, err)
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err == nil && fi.IsDir() {
		return nil, badFile(path, errors.New("is a folder, not a file"))
	}
	var doc baselineDoc
	dec := json.NewDecoder(io.LimitReader(f, maxBaselineBytes))
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.EOF) {
			err = errors.New("the file ends early")
		}
		return nil, notAReport(path, fmt.Sprintf("is not valid JSON (%v)", err))
	}
	if doc.Schema != core.Schema {
		return nil, notAReport(path, "is not a rhythm-sightread report")
	}
	if doc.Kind != core.KindReview {
		return nil, notAReport(path, fmt.Sprintf("is a rhythm-sightread %s document, not a review report", show(doc.Kind)))
	}
	set := map[string]bool{}
	for _, u := range doc.Data.Updates {
		for _, fd := range u.Findings {
			fp := fd.Fingerprint
			if fp == "" {
				fp = core.Fingerprint(u.Ecosystem, u.Name, u.To.Version, fd.ID, fd.File, fd.Evidence)
			}
			set[fp] = true
		}
	}
	return set, nil
}

func notAReport(path, what string) *core.Error {
	return &core.Error{Code: core.EBadConfig, Exit: cli.ExitUsage, What: display(path) + " " + what,
		Hint: []string{"--baseline takes the JSON a review wrote, such as -o sightread.json"}}
}
