// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package policy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

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
	return parseBaseline(io.LimitReader(f, maxBaselineBytes), path)
}

// parseBaseline decodes a baseline report read from r. path names the
// file in errors.
func parseBaseline(r io.Reader, path string) (map[string]bool, error) {
	var doc baselineDoc
	dec := json.NewDecoder(r)
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

// BaselineAtBase applies the pull request rule to a --baseline report
// that lives in the project's git repository: a change could otherwise
// swap in a report that holds its own findings. Only the fingerprints
// the report also has at baseRef stay in set; the others are removed and
// counted in the returned number. A report the ref can't show or parse
// keeps none. With baseRef empty, or a report outside the repository (a
// saved artifact of an earlier run, say), set is returned unchanged.
func (s *Store) BaselineAtBase(set map[string]bool, path, baseRef string) (map[string]bool, int, error) {
	if baseRef == "" || len(set) == 0 {
		return set, 0, nil
	}
	gitShow := core.GetGitShow()
	if gitShow == nil {
		return nil, 0, fmt.Errorf("reading the baseline at %s: git show %w", baseRef, core.ErrNotLinked)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return set, 0, nil
	}
	repo := gitRoot(filepath.Dir(abs))
	if repo == "" {
		return set, 0, nil
	}
	rel, ok := inside(repo, abs)
	if !ok {
		return set, 0, nil
	}
	var base map[string]bool
	if data, err := gitShow(context.Background(), repo, baseRef, rel); err == nil {
		base, _ = parseBaseline(io.LimitReader(bytes.NewReader(data), maxBaselineBytes), rel)
	}
	kept := make(map[string]bool, len(set))
	for fp := range set {
		if base[fp] {
			kept[fp] = true
		}
	}
	return kept, len(set) - len(kept), nil
}

func notAReport(path, what string) *core.Error {
	return &core.Error{Code: core.EBadConfig, Exit: cli.ExitUsage, What: display(path) + " " + what,
		Hint: []string{"--baseline takes the JSON a review wrote, such as -o sightread.json"}}
}
