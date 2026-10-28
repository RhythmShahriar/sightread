// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import "io"

// WriteOptions shape every output format.
type WriteOptions struct {
	Width       int
	Plain       bool
	Color       bool
	Quiet       bool
	MaxFindings int // per update on the terminal
	ShowDiff    bool
	Program     string // cli.Name(): "rhythm sightread" through the router
	Version     string
	RedactPaths bool
	Soundcheck  bool
	Signed      string // sha256 of the signed JSON, for footers with --sign
	// RerunFlags are the flags that chose what the run read and compared
	// (--path, --from, --to-file, ...), as arguments: the terminal's
	// "the full diff" command repeats them so it reviews the same thing.
	RerunFlags []string
	// HTMLReport is the first -o .html file this run writes, as given:
	// the terminal's "the full diff" step points at it instead of asking
	// for a rerun.
	HTMLReport string
	// Demo marks the built-in demo's report: its packages are made up,
	// so no next step or allow line names them for a real registry; the
	// rerun step reruns the demo.
	Demo bool
}

// Output formats of Writer.Format.
const (
	FormatTerminal = "terminal"
	FormatJSON     = "json"
	FormatJSONL    = "jsonl"
	FormatSARIF    = "sarif"
	FormatMarkdown = "md"
	FormatHTML     = "html"
)

// Writer renders a report in one format (package report).
type Writer interface {
	Format() string
	Write(w io.Writer, r *Report, o WriteOptions) error
}

// StreamWriter is implemented by the jsonl writer: WriteUpdate writes one
// line per update as it finishes, then Write adds the closing envelope.
type StreamWriter interface {
	WriteUpdate(w io.Writer, u *Update, o WriteOptions) error
}

// ExplainRenderer renders `explain` (package report).
type ExplainRenderer interface {
	RenderSignal(w io.Writer, id string, o WriteOptions, asJSON bool) error
	// RenderFinding shows one finding of a saved report; sel is its
	// 1-based index or its fingerprint.
	RenderFinding(w io.Writer, r *Report, sel string, hunks []Hunk, o WriteOptions, asJSON bool) error
}

// Signer signs and verifies report JSON with Ed25519 (report/sign.go).
type Signer interface {
	Sign(jsonPath, keyPath string) (sigPath string, err error)
	Verify(jsonBytes, sigBytes []byte, trusted [][]byte) (keyID string, err error)
}

// ReportReader parses a rhythm-sightread/v1 kind review document back
// into a Report.
type ReportReader func(r io.Reader) (*Report, error)
