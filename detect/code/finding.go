// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package code

import (
	"slices"
	"strconv"

	"github.com/RhythmShahriar/sightread/core"
)

// Feature attributes the code detectors read. The analyzer sets them
// (analyze lane); fixtures set them by hand.
const (
	// AttrSource is where a value comes from: SrcLiteral, SrcRequest,
	// SrcRemote, SrcDecode, SrcEnv or SrcVariable.
	AttrSource = "source"
	// AttrArg is the folded text of a call's first argument, e.g.
	// "base64_decode($x)" for eval(base64_decode($x)).
	AttrArg = "arg"
	// AttrCallee is the folded name of a dynamic call's callee.
	AttrCallee = "callee"
	// AttrBuilt is "true" when AttrCallee was built at run time (joined,
	// reversed, decoded), not written as one literal.
	AttrBuilt = "built"
	// AttrEncoding, AttrSize, AttrEntropy and AttrDecoded describe an
	// FBlob: "base64", "hex", "data-uri"...; bytes; bits per char;
	// "code", "data" or "none".
	AttrEncoding = "encoding"
	AttrSize     = "size"
	AttrEntropy  = "entropy"
	AttrDecoded  = "decoded"
)

// Values of AttrSource.
const (
	SrcLiteral  = "literal"
	SrcRequest  = "request"
	SrcRemote   = "remote"
	SrcDecode   = "decode"
	SrcEnv      = "env"
	SrcVariable = "variable"
)

// fires reports whether a feature's context can raise a signal. Code
// and decoded payloads fire; vendored code fires too and the scorer
// demotes it. Comments, docs and tests never fire.
func fires(f core.Feature) bool {
	switch f.Context {
	case core.CtxCode, core.CtxDecoded, core.CtxVendored:
		return true
	}
	return false
}

// newFinding fills a finding of signal id from the catalogue (title,
// severity, confidence) and the explain text (advice), placed at f.
func newFinding(id string, f core.Feature) core.Finding {
	info, _ := core.Signal(id)
	ex, _ := core.ExplainFor(id)
	return core.Finding{
		ID: id, Title: info.Title, Severity: info.Severity, Confidence: info.Confidence,
		File: f.Ev.Path, Line: f.Ev.Line, EndLine: f.Ev.EndLine, Func: f.Ev.Func,
		Evidence: f.Ev.Snippet, Advice: ex.Advice,
	}
}

// forEco reports whether signal id applies to the update's ecosystem.
func forEco(id string, s *core.Subject) bool {
	info, ok := core.Signal(id)
	return ok && (s.Update.Eco == "" || slices.Contains(info.Ecosystems, s.Update.Eco))
}

// emitter sends findings on, skipping signals that don't apply to the
// ecosystem and a second finding of one signal at one place.
type emitter struct {
	s    *core.Subject
	emit func(core.Finding)
	seen map[string]bool
}

func newEmitter(s *core.Subject, emit func(core.Finding)) *emitter {
	return &emitter{s: s, emit: emit, seen: map[string]bool{}}
}

func (e *emitter) send(f core.Finding) {
	if !forEco(f.ID, e.s) {
		return
	}
	k := f.ID + "\x00" + f.File + "\x00" + strconv.Itoa(f.Line)
	if e.seen[k] {
		return
	}
	e.seen[k] = true
	e.emit(f)
}

// newFeatures returns the features of the candidate absent from the
// installed version that may fire.
func newFeatures(s *core.Subject) []core.Feature {
	var out []core.Feature
	for _, f := range s.NewFeatures.NewIn(s.OldFeatures) {
		if fires(f) {
			out = append(out, f)
		}
	}
	return out
}

// FeatureDetectors returns the detectors that work on features alone:
// execution, WordPress behaviour and network. detect/meta runs them on
// the code an install script runs; it also tells how serious the
// capabilities a changelog leaves out are. The rule detector is left
// out: it reads tree files, not features, so it would only repeat the
// main pass.
func FeatureDetectors() []core.Detector {
	return []core.Detector{execDetector{}, wpDetector{}, netDetector{}}
}
