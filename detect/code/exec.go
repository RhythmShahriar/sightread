// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package code

import (
	"context"
	"fmt"
	"io"
	"math"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
)

// The signals of the execution and obfuscation detector.
const (
	SigRemoteFetchExec = "remote-fetch-exec"
	SigDecodeExec      = "decode-exec"
	SigEvalDynamic     = "eval-dynamic"
	SigObfuscation     = "obfuscation"
)

func init() { core.RegisterDetector(execDetector{}) }

// execDetector finds new code that runs fetched, decoded or built text,
// and new blobs nobody can read (PRD 12.1).
type execDetector struct{}

func (execDetector) Info() core.DetectorInfo {
	return core.DetectorInfo{Name: "code-exec", Signals: []string{SigRemoteFetchExec, SigDecodeExec, SigEvalDynamic, SigObfuscation}}
}

// execSinks are the FFlow sinks (the part after "->") that run code:
// eval and friends, include and require, a code file written to be
// loaded, child processes, Function and vm. A flow into unserialize or a
// dynamic call is not here: those are input-unserialize and
// eval-dynamic.
var execSinks = map[string]bool{
	"eval": true, "assert": true, "create_function": true, "preg-replace-e": true,
	"include": true, "require": true, "write-code": true,
	"exec": true, "child_process": true, "function": true, "vm": true, "timer-string": true,
}

// decodeCalls are the decode steps whose output, run, is decode-exec.
var decodeCalls = []string{
	"base64_decode", "gzinflate", "gzuncompress", "gzdecode", "str_rot13", "hex2bin",
	"strrev", "convert_uudecode", "atob", "fromcharcode", "buffer.from",
}

// sensitiveCallees are names that, reached through a dynamic call, run
// code or a program.
var sensitiveCallees = map[string]bool{
	"eval": true, "assert": true, "create_function": true, "system": true, "exec": true,
	"shell_exec": true, "passthru": true, "popen": true, "proc_open": true, "pcntl_exec": true,
	"call_user_func": true, "call_user_func_array": true, "function": true,
}

// alwaysEval are FEval keys that fire even with a literal argument:
// preg_replace with /e and create_function have no honest new use.
var alwaysEval = map[string]bool{"preg_replace_e": true, "create_function": true}

func (execDetector) Detect(ctx context.Context, s *core.Subject, emit func(core.Finding)) {
	out := newEmitter(s, emit)
	var critical, dynamic []core.Finding
	for _, f := range newFeatures(s) {
		if ctx.Err() != nil {
			return
		}
		switch f.Kind {
		case core.FFlow:
			src, sink, _ := strings.Cut(f.Key, "->")
			switch {
			case src == SrcRemote && execSinks[sink]:
				critical = append(critical, newFinding(SigRemoteFetchExec, f))
			case src == SrcDecode && execSinks[sink]:
				critical = append(critical, newFinding(SigDecodeExec, f))
			case sink == "dyn-call" && (src == SrcRequest || src == SrcRemote):
				dynamic = append(dynamic, newFinding(SigEvalDynamic, f))
			}
		case core.FEval:
			if bundlerHelper(f) {
				continue
			}
			if hasDecode(f.Attrs[AttrArg]) || f.Attrs[AttrSource] == SrcDecode {
				critical = append(critical, newFinding(SigDecodeExec, f))
			} else if alwaysEval[f.Key] || f.Attrs[AttrSource] != SrcLiteral {
				dynamic = append(dynamic, newFinding(SigEvalDynamic, f))
			}
		case core.FDynCall:
			if bundlerHelper(f) {
				continue
			}
			callee := strings.ToLower(f.Attrs[AttrCallee])
			built := f.Attrs[AttrBuilt] == "true" && callee != ""
			switch {
			case sensitiveCallees[callee] && hasDecode(f.Attrs[AttrArg]):
				critical = append(critical, newFinding(SigDecodeExec, f))
			case built, f.Attrs[AttrSource] == SrcRequest, f.Attrs[AttrSource] == SrcRemote, f.Attrs[AttrSource] == SrcDecode:
				dynamic = append(dynamic, newFinding(SigEvalDynamic, f))
			}
		case core.FBlob:
			if fd, ok := blobFinding(s, f); ok {
				out.send(fd)
			}
		}
	}
	for _, f := range critical {
		out.send(f)
	}
	// eval(base64_decode($x)) is one decode-exec, not also an
	// eval-dynamic on the same line.
	for _, f := range dynamic {
		if !slices.ContainsFunc(critical, func(c core.Finding) bool { return covers(c, f) }) {
			out.send(f)
		}
	}
	for _, f := range entropyFindings(ctx, s) {
		out.send(f)
	}
}

// covers reports whether c spans f's line in the same file.
func covers(c, f core.Finding) bool {
	end := max(c.EndLine, c.Line)
	return c.File == f.File && f.Line >= c.Line && f.Line <= end
}

// hasDecode reports whether folded argument text calls a decoder.
func hasDecode(arg string) bool {
	a := strings.ToLower(arg)
	for _, d := range decodeCalls {
		if i := strings.Index(a, d); i >= 0 && strings.Contains(a[i+len(d):], "(") {
			return true
		}
	}
	return false
}

// bundlerHelper spots the webpack and esbuild runtime helpers that
// look like dynamic code: __webpack_require__ calls and
// new Function("return this"). It goes by the feature's callee and
// argument, never by the file, so a payload in a bundle still fires.
func bundlerHelper(f core.Feature) bool {
	switch f.Attrs[AttrCallee] {
	case "__webpack_require__", "__nested_webpack_require__", "__require", "__webpack_modules__":
		return true
	}
	arg := strings.Trim(strings.TrimSpace(f.Attrs[AttrArg]), "\"'`")
	return f.Key == "function" && strings.TrimSuffix(strings.TrimSpace(arg), ";") == "return this"
}

// Blobs that are not code by design.
var blobExempt = map[string]bool{".css": true, ".svg": true, ".woff": true, ".woff2": true, ".ttf": true,
	".eot": true, ".otf": true, ".pot": true, ".po": true, ".mo": true, ".map": true}

// blobFinding turns a new FBlob into an obfuscation finding: over 512
// bytes, over 4.5 bits per char, in code or decoded code; never a data
// URI, font, translation file, source map or minified file.
func blobFinding(s *core.Subject, f core.Feature) (core.Finding, bool) {
	size, _ := strconv.Atoi(f.Attrs[AttrSize])
	entropy, _ := strconv.ParseFloat(f.Attrs[AttrEntropy], 64)
	switch {
	case size <= 512 || entropy <= 4.5:
		return core.Finding{}, false
	case f.Attrs[AttrDecoded] == "none", f.Attrs[AttrEncoding] == "data-uri":
		return core.Finding{}, false
	case blobExempt[strings.ToLower(path.Ext(f.Ev.Path))], minified(s, f.Ev.Path):
		return core.Finding{}, false
	}
	fd := newFinding(SigObfuscation, f)
	enc := f.Attrs[AttrEncoding]
	if enc == "" {
		enc = "encoded"
	}
	fd.Evidence = core.NewSnippet(fmt.Sprintf("%s blob of %d bytes, %.1f bits per char: %s", enc, size, entropy, f.Ev.Snippet))
	return fd, true
}

// minified reports whether p is a minified or bundled file.
func minified(s *core.Subject, p string) bool {
	if s.NewFeatures != nil && slices.Contains(s.NewFeatures.Minified, p) {
		return true
	}
	if s.NewTree != nil {
		if f, ok := s.NewTree.Lookup(p); ok && f.Kind == core.KindMinified {
			return true
		}
	}
	return false
}

// Entropy outlier settings: a new code file fires when its entropy is
// over the 95th percentile of the other code files by entropyMargin
// bits. Fewer than entropyPeers other files give no fair baseline.
const (
	entropyMargin = 0.8
	entropyPeers  = 5
	entropyMin    = 512 // bytes; tiny files have noisy entropy
)

// entropyFindings flags added code files far more random than the rest
// of the package's code.
func entropyFindings(ctx context.Context, s *core.Subject) []core.Finding {
	if s.Diff == nil || s.NewTree == nil || s.NewTree.Blobs == nil {
		return nil
	}
	added := map[string]bool{}
	for _, c := range s.Diff.Changes {
		if c.Kind == core.Added && c.New != nil {
			added[c.New.Path] = true
		}
	}
	if len(added) == 0 {
		return nil
	}
	type scored struct {
		path string
		h    float64
	}
	var peers, cands []scored
	for _, f := range s.NewTree.Files {
		if ctx.Err() != nil {
			return nil
		}
		if f.Kind != core.KindPHP && f.Kind != core.KindJS || f.Size < entropyMin || minified(s, f.Path) {
			continue
		}
		h, ok := fileEntropy(s.NewTree, f)
		if !ok {
			continue
		}
		if added[f.Path] {
			cands = append(cands, scored{f.Path, h})
		} else {
			peers = append(peers, scored{f.Path, h})
		}
	}
	if len(peers) < entropyPeers {
		return nil
	}
	hs := make([]float64, len(peers))
	for i, p := range peers {
		hs[i] = p.h
	}
	slices.Sort(hs)
	p95 := hs[int(math.Ceil(0.95*float64(len(hs))))-1]
	var out []core.Finding
	for _, c := range cands {
		if c.h <= p95+entropyMargin {
			continue
		}
		f := core.Feature{Ev: core.Evidence{Path: c.path, Line: 1, EndLine: 1}}
		fd := newFinding(SigObfuscation, f)
		fd.Evidence = core.NewSnippet(fmt.Sprintf("new file at %.2f bits per byte; the other %d code files reach %.2f (95th percentile)", c.h, len(peers), p95))
		out = append(out, fd)
	}
	return out
}

// fileEntropy is the Shannon entropy in bits per byte of up to the
// analysed size limit of f.
func fileEntropy(t *core.Tree, f core.File) (float64, bool) {
	rc, err := t.Blobs.Open(f.SHA256)
	if err != nil {
		return 0, false
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, core.DefaultLimits().EntryAnalysed))
	if err != nil || len(b) == 0 {
		return 0, false
	}
	return entropy(b), true
}

// entropy is the Shannon entropy of b in bits per byte.
func entropy(b []byte) float64 {
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	n := float64(len(b))
	h := 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}
