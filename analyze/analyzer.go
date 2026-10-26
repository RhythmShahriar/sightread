// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"io/fs"
	"path"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/RhythmShahriar/rhythm/kit/secrets"

	"github.com/RhythmShahriar/sightread/core"
)

// Analyzer is the core.Analyzer: it reads the files of a tree, lexes
// PHP and JavaScript and returns their features. It never runs package
// code and never reaches the network. The zero value is ready to use.
type Analyzer struct{}

func init() { core.SetAnalyzer(Analyzer{}) }

// tailMax is how much of the end of an oversized asset is kept to look
// for code appended after the image data.
const tailMax = 1 << 20

// fileResult is what one file gave.
type fileResult struct {
	feats    []core.Feature
	un       []core.Unanalysed
	minified bool
	decoded  int64 // bytes its blobs decoded, for the package budget
}

// Analyze returns the features of the files at paths in t. Code files
// (Kind php, js, minified) are lexed and analysed; package.json and
// composer.json give install hooks and hosts; documentation gives hosts;
// style sheets and SVG files give data URIs; assets, binary files and
// plain text files are checked for hidden code. Every limit fails
// closed: a code file over lim.EntryAnalysed, one whose analysis takes
// longer than lim.FileBudget, one with an unterminated construct and
// one whose blobs hit a decode limit are listed in Unanalysed with the
// reason. Files are analysed on GOMAXPROCS workers and the result is
// the same on every run: features sorted by path, line, kind and key.
// Only a done ctx is an error.
func (Analyzer) Analyze(ctx context.Context, t *core.Tree, paths []string, lim core.Limits) (*core.FeatureSet, error) {
	lim = withDefaults(lim)
	set := core.NewFeatureSet()
	if t == nil {
		return set, nil
	}
	paths = slices.Clone(paths)
	slices.Sort(paths)
	paths = slices.Compact(paths)
	results := make([]fileResult, len(paths))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for range max(1, min(runtime.GOMAXPROCS(0), len(paths))) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if ctx.Err() == nil {
					results[i] = analyzeFile(ctx, t, paths[i], lim)
				}
			}
		}()
	}
	for i := range paths {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	merge(set, paths, results)
	return set, nil
}

// merge adds the results to set in path order. The package decode
// budget (16 MiB) is applied here, in path order, rather than shared by
// the workers as they go, so which file passes it never depends on
// scheduling: a file whose blobs decode past it loses its decoded
// features and is Unanalysed with reasonDecodeLimit.
func merge(set *core.FeatureSet, paths []string, results []fileResult) {
	var decoded int64
	for i, r := range results {
		decoded += r.decoded
		over := r.decoded > 0 && decoded > maxPackageOut
		for _, f := range r.feats {
			if over && f.Context == core.CtxDecoded {
				continue
			}
			set.Add(f)
		}
		un := r.un
		if over {
			un = append(un, core.Unanalysed{Path: paths[i], Reason: reasonDecodeLimit})
		}
		set.Unanalysed = append(set.Unanalysed, un...)
		if r.minified {
			set.Minified = append(set.Minified, paths[i])
		}
	}
	slices.SortStableFunc(set.Unanalysed, func(a, b core.Unanalysed) int {
		if c := strings.Compare(a.Path, b.Path); c != 0 {
			return c
		}
		return strings.Compare(a.Reason, b.Reason)
	})
	set.Unanalysed = slices.Compact(set.Unanalysed)
}

// withDefaults fills the limits a caller left at zero.
func withDefaults(lim core.Limits) core.Limits {
	def := core.DefaultLimits()
	if lim.EntryAnalysed <= 0 {
		lim.EntryAnalysed = def.EntryAnalysed
	}
	if lim.FileBudget <= 0 {
		lim.FileBudget = def.FileBudget
	}
	return lim
}

// reasonTooBig is the Unanalysed reason of a code file over the limit:
// "file over 4 MiB".
func reasonTooBig(limit int64) string {
	switch {
	case limit >= 1<<20 && limit%(1<<20) == 0:
		return "file over " + strconv.FormatInt(limit>>20, 10) + " MiB"
	case limit >= 1<<10 && limit%(1<<10) == 0:
		return "file over " + strconv.FormatInt(limit>>10, 10) + " KiB"
	}
	return "file over " + strconv.FormatInt(limit, 10) + " bytes"
}

// manifest reports a package.json or composer.json: metadata whose
// scripts run on install, so one too big to read is Unanalysed.
func manifest(p string) bool {
	base := path.Base(p)
	return base == "package.json" || base == "composer.json"
}

// styleExts are the style sheets read for data URIs.
var styleExts = map[string]bool{".css": true, ".scss": true, ".sass": true, ".less": true}

// analyzeFile analyses one file of t within its time budget.
func analyzeFile(ctx context.Context, t *core.Tree, p string, lim core.Limits) fileResult {
	f, ok := t.Lookup(p)
	if !ok || f.Mode&fs.ModeType != 0 {
		return fileResult{} // removed, or a link: the archive issues cover links
	}
	ext := strings.ToLower(path.Ext(p))
	var l lang
	code := false
	switch f.Kind {
	case core.KindPHP:
		l, code = langPHP, true
	case core.KindJS, core.KindMinified:
		l, code = langJS, true
	case core.KindJSON, core.KindText, core.KindAsset, core.KindBinary:
	default:
		return fileResult{} // archives are listed, not opened
	}
	asset := assetChecked(p, f.Kind)
	style := styleExts[ext] || ext == ".svg"
	doc := f.Kind == core.KindText && pathContext(p) == core.CtxDoc
	if !code && !asset && !style && !doc && f.Kind != core.KindJSON && !secretText(p, f.Kind) {
		return fileResult{}
	}
	src, tail, over, err := readFile(t, f, lim.EntryAnalysed, asset)
	if err != nil {
		return fileResult{un: []core.Unanalysed{{Path: p, Reason: reasonUnread}}}
	}
	if over {
		return oversized(p, f.Kind, src, tail, lim.EntryAnalysed, code, asset)
	}
	fctx, cancel := context.WithTimeout(ctx, lim.FileBudget)
	defer cancel()
	budget := newDecodeBudget()
	env := decodeEnv{budget: budget, layers: maxLayers, clk: newClock(fctx)}
	var r fileResult
	switch {
	case code:
		r.feats, r.un = analyzeCode(l, p, src, pathContext(p), env)
		r.minified = minified(p, f.Kind, src)
	case f.Kind == core.KindJSON:
		_, gyp := t.Lookup(path.Join(path.Dir(p), "binding.gyp"))
		r.feats = jsonFeatures(p, src, gyp)
	case doc:
		r.feats = docFeatures(p, src)
	}
	if style {
		fs, un := assetFeatures(p, src, env)
		r.feats, r.un = append(r.feats, fs...), append(r.un, un...)
		r.minified = r.minified || ext == ".css" && minified(p, f.Kind, src)
	}
	if asset {
		fs, un := assetFileFeatures(p, src, env)
		r.feats, r.un = append(r.feats, fs...), append(r.un, un...)
	}
	if code || secretText(p, f.Kind) {
		if env.clk.expired() {
			// The secret scan is skipped; reasonTimeLimit is listed
			// once by merge.
			r.un = append(r.un, core.Unanalysed{Path: p, Reason: reasonTimeLimit})
		} else {
			r.feats = append(r.feats, secretFeatures(p, src, code)...)
		}
	}
	sortFeatures(r.feats)
	r.decoded = maxPackageOut - max(budget.left.Load(), 0)
	return r
}

// secretText reports a text or JSON file read for hard-coded secrets:
// configuration and data, not documentation.
func secretText(p string, kind core.FileKind) bool {
	return (kind == core.KindText || kind == core.KindJSON) && !docName(p) && pathContext(p) != core.CtxDoc
}

// oversized handles a file over the analysis limit: code and package
// manifests are Unanalysed; an asset whose start or end holds code is
// code-in-asset and Unanalysed (the code is not read whole); anything
// else is listed, not flagged.
func oversized(p string, kind core.FileKind, head, tail []byte, limit int64, code, asset bool) fileResult {
	var r fileResult
	if code || kind == core.KindJSON && manifest(p) {
		r.un = []core.Unanalysed{{Path: p, Reason: reasonTooBig(limit)}}
		return r
	}
	if !asset {
		return r
	}
	for i, part := range [][]byte{head, tail} {
		if l, k, ok := assetCode(p, part); ok {
			name := "php"
			if l == langJS {
				name = "js"
			}
			line := bytes.Count(part[:k], []byte("\n")) + 1
			if i == 1 {
				line = 0 // the end of the file: its line is not counted
			}
			r.feats = []core.Feature{{
				Kind: core.FCodeInAsset, Key: p, Context: pathContext(p),
				Attrs: map[string]string{"lang": name, "ext": strings.ToLower(path.Ext(p))},
				Ev:    core.Evidence{Path: p, Line: line, EndLine: line, Snippet: core.NewSnippet(snippetAt(part, k))},
			}}
			r.un = []core.Unanalysed{{Path: p, Reason: reasonTooBig(limit)}}
			return r
		}
	}
	return r
}

// snippetAt is the text of the line that holds offset k.
func snippetAt(b []byte, k int) string {
	start := bytes.LastIndexByte(b[:k], '\n') + 1
	end := bytes.IndexByte(b[k:], '\n')
	if end < 0 {
		end = len(b)
	} else {
		end += k
	}
	return string(b[start:min(end, start+snippetLine)])
}

// readFile reads up to limit bytes of f. over is true when the file
// holds more, counted on bytes read and never on the size the archive
// claims. With keepTail, an oversized file is read to its end and its
// last tailMax bytes are returned too, for code appended to an image.
func readFile(t *core.Tree, f core.File, limit int64, keepTail bool) (head, tail []byte, over bool, err error) {
	if t.Blobs == nil {
		return nil, nil, false, core.ErrBlobCorrupt
	}
	rc, err := t.Blobs.Open(f.SHA256)
	if err != nil {
		return nil, nil, false, err
	}
	defer func() { _ = rc.Close() }()
	br := bufio.NewReader(rc)
	head, err = io.ReadAll(io.LimitReader(br, limit))
	if err != nil {
		return nil, nil, false, err
	}
	if _, err := br.Peek(1); err != nil {
		if err == io.EOF { //nolint:errorlint // bufio returns io.EOF itself
			return head, nil, false, nil
		}
		return nil, nil, false, err
	}
	if !keepTail {
		// Read to the end anyway: the store checks the hash there.
		if _, err := io.Copy(io.Discard, br); err != nil {
			return nil, nil, true, err
		}
		return head, nil, true, nil
	}
	ring := make([]byte, 0, tailMax)
	buf := make([]byte, 64<<10)
	for {
		n, rerr := br.Read(buf)
		ring = append(ring, buf[:n]...)
		if len(ring) > tailMax {
			ring = append(ring[:0], ring[len(ring)-tailMax:]...)
		}
		if rerr == io.EOF { //nolint:errorlint // Read returns io.EOF itself
			return head, ring, true, nil
		}
		if rerr != nil {
			return nil, nil, true, rerr
		}
	}
}

// nameRules are the kit secrets rules that judge a value by the name
// it is given (a variable, a header, a form field) rather than by a
// provider's token format. In code they fire on `credentials:
// 'same-origin'` and the like, so code keeps only the format rules.
var nameRules = map[string]bool{
	"assignment": true, "header-token": true, "form-field": true, "json-field": true, "cookie": true,
	"authorization": true, "yaml": true, "env": true, "key-path-token": true, "reset-link-token": true,
	"oauth-code": true, "wp-reset-key": true, "php-serialized": true,
}

// secretFeatures returns FSecret for every hard-coded credential kit
// secrets finds, one per line and secret; in code (PHP, JavaScript)
// only the rules that know a token's format count. The key and
// attributes hold the masked value only and the snippet is masked by
// core.NewSnippet, so no raw secret leaves the analyzer.
func secretFeatures(p string, src []byte, code bool) []core.Feature {
	keep := func(ss []secrets.Secret) []secrets.Secret {
		if code {
			ss = slices.DeleteFunc(ss, func(s secrets.Secret) bool { return nameRules[s.Kind] })
		}
		return ss
	}
	if len(keep(secrets.FindSecrets(src))) == 0 {
		return nil
	}
	col := newCollector(p, pathContext(p), newLineIndex(src))
	line := 0
	for rest := src; len(rest) > 0; {
		line++
		n := bytes.IndexByte(rest, '\n')
		if n < 0 {
			n = len(rest)
		}
		for _, s := range keep(secrets.FindSecrets(rest[:n])) {
			col.add(core.FSecret, s.Kind+":"+attrText(s.String()), line, line, "", map[string]string{
				"kind":   s.Kind,
				"name":   attrText(s.Name),
				"masked": s.Masked,
			})
		}
		rest = rest[min(n+1, len(rest)):]
	}
	return col.out
}

// AnalyzeText analyses text that is not a file of a tree, such as an
// npm script or a file a script names: PHP and JavaScript as code, any
// other kind as shell lines. The default limits apply: text over 4 MiB
// or slower than 2 s is Unanalysed.
func (Analyzer) AnalyzeText(ctx context.Context, kind core.FileKind, p string, src []byte) (*core.FeatureSet, error) {
	lim := core.DefaultLimits()
	set := core.NewFeatureSet()
	if int64(len(src)) > lim.EntryAnalysed {
		set.Unanalysed = []core.Unanalysed{{Path: p, Reason: reasonTooBig(lim.EntryAnalysed)}}
		return set, nil
	}
	fctx, cancel := context.WithTimeout(ctx, lim.FileBudget)
	defer cancel()
	feats, un := analyzeText(kind, p, src, decodeEnv{budget: newDecodeBudget(), layers: maxLayers, clk: newClock(fctx)})
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	for _, f := range feats {
		set.Add(f)
	}
	set.Unanalysed = un
	if kind == core.KindMinified || kind == core.KindJS && minified(p, kind, src) {
		set.Minified = []string{p}
	}
	return set, nil
}
