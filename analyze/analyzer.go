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
	"golang.org/x/sync/semaphore"

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

// inflight is how many bytes of source the workers analyse at once.
// Analysis holds about a hundred times a file's size at its peak (the
// lexer's tokens, the normalised stream, the walk's values), so the
// workers share this budget rather than each taking a file of up to
// 4 MiB: many small files still run side by side, while large bundles
// run one after another and peak memory stays that of one file.
const inflight = 4 << 20

// ownDirs returns the folder names a WordPress install could give the
// package: the archive's stripped top folder ("akismet/" gives
// "akismet") and the name of each top-level PHP file without ".php",
// since a plugin's main file usually carries its slug. A GitHub archive
// folder ("owner-repo-sha") never matches, which errs toward scope=all.
func ownDirs(t *core.Tree) []string {
	var out []string
	if r := strings.Trim(t.Root, "/"); r != "" && !strings.Contains(r, "/") {
		out = append(out, strings.ToLower(r))
	}
	for _, f := range t.Files {
		if !strings.Contains(f.Path, "/") && strings.HasSuffix(strings.ToLower(f.Path), ".php") {
			out = append(out, strings.ToLower(f.Path[:len(f.Path)-4]))
		}
	}
	return out
}

// memWeight is what a file of size bytes holds from the inflight
// budget: at least 1 so empty files take turns too, at most the whole
// budget so a file over it (with a raised limit) still runs.
func memWeight(size int64) int64 { return min(max(size, 1), inflight) }

// fileResult is what one file gave.
type fileResult struct {
	feats    []core.Feature
	un       []core.Unanalysed
	minified bool
}

// Analyze returns the features of the files at paths in t. Code files
// (Kind php, js, minified) are lexed and analysed; package.json and
// composer.json give install hooks and hosts; documentation gives hosts;
// style sheets and SVG files give data URIs; assets, binary files and
// plain text files are checked for hidden code. Every limit fails
// closed: a code file over lim.EntryAnalysed, one whose analysis takes
// longer than lim.FileBudget, one with an unterminated construct or
// code nested too deep and one whose blobs hit a decode limit are
// listed in Unanalysed with the reason. Files are analysed on
// GOMAXPROCS workers that together hold at most 4 MiB of source and
// 2 MiB of decoded payloads in analysis to bound memory; the whole
// package decodes at most 16 MiB. The result is the same on every run:
// features sorted by path, line, kind and key. Only a done ctx is an
// error.
func (Analyzer) Analyze(ctx context.Context, t *core.Tree, paths []string, lim core.Limits) (*core.FeatureSet, error) {
	lim = withDefaults(lim)
	set := core.NewFeatureSet()
	if t == nil {
		return set, nil
	}
	own := ownDirs(t)
	paths = slices.Clone(paths)
	slices.Sort(paths)
	paths = slices.Compact(paths)
	results := make([]fileResult, len(paths))
	type job struct {
		i      int
		f      core.File
		weight int64
	}
	jobs := make(chan job)
	mem := semaphore.NewWeighted(inflight)
	run := &analysis{t: t, lim: lim, own: own, decodeMem: semaphore.NewWeighted(decodeInflight), order: newDecodeOrder(len(paths))}
	var wg sync.WaitGroup
	for range max(1, min(runtime.GOMAXPROCS(0), len(paths))) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() == nil {
					results[j.i] = run.file(ctx, j.i, paths[j.i], j.f)
				}
				mem.Release(j.weight)
			}
		}()
	}
	// Files take their share of mem here, in path order, before a
	// worker starts them: a file that waits in decodeOrder for the
	// files before it then never holds memory those files still need.
	for i, p := range paths {
		f, ok := run.wanted(p)
		if !ok {
			run.order.finish(i, 0)
			continue
		}
		// The read and the analysis hold the file's size from mem. The
		// size the tree records is that of the stored blob, which Open
		// checks, so the bytes read never exceed it.
		w := memWeight(f.Size)
		if err := mem.Acquire(ctx, w); err != nil {
			break // canceled: Analyze returns ctx's error
		}
		jobs <- job{i: i, f: f, weight: w}
	}
	close(jobs)
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	merge(set, paths, results)
	return set, nil
}

// analysis is what the workers of one Analyze call share.
type analysis struct {
	t         *core.Tree
	lim       core.Limits
	own       []string
	decodeMem *semaphore.Weighted
	order     *decodeOrder
}

// decodeOrder hands out the package decode budget (maxPackageOut) in
// path order, so which file runs out never depends on scheduling and
// the whole package decodes at most maxPackageOut however many files
// hold payloads. A file that decodes waits, on its first decode, until
// every file before it has finished, then gets what they left. Files
// that decode nothing never wait. Workers take files in path order, so
// the files waited on are always running or done.
type decodeOrder struct {
	mu      sync.Mutex
	done    []bool
	used    []int64
	next    int           // files [0, next) are finished
	spent   int64         // what files [0, next) decoded
	changed chan struct{} // closed and replaced when next moves
}

func newDecodeOrder(n int) *decodeOrder {
	return &decodeOrder{done: make([]bool, n), used: make([]int64, n), changed: make(chan struct{})}
}

// finish records that file i is done after decoding used bytes.
func (o *decodeOrder) finish(i int, used int64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.done[i], o.used[i] = true, used
	moved := false
	for o.next < len(o.done) && o.done[o.next] {
		o.spent += o.used[o.next]
		o.next++
		moved = true
	}
	if moved {
		close(o.changed)
		o.changed = make(chan struct{})
	}
}

// left waits until every file before i has finished and returns what
// they left of the package budget; 0 when ctx ends first.
func (o *decodeOrder) left(ctx context.Context, i int) int64 {
	for {
		o.mu.Lock()
		if o.next >= i {
			left := maxPackageOut - o.spent
			o.mu.Unlock()
			return max(left, 0)
		}
		ch := o.changed
		o.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return 0
		}
	}
}

// merge adds the results to set in path order.
func merge(set *core.FeatureSet, paths []string, results []fileResult) {
	for i, r := range results {
		for _, f := range r.feats {
			set.Add(f)
		}
		set.Unanalysed = append(set.Unanalysed, r.un...)
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

// wanted returns the file at p and whether it is read at all.
func (a *analysis) wanted(p string) (core.File, bool) {
	f, ok := a.t.Lookup(p)
	if !ok || f.Mode&fs.ModeType != 0 {
		return f, false // removed, or a link: the archive issues cover links
	}
	switch f.Kind {
	case core.KindPHP, core.KindJS, core.KindMinified:
		return f, true
	case core.KindJSON:
		return f, true
	case core.KindText, core.KindAsset, core.KindBinary:
	default:
		return f, false // archives are listed, not opened
	}
	ext := strings.ToLower(path.Ext(p))
	doc := f.Kind == core.KindText && pathContext(p) == core.CtxDoc
	return f, assetChecked(p, f.Kind) || styleExts[ext] || ext == ".svg" || doc || secretText(p, f.Kind)
}

// file analyses file i of the tree, at p, within its time budget. The
// caller holds the file's size from the source memory budget and
// records it as finished in the decode order.
func (a *analysis) file(ctx context.Context, i int, p string, f core.File) (r fileResult) {
	lim := a.lim
	clk := newClock(ctx, lim.FileBudget)
	budget := &decodeBudget{ready: func() int64 {
		// Waiting for the files before this one is not this file's
		// analysis time.
		resume := clk.pause()
		defer resume()
		return a.order.left(ctx, i)
	}}
	defer func() { a.order.finish(i, budget.used()) }()
	ext := strings.ToLower(path.Ext(p))
	var l lang
	code := false
	switch f.Kind {
	case core.KindPHP:
		l, code = langPHP, true
	case core.KindJS, core.KindMinified:
		l, code = langJS, true
	}
	asset := assetChecked(p, f.Kind)
	style := styleExts[ext] || ext == ".svg"
	doc := f.Kind == core.KindText && pathContext(p) == core.CtxDoc
	src, tail, over, err := readFile(a.t, f, lim.EntryAnalysed, asset)
	if err != nil {
		return fileResult{un: []core.Unanalysed{{Path: p, Reason: reasonUnread}}}
	}
	if over {
		return oversized(p, f.Kind, src, tail, lim.EntryAnalysed, code, asset)
	}
	env := decodeEnv{budget: budget, layers: maxLayers, clk: clk, own: a.own, mem: a.decodeMem}
	switch {
	case code:
		r.feats, r.un = analyzeCode(l, p, src, pathContext(p), env)
		r.minified = minified(p, f.Kind, src)
	case f.Kind == core.KindJSON:
		_, gyp := a.t.Lookup(path.Join(path.Dir(p), "binding.gyp"))
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
	all := keep(secrets.FindSecrets(src))
	if len(all) == 0 {
		return nil
	}
	col := newCollector(p, pathContext(p), newLineIndex(src))
	found := map[secrets.Secret]bool{}
	add := func(s secrets.Secret, line int, raw []byte) {
		found[s] = true
		attrs := map[string]string{
			"kind":   s.Kind,
			"name":   attrText(s.Name),
			"masked": s.Masked,
		}
		if exampleSecret(string(raw), s) {
			attrs["example"] = "true"
		}
		col.add(core.FSecret, s.Kind+":"+attrText(s.String()), line, line, "", attrs)
	}
	line := 0
	for rest := src; len(rest) > 0; {
		line++
		n := bytes.IndexByte(rest, '\n')
		if n < 0 {
			n = len(rest)
		}
		for _, s := range keep(secrets.FindSecrets(rest[:n])) {
			add(s, line, rest[:n])
		}
		rest = rest[min(n+1, len(rest)):]
	}
	if len(found) == len(all) {
		return col.out
	}
	// A secret the whole text holds but no single line does spans
	// lines: a PEM private key block. Each block is scanned from its
	// BEGIN line, which is where it is reported.
	for _, b := range pemBlocks(src) {
		for _, s := range keep(secrets.FindSecrets(src[b.start:b.end])) {
			if !found[s] {
				add(s, b.line, src[b.start:b.end])
			}
		}
	}
	// Fail toward reporting: anything still not placed goes on line 1.
	for _, s := range all {
		if !found[s] {
			add(s, 1, nil)
		}
	}
	return col.out
}

// maskBullets is what secrets.Mask puts in place of the hidden part.
const maskBullets = "•••••"

// exampleSecret reports whether the value of s in raw is a documented
// example: its hidden part holds EXAMPLE or XXXX. Only the value counts,
// never the rest of the line, so "// for example" or an example.com
// host next to a real token does not lower it. The value is found by
// lining raw up with what secrets.Redact makes of it: each masked span
// is the kept prefix and the bullets. The raw text after it starts
// where the redacted text resumes.
func exampleSecret(raw string, s secrets.Secret) bool {
	if raw == "" || !strings.HasSuffix(s.Masked, maskBullets) {
		return false
	}
	red := secrets.Redact(raw)
	i, j := 0, 0 // raw[i:] lines up with red[j:]
	for {
		q := strings.Index(red[j:], maskBullets)
		if q < 0 {
			return false
		}
		q += j
		hiddenAt := i + (q - j) // raw[hiddenAt:] starts the hidden part
		after := q + len(maskBullets)
		// The next stretch of redacted text that is raw text too.
		next := strings.Index(red[after:], maskBullets)
		seg := red[after:]
		if next >= 0 {
			seg = red[after : after+next]
		}
		end := len(raw)
		if seg != "" {
			k := strings.Index(raw[min(hiddenAt+1, len(raw)):], seg)
			if k < 0 {
				return false
			}
			end = min(hiddenAt+1, len(raw)) + k
		}
		if hiddenAt > len(raw) || end < hiddenAt {
			return false
		}
		prefix := strings.TrimSuffix(s.Masked, maskBullets)
		if strings.HasSuffix(red[j:q], prefix) {
			v := strings.ToUpper(raw[hiddenAt:end])
			if strings.Contains(v, "EXAMPLE") || strings.Contains(v, "XXXX") {
				return true
			}
		}
		i, j = end, after
	}
}

// pemBlock is a "-----BEGIN" block at src[start:end] that starts on line.
type pemBlock struct {
	start, end, line int
}

// pemBlocks returns every "-----BEGIN" block of src, each running to
// the end of its "-----END ...-----" line or, unterminated, to the end
// of src.
func pemBlocks(src []byte) []pemBlock {
	const begin, end = "-----BEGIN ", "-----END "
	var out []pemBlock
	line, last := 1, 0
	for off := 0; ; {
		i := bytes.Index(src[off:], []byte(begin))
		if i < 0 {
			return out
		}
		i += off
		line += bytes.Count(src[last:i], []byte("\n"))
		last = i
		stop := len(src)
		if j := bytes.Index(src[i+len(begin):], []byte(end)); j >= 0 {
			stop = i + len(begin) + j + len(end)
			if k := bytes.IndexAny(src[stop:], "\r\n"); k >= 0 {
				stop += k
			} else {
				stop = len(src)
			}
		}
		out = append(out, pemBlock{start: i, end: stop, line: line})
		off = i + len(begin)
	}
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
	feats, un := analyzeText(kind, p, src, decodeEnv{budget: newDecodeBudget(), layers: maxLayers, clk: newClock(ctx, lim.FileBudget)})
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
