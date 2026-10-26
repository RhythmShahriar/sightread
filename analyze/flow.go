// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"sort"
	"strconv"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
)

// Data flow lite: within each function body, follow values from a
// source (a fetch, the request, a decoder, the environment) to a sink
// (eval, include, unserialize, a dynamic call, a code write, a shell).
// Flow goes through assignments, concatenation, array and member
// access and calls such as json_decode. Closures run inline. Flow also
// goes one level into a function of the same file: a call passes its
// arguments' taint to that function's summary and gets its return
// value's taint back. The result is an FFlow feature keyed
// "<source>-><sink>".

// The sinks, as they appear in FFlow keys.
const (
	sinkEval        = "eval"
	sinkInclude     = "include"
	sinkUnserialize = "unserialize"
	sinkDynCall     = "dyn-call"
	sinkWriteCode   = "write-code"
	sinkExec        = "exec"
)

// decodeFuncs are the PHP decoders. Their output counts as source
// "decode": a payload that is decoded and then run is the classic
// obfuscated backdoor.
var decodeFuncs = map[string]bool{
	"base64_decode": true, "gzinflate": true, "gzuncompress": true, "gzdecode": true,
	"str_rot13": true, "hex2bin": true, "convert_uudecode": true, "strrev": true,
}

var phpRemote = map[string]bool{
	"wp_remote_get": true, "wp_remote_post": true, "wp_remote_request": true, "wp_remote_head": true,
	"wp_safe_remote_get": true, "wp_safe_remote_post": true, "wp_safe_remote_request": true,
	"wp_safe_remote_head": true, "wp_remote_retrieve_body": true, "download_url": true,
	"curl_exec": true, "curl_multi_getcontent": true, "fsockopen": true, "pfsockopen": true,
	"stream_socket_client": true,
}

// phpURLReaders read a URL when given one.
var phpURLReaders = map[string]bool{"file_get_contents": true, "fopen": true, "file": true, "readfile": true}

var phpShell = map[string]bool{
	"system": true, "exec": true, "shell_exec": true, "passthru": true, "proc_open": true,
	"popen": true, "pcntl_exec": true, "expect_popen": true,
}

// phpPropagate are calls whose result carries their arguments' data.
var phpPropagate = map[string]bool{
	"json_decode": true, "wp_remote_retrieve_body": true, "trim": true, "rtrim": true, "ltrim": true,
	"substr": true, "strtolower": true, "strtoupper": true, "str_replace": true, "str_ireplace": true,
	"preg_replace": true, "stripslashes": true, "wp_unslash": true, "urldecode": true,
	"rawurldecode": true, "html_entity_decode": true, "htmlspecialchars_decode": true, "implode": true,
	"join": true, "explode": true, "sprintf": true, "vsprintf": true, "strval": true,
	"array_values": true, "array_merge": true, "array_pop": true, "array_shift": true, "reset": true,
	"end": true, "current": true, "maybe_unserialize": true, "unserialize": true, "fgets": true,
	"fread": true, "fgetc": true, "stream_get_contents": true, "str_split": true, "ucfirst": true,
	"pack": true, "array_map": true, "array_filter": true, "sanitize_text_field": true,
	"base64_decode": true, "gzinflate": true, "gzuncompress": true, "gzdecode": true,
	"str_rot13": true, "hex2bin": true, "convert_uudecode": true, "strrev": true,
	"wp_remote_retrieve_header": true, "wp_remote_retrieve_headers": true,
}

var jsPropagate = map[string]bool{
	"JSON.parse": true, "String": true, "decodeURIComponent": true, "atob": true,
	"Buffer.from": true, "Buffer.concat": true, "toString": true, "trim": true, "json": true,
	"text": true, "concat": true, "join": true, "slice": true, "replace": true,
}

var jsRemote = map[string]bool{
	"fetch": true, "node-fetch": true, "axios": true, "got": true, "request": true,
	"http.get": true, "https.get": true, "http.request": true, "https.request": true,
	"http2.connect": true, "net.connect": true, "net.createConnection": true, "tls.connect": true,
	"dns.resolve": true, "dns.resolveTxt": true, "dns.promises.resolveTxt": true,
	"undici.request": true, "undici.fetch": true, "XMLHttpRequest": true, "needle": true,
	"superagent": true, "WebSocket": true, "ws": true,
}

var jsExec = map[string]bool{
	"child_process.exec": true, "child_process.execSync": true, "child_process.spawn": true,
	"child_process.spawnSync": true, "child_process.execFile": true, "child_process.execFileSync": true,
	"child_process.fork": true, "shelljs.exec": true, "execa": true, "execa.command": true,
}

var jsEval = map[string]bool{
	"eval": true, "Function": true, "vm.runInNewContext": true, "vm.runInThisContext": true,
	"vm.runInContext": true, "vm.compileFunction": true, "vm.Script": true, "vm.SourceTextModule": true,
	"execScript": true,
}

var jsTimers = map[string]bool{"setTimeout": true, "setInterval": true, "setImmediate": true}

var jsWrite = map[string]bool{
	"fs.writeFile": true, "fs.writeFileSync": true, "fs.appendFile": true, "fs.appendFileSync": true,
	"fs.promises.writeFile": true, "fs.promises.appendFile": true, "fs.createWriteStream": true,
}

// codeExts are the file types a write must not plant.
var codeExts = []string{".php", ".phtml", ".php5", ".php7", ".phar", ".inc", ".js", ".mjs", ".cjs"}

// summary is what calling a function of the same file does with its
// parameters, found with parameter markers in place of sources.
type summary struct {
	ret  taint
	hits []hit
}

type hit struct {
	sink, name string
	line       int
	t          taint
}

// flowHooks is the hooks implementation of the data flow pass.
type flowHooks struct {
	st      *stream
	lines   lineIndex
	path    string
	ctx     string
	bodies  []body
	funcs   map[string][]int // function key -> body indexes
	methods map[string][]int // method key -> body indexes
	sums    []*summary       // per body; nil until computed
	cur     *summary         // the summary being computed, or nil
	out     map[string]core.Feature
	obs     observer // sees the last pass over each body, or nil
	observe bool     // the current pass is the one obs sees
}

// observer is what feature extraction (extract.go) plugs into the flow
// pass: it sees every call and include of the last pass over each body,
// with folded values and taint, so extraction needs no walk of its own.
type observer interface {
	begin(h *flowHooks)
	call(s *scope, c *callSite)
	include(s *scope, r res, sp [2]int, line int, kind string)
}

// flowFeatures returns the FFlow features of one file's stream. src is
// the file text, for snippets.
func flowFeatures(st *stream, src []byte, path, ctx string) []core.Feature {
	return runFlow(st, newLineIndex(src), path, ctx, nil)
}

// runFlow is flowFeatures with an observer.
func runFlow(st *stream, lines lineIndex, path, ctx string, obs observer) []core.Feature {
	h := &flowHooks{st: st, lines: lines, path: path, ctx: ctx, obs: obs,
		funcs: map[string][]int{}, methods: map[string][]int{}, out: map[string]core.Feature{}}
	bodies, skip := splitBodies(st)
	h.bodies = bodies
	f := &fileCtx{st: st, h: h, skip: skip}
	if st.lang == langJS {
		f.aliases = jsAliases(st)
	}
	for i, b := range bodies {
		if b.key == "" {
			continue
		}
		if b.method {
			h.methods[b.key] = append(h.methods[b.key], i)
		} else {
			h.funcs[b.key] = append(h.funcs[b.key], i)
		}
	}
	if obs != nil {
		obs.begin(h)
	}
	budget := func() int { return 8*len(st.toks) + 4096 }
	// Phase 1: summaries, parameters marked.
	h.sums = make([]*summary, len(bodies))
	sums := make([]*summary, len(bodies))
	for i, b := range bodies {
		if i == 0 || b.key == "" {
			continue
		}
		sum := &summary{}
		h.cur = sum
		f.budget = budget()
		s := newScope(f, b.name)
		for _, p := range b.params {
			s.vars[p.name] = paramTaint(p.idx)
		}
		s.walk(b.start, b.end)
		sum.ret = s.ret
		sums[i] = sum
	}
	h.cur = nil
	h.sums = sums
	// Phase 2: every body with real sources, summaries applied. Two
	// passes over a body let a value tainted late (in a callback) reach
	// a sink read earlier.
	for _, b := range bodies {
		s := newScope(f, b.name)
		for pass := range 2 {
			h.observe = pass == 1
			f.budget = budget()
			s.env = map[string]value{}
			s.walk(b.start, b.end)
		}
	}
	keys := make([]string, 0, len(h.out))
	for k := range h.out {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	feats := make([]core.Feature, 0, len(keys))
	for _, k := range keys {
		feats = append(feats, h.out[k])
	}
	sort.SliceStable(feats, func(a, b int) bool {
		if feats[a].Ev.Line != feats[b].Ev.Line {
			return feats[a].Ev.Line < feats[b].Ev.Line
		}
		return feats[a].Key < feats[b].Key
	})
	return feats
}

func (h *flowHooks) propagates(name string) bool {
	if h.st.lang == langPHP {
		return phpPropagate[name]
	}
	return jsPropagate[name]
}

func (h *flowHooks) read(s *scope, name string, line int) taint {
	var t taint
	if s.lang == langPHP {
		switch name {
		case "$_GET", "$_POST", "$_REQUEST", "$_COOKIE", "$_SERVER", "$_FILES", "$HTTP_RAW_POST_DATA":
			t.add(srcRequest, line, name)
		case "$_ENV":
			t.add(srcEnv, line, name)
		}
		return t
	}
	if name == "process.env" || strings.HasPrefix(name, "process.env.") {
		t.add(srcEnv, line, name)
	}
	return t
}

func (h *flowHooks) include(s *scope, r res, sp [2]int, line int, kind string) {
	h.sink(s, sinkInclude, kind, line, r.t)
	if h.observe && h.obs != nil {
		h.obs.include(s, r, sp, line, kind)
	}
}

func (h *flowHooks) call(s *scope, c *callSite) taint {
	if h.observe && h.obs != nil && h.cur == nil {
		h.obs.call(s, c)
	}
	if s.lang == langPHP {
		return h.callPHP(s, c)
	}
	return h.callJS(s, c)
}

func (h *flowHooks) callPHP(s *scope, c *callSite) taint {
	var t taint
	name := c.name
	switch {
	case phpRemote[name]:
		t.add(srcRemote, c.line, name)
	case phpURLReaders[name]:
		switch urlKind(s, c, 0) {
		case "remote":
			t.add(srcRemote, c.line, name)
		case "input":
			t.add(srcRequest, c.line, "php://input")
		}
	case name == "getallheaders" || name == "apache_request_headers" || name == "filter_input" || name == "filter_input_array":
		t.add(srcRequest, c.line, name)
	case name == "getenv":
		t.add(srcEnv, c.line, name)
	}
	if decodeFuncs[name] {
		t.add(srcDecode, c.line, name)
	}
	// Sinks.
	switch {
	case name == "eval" || name == "assert":
		h.sink(s, sinkEval, name, c.line, c.arg(0).t)
	case name == "create_function":
		h.sink(s, sinkEval, name, c.line, c.argsTaint())
	case name == "preg_replace" && evalModifier(c.arg(0).v):
		h.sink(s, sinkEval, "preg_replace /e", c.line, c.arg(1).t.union(c.arg(2).t))
	case phpShell[name]:
		h.sink(s, sinkExec, name, c.line, c.argsTaint())
	case name == "unserialize" || name == "maybe_unserialize":
		h.sink(s, sinkUnserialize, name, c.line, c.arg(0).t)
	case name == "file_put_contents":
		if codeTarget(s, c, 0) {
			h.sink(s, sinkWriteCode, name, c.line, c.arg(1).t)
		}
	case name == "fwrite" || name == "fputs":
		if v := c.arg(0).v; v.kind == vName && strings.HasPrefix(v.s, "fopen:") && isCodePath(v.s) {
			h.sink(s, sinkWriteCode, name, c.line, c.arg(1).t)
		}
	}
	if c.dynamic && name == "" {
		what := "variable function"
		switch {
		case c.via != "":
			what = c.via
		case c.recv != nil:
			what = "variable method"
		}
		h.sink(s, sinkDynCall, what, c.line, c.callee.t)
	}
	return t.union(h.applySummary(s, c))
}

func (h *flowHooks) callJS(s *scope, c *callSite) taint {
	var t taint
	name := c.name
	if strings.HasPrefix(name, "fs.promises.") {
		name = "fs." + strings.TrimPrefix(name, "fs.promises.")
	}
	root := name
	if k := strings.IndexByte(root, '.'); k > 0 {
		root = root[:k]
	}
	switch {
	case jsRemote[name] || (jsRemote[root] && (root == "axios" || root == "got" || root == "superagent" || root == "needle")):
		t.add(srcRemote, c.line, name)
	case name == "atob":
		t.add(srcDecode, c.line, name)
	case name == "Buffer.from":
		if enc, _ := c.arg(1).v.str(); enc == "base64" || enc == "hex" {
			t.add(srcDecode, c.line, name)
		}
	}
	switch {
	case jsEval[name]:
		if name == "eval" || strings.HasPrefix(name, "vm.") || name == "execScript" {
			h.sink(s, sinkEval, name, c.line, c.arg(0).t)
		} else {
			h.sink(s, sinkEval, name, c.line, c.argsTaint())
		}
	case jsTimers[name] && c.arg(0).v.kind != vClosure:
		h.sink(s, sinkEval, name, c.line, c.arg(0).t)
	case jsExec[name]:
		h.sink(s, sinkExec, name, c.line, c.argsTaint())
	case name == "require" || name == "import" || name == "module.require":
		h.sink(s, sinkInclude, name, c.line, c.arg(0).t)
	case jsWrite[name]:
		if codeTarget(s, c, 0) {
			h.sink(s, sinkWriteCode, name, c.line, c.arg(1).t)
		}
	}
	if c.recv == nil || c.method == "" {
		if c.callee.t.any() && !jsEval[name] && !jsExec[name] {
			h.sink(s, sinkDynCall, "variable function", c.line, c.callee.t)
		}
	}
	return t.union(h.applySummary(s, c))
}

// applySummary handles a call of a function of the same file: its
// parameters' paths to sinks become flows from the caller's arguments,
// and its return value's taint comes back. Only one level: summaries
// are computed without other summaries.
func (h *flowHooks) applySummary(s *scope, c *callSite) taint {
	if h.cur != nil {
		return taint{}
	}
	idx := h.calleeBody(s, c)
	if idx < 0 || h.sums[idx] == nil {
		return taint{}
	}
	sum := h.sums[idx]
	var t taint
	t = t.union(taint{bits: sum.ret.bits & realMask, from: sum.ret.from})
	for p := range maxParams {
		if sum.ret.bits&(1<<(paramBase+p)) != 0 {
			t = t.union(c.arg(p).t)
		}
	}
	callee := h.bodies[idx].name
	for _, hh := range sum.hits {
		for p := range maxParams {
			if hh.t.bits&(1<<(paramBase+p)) == 0 {
				continue
			}
			a := c.arg(p).t
			for src := range nSources {
				if a.has(src) {
					caller := s.fn
					if caller == "" {
						caller = "top level"
					}
					h.emit(src, a.from[src], hh.sink, hh.name, hh.line, callee, caller)
				}
			}
		}
	}
	return t
}

// calleeBody finds the body a call reaches, or -1.
func (h *flowHooks) calleeBody(s *scope, c *callSite) int {
	switch {
	case c.recv == nil && !c.dynamic && c.name != "":
		if s.lang == langPHP {
			if k := strings.LastIndex(c.name, "::"); k >= 0 {
				return first(h.methods[c.name[k+2:]])
			}
		}
		if s.lang == langJS && strings.HasPrefix(c.name, "this.") {
			return first(h.methods[strings.TrimPrefix(c.name, "this.")])
		}
		return first(h.funcs[c.name])
	case c.recv != nil && c.method != "":
		return first(h.methods[c.method])
	}
	return -1
}

func first(xs []int) int {
	if len(xs) == 0 {
		return -1
	}
	return xs[0]
}

// sink records that t reaches a sink: as a summary hit while summaries
// are computed, else as features for each real source.
func (h *flowHooks) sink(s *scope, sink, name string, line int, t taint) {
	if !t.any() {
		return
	}
	if h.cur != nil {
		if t.bits&^realMask != 0 {
			h.cur.hits = append(h.cur.hits, hit{sink: sink, name: name, line: line, t: t})
		}
		return
	}
	for src := range nSources {
		if t.has(src) {
			h.emit(src, t.from[src], sink, name, line, s.fn, "")
		}
	}
}

func (h *flowHooks) emit(src source, o origin, sink, sinkName string, line int, fn, caller string) {
	key := sourceNames[src] + "->" + sink
	from, to := o.line, line
	if from > to || from == 0 {
		from, to = to, max(from, to)
	}
	id := key + "\x00" + fn + "\x00" + strconv.Itoa(from) + "\x00" + strconv.Itoa(to)
	if _, ok := h.out[id]; ok {
		return
	}
	attrs := map[string]string{"source": o.name, "sink": sinkName}
	if caller != "" {
		// A flow one level deep: the source is in the caller.
		attrs["caller"] = caller
	}
	snip := h.lines.text(to)
	if from != to {
		snip = h.lines.text(from) + " … " + snip
	}
	h.out[id] = core.Feature{
		Kind:    core.FFlow,
		Key:     key,
		Context: h.ctx,
		Attrs:   attrs,
		Ev:      core.Evidence{Path: h.path, Line: from, EndLine: to, Func: fn, Snippet: core.NewSnippet(snip)},
	}
}

// urlKind tells whether argument i of a file reader names a URL: its
// value, or a literal piece of it, starts with a scheme.
func urlKind(s *scope, c *callSite, i int) string {
	var texts []string
	if v, ok := c.arg(i).v.str(); ok {
		texts = append(texts, v)
	} else if i < len(c.spans) {
		sp := c.spans[i]
		if sp[0] < len(s.toks) && s.toks[sp[0]].k == tStr && s.toks[sp[0]].known {
			texts = append(texts, s.toks[sp[0]].val)
		}
		for j := sp[0]; j < sp[1]; j++ {
			if s.toks[j].k == tStr && s.toks[j].known && strings.Contains(s.toks[j].val, "://") {
				texts = append(texts, s.toks[j].val)
			}
		}
	}
	for _, t := range texts {
		l := strings.ToLower(strings.TrimSpace(t))
		switch {
		case strings.HasPrefix(l, "php://input"):
			return "input"
		case strings.HasPrefix(l, "http://") || strings.HasPrefix(l, "https://") || strings.HasPrefix(l, "ftp://"):
			return "remote"
		}
	}
	return ""
}

// codeTarget reports whether argument i of a write names a code file:
// its value or a literal piece ends in a code extension.
func codeTarget(s *scope, c *callSite, i int) bool {
	if v, ok := c.arg(i).v.str(); ok {
		return isCodePath(v)
	}
	if i >= len(c.spans) {
		return false
	}
	return isCodePath(literalTail(s, c.spans[i]))
}

func isCodePath(p string) bool {
	p = strings.ToLower(strings.TrimSpace(p))
	for _, e := range codeExts {
		if strings.HasSuffix(p, e) {
			return true
		}
	}
	return false
}

// evalModifier reports whether a preg_replace pattern carries the /e
// modifier, which ran the replacement as PHP before PHP 7.
func evalModifier(v value) bool {
	pats := []value{v}
	if v.kind == vArr {
		pats = v.arr
	}
	for _, p := range pats {
		s, ok := p.str()
		s = strings.TrimSpace(s)
		if !ok || len(s) < 2 {
			continue
		}
		d := s[0]
		end := d
		switch d {
		case '(':
			end = ')'
		case '{':
			end = '}'
		case '[':
			end = ']'
		case '<':
			end = '>'
		}
		k := strings.LastIndexByte(s, end)
		if k <= 0 {
			continue
		}
		if strings.ContainsRune(s[k+1:], 'e') {
			return true
		}
	}
	return false
}

// lineIndex finds the text of a line of a file.
type lineIndex struct {
	src    string
	starts []int
}

func newLineIndex(src []byte) lineIndex {
	s := string(src)
	starts := []int{0}
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			starts = append(starts, i+1)
		}
	}
	return lineIndex{src: s, starts: starts}
}

// text returns line n (1-based) without its line break and outer blanks.
func (l lineIndex) text(n int) string {
	if n < 1 || n > len(l.starts) {
		return ""
	}
	start := l.starts[n-1]
	end := len(l.src)
	if n < len(l.starts) {
		end = l.starts[n] - 1
	}
	return strings.TrimSpace(l.src[start:end])
}
