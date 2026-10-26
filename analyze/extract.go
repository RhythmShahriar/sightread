// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"path"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/RhythmShahriar/rhythm/kit/secrets"

	"github.com/RhythmShahriar/sightread/core"
)

// Feature extraction: what a file can do, as core.Feature values. It
// rides on the flow pass (flow.go): the extractor is that pass's
// observer and sees every call with its folded arguments and their
// taint, so a built name or a built path counts as written. The rules
// of each language are in php.go and js.go; this file holds what they
// share.

// callWindow is how many tokens after a callee extraction reads: a call
// whose arguments run longer is judged on its first callWindow tokens.
const callWindow = 256

// maxAttr is the most bytes of package text an attribute keeps.
const maxAttr = 200

// pathContext gives the Context of a file's features from its path
// inside the package: vendored code, tests and documentation are told
// apart from the package's own code.
func pathContext(p string) string {
	l := strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	parts := strings.Split(l, "/")
	dirs := parts[:len(parts)-1]
	has := func(names ...string) bool {
		for _, d := range dirs {
			for _, n := range names {
				if d == n {
					return true
				}
			}
		}
		return false
	}
	base := parts[len(parts)-1]
	switch {
	case has("vendor", "node_modules", "bower_components"):
		return core.CtxVendored
	case has("test", "tests", "__tests__"):
		return core.CtxTest
	case has("docs", "doc"), strings.HasPrefix(base, "readme"), strings.HasPrefix(base, "changelog"):
		return core.CtxDoc
	}
	switch path.Ext(base) {
	case ".md", ".markdown", ".rst", ".txt":
		return core.CtxDoc
	}
	return core.CtxCode
}

// collector gathers the features of one file, one per kind, key,
// context and line.
type collector struct {
	path  string
	ctx   string
	lines lineIndex
	seen  map[string]map[string]string // id -> the stored feature's attrs
	out   []core.Feature
	snips map[[2]int]core.Snippet // by line and end line, for short lines
}

func newCollector(path, ctx string, lines lineIndex) *collector {
	return &collector{path: path, ctx: ctx, lines: lines, seen: map[string]map[string]string{}}
}

// add records a feature in the file's context and returns its attrs,
// which the caller may still fill. A feature already recorded at the
// same line keeps its first attrs.
func (c *collector) add(kind core.FeatureKind, key string, line, end int, fn string, attrs map[string]string) map[string]string {
	return c.addCtxAt(c.ctx, -1, kind, key, line, end, fn, attrs)
}

// addAt is add with the byte offset of the feature in the file, so the
// snippet of a long line is cut around it.
func (c *collector) addAt(off int, kind core.FeatureKind, key string, line, end int, fn string, attrs map[string]string) map[string]string {
	return c.addCtxAt(c.ctx, off, kind, key, line, end, fn, attrs)
}

// addCtxAt is addAt with a context of its own (a comment, a decoded
// payload, an asset); off is -1 when unknown.
func (c *collector) addCtxAt(ctx string, off int, kind core.FeatureKind, key string, line, end int, fn string, attrs map[string]string) map[string]string {
	if attrs == nil {
		attrs = map[string]string{}
	}
	id := string(kind) + "\x00" + key + "\x00" + ctx + "\x00" + strconv.Itoa(line)
	if a, ok := c.seen[id]; ok {
		return a
	}
	c.seen[id] = attrs
	if end < line {
		end = line
	}
	c.out = append(c.out, core.Feature{
		Kind: kind, Key: key, Context: ctx, Attrs: attrs,
		Ev: core.Evidence{Path: c.path, Line: line, EndLine: end, Func: fn, Snippet: c.snippet(line, end, off)},
	})
	return attrs
}

// snippet is the masked text of lines line to end. Masking is the
// costly part of a feature, so a snippet that does not depend on the
// offset (a line shorter than snippetLine) is made once per line.
func (c *collector) snippet(line, end, off int) core.Snippet {
	short := c.lines.short(line)
	if short {
		if s, ok := c.snips[[2]int{line, end}]; ok {
			return s
		}
	}
	text := c.lines.textAt(line, off)
	if end != line {
		text += " … " + c.lines.text(end)
	}
	s := core.NewSnippet(text)
	if short {
		if c.snips == nil {
			c.snips = map[[2]int]core.Snippet{}
		}
		c.snips[[2]int{line, end}] = s
	}
	return s
}

// has reports whether a feature is already recorded, so a caller can
// skip building its attributes.
func (c *collector) has(ctx string, kind core.FeatureKind, key string, line int) bool {
	_, ok := c.seen[string(kind)+"\x00"+key+"\x00"+ctx+"\x00"+strconv.Itoa(line)]
	return ok
}

// attrText makes package text fit for an attribute: secrets masked,
// cut to maxAttr bytes on a rune boundary.
func attrText(s string) string {
	s = secrets.Redact(s)
	if len(s) <= maxAttr {
		return s
	}
	cut := maxAttr
	for cut > 0 && s[cut]&0xc0 == 0x80 {
		cut--
	}
	return s[:cut] + "…"
}

// bodyFacts is what one body reads besides its arguments: users,
// options, the admin email, the environment, credential files. A send
// in the same body names them in its "reads" attribute.
type bodyFacts map[string]bool

// The reads a body can have.
const (
	readUsers      = "users"
	readOptions    = "options"
	readAdminEmail = "admin_email"
	readEnv        = "env"
	readCreds      = "creds"
)

var readOrder = []string{readUsers, readOptions, readAdminEmail, readEnv, readCreds}

// extractor is the flow pass's observer for one file.
type extractor struct {
	col    *collector
	st     *stream
	toks   []tok
	lang   lang
	h      *flowHooks
	owner  []int32 // token index -> body index
	facts  []bodyFacts
	sends  []sendRef
	work   int             // look-back steps left (spend)
	uaVars map[string]bool // PHP variables holding the user agent
	own    []string        // the package's own plugin folders (ownDirs)
	// basenames holds the names given plugin_basename(__FILE__), found
	// on the first update filter: variables, properties and constants.
	basenames map[string]bool
}

// sendRef is a send whose "reads" attribute waits for the end of the
// file, when every read of its body is known.
type sendRef struct {
	body  int
	attrs map[string]string
}

func newExtractor(st *stream, col *collector) *extractor {
	return &extractor{col: col, st: st, toks: st.toks, lang: st.lang}
}

func (e *extractor) begin(h *flowHooks) {
	e.h = h
	e.work = 1<<20 + 16*len(e.toks)
	e.owner = make([]int32, len(e.toks))
	// Bodies come outer first, so an inner body overwrites its range.
	for bi := 1; bi < len(h.bodies); bi++ {
		b := h.bodies[bi]
		for k := max(b.start, 0); k < b.end && k < len(e.owner); k++ {
			e.owner[k] = int32(bi) // #nosec G115 -- a body index is far below 2^31
		}
	}
	e.facts = make([]bodyFacts, len(h.bodies))
}

func (e *extractor) call(s *scope, c *callSite) {
	if e.lang == langPHP {
		e.phpCall(s, c)
	} else {
		e.jsCall(s, c)
	}
	e.callHosts(c, hostCalls[jsName(c.name)])
}

func (e *extractor) include(s *scope, r res, sp [2]int, line int, kind string) {
	if e.lang == langPHP {
		e.phpInclude(s, r, sp, line, kind)
	}
}

// bodyAt is the index of the body that holds token i.
func (e *extractor) bodyAt(i int) int {
	if i >= 0 && i < len(e.owner) {
		return int(e.owner[i])
	}
	return 0
}

// fnAt is the evidence name of the body that holds token i.
func (e *extractor) fnAt(i int) string {
	if e.h == nil {
		return ""
	}
	return e.h.bodies[e.bodyAt(i)].name
}

// note records that the body holding token i reads what.
func (e *extractor) note(i int, what string) {
	b := e.bodyAt(i)
	if b >= len(e.facts) {
		return
	}
	if e.facts[b] == nil {
		e.facts[b] = bodyFacts{}
	}
	e.facts[b][what] = true
}

// send records a network send and returns its attrs.
func (e *extractor) send(c *callSite, key string, attrs map[string]string) map[string]string {
	a := e.callFeature(core.FSend, key, c, attrs)
	e.sends = append(e.sends, sendRef{body: e.bodyAt(c.pos), attrs: a})
	return a
}

// finishSends fills the reads attribute of every send.
func (e *extractor) finishSends() {
	for _, sr := range e.sends {
		if sr.body >= len(e.facts) || len(e.facts[sr.body]) == 0 {
			continue
		}
		var reads []string
		for _, r := range readOrder {
			if e.facts[sr.body][r] {
				reads = append(reads, r)
			}
		}
		if len(reads) > 0 {
			sr.attrs["reads"] = strings.Join(reads, ",")
		}
	}
}

// callEnd is the last token of a call's argument window.
func (e *extractor) callEnd(c *callSite) int {
	end := c.pos
	if len(c.spans) > 0 {
		// The closing parenthesis of the argument list.
		end = e.st.close(c.spans[0][0] - 1)
	}
	return max(min(end, c.pos+callWindow, len(e.toks)-1), 0)
}

// callFeature records a feature at a call, spanning its argument window.
func (e *extractor) callFeature(kind core.FeatureKind, key string, c *callSite, attrs map[string]string) map[string]string {
	end := e.toks[e.callEnd(c)].line
	return e.col.addAt(e.toks[c.pos].off, kind, key, c.line, end, e.fnAt(c.pos), attrs)
}

// argAttrs returns the folded string and number arguments of a call as
// arg0, arg1, ... (the first four), for FCall. Two kinds of argument
// keep only their size, as argN_bytes. One is the encoded input of a
// decoder (base64_decode, gzinflate and the like): its text would carry
// a secret past masking in encoded form. The other is binary text such
// as a decoded gzip stream, which is not valid UTF-8 or holds control
// bytes.
// The decoder's name is then argN_encoding.
func argAttrs(c *callSite) map[string]string {
	a := map[string]string{}
	for i := 0; i < len(c.args) && i < 4; i++ {
		v, ok := c.args[i].v.str()
		if !ok {
			continue
		}
		k := "arg" + strconv.Itoa(i)
		switch {
		case i == 0 && decoderNames[c.name]:
			a[k+"_bytes"] = strconv.Itoa(len(v))
			a[k+"_encoding"] = c.name
		case !textArg(v):
			a[k+"_bytes"] = strconv.Itoa(len(v))
		default:
			a[k] = attrText(v)
		}
	}
	return a
}

// textArg reports whether s reads as text: valid UTF-8 with no control
// bytes besides tab and line breaks.
func textArg(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c == 0x7f {
			return false
		}
	}
	return true
}

// argStr is argument i of c when folding knows it as a string.
func argStr(c *callSite, i int) (string, bool) {
	v, ok := c.arg(i).v.str()
	return v, ok
}

// span is the token range of argument i of c inside the stream, empty
// when absent. An unbalanced file can leave a range open to the end.
func (e *extractor) span(c *callSite, i int) [2]int {
	if i >= len(c.spans) {
		return [2]int{}
	}
	sp := c.spans[i]
	n := len(e.toks)
	return [2]int{min(sp[0], n), min(sp[1], n)}
}

// sourceAttr names the strongest source in t, or "".
func sourceAttr(t taint) string {
	for _, s := range []source{srcRequest, srcRemote, srcDecode, srcEnv} {
		if t.has(s) {
			return sourceNames[s]
		}
	}
	return ""
}

// isVarTok reports whether t names a variable: a PHP $var, a JS name.
func (e *extractor) isVarTok(t tok) bool {
	if e.lang == langPHP {
		return t.k == tVar
	}
	return t.k == tName && !isJSKeyword(t.text) && !jsRoots[t.text]
}

// lookBack is how many tokens back an assignment is looked for.
const lookBack = 4096

// spend uses one step of the file's look-back work and reports whether
// any was left. The budget keeps a file full of calls linear: past it,
// variables are no longer followed to their assignments.
func (e *extractor) spend() bool {
	e.work--
	return e.work >= 0
}

// assigned finds the last plain assignment "name = ..." before token
// before and returns the range of its right-hand side.
func (e *extractor) assigned(before int, name string) ([2]int, bool) {
	toks := e.toks
	for j := before - 1; j >= 0 && j >= before-lookBack; j-- {
		if !e.spend() {
			return [2]int{}, false
		}
		t := toks[j]
		if t.text != name || !e.isVarTok(t) || !at(toks, j+1).punct("=") {
			continue
		}
		if p := at(toks, j-1); p.punct("->") || p.punct("::") || p.punct(".") || p.punct("?->") || p.punct("?.") {
			continue
		}
		return [2]int{j + 2, e.exprStop(j+2, before)}, true
	}
	return [2]int{}, false
}

// indexAssigned finds the last "$name['key'] = ..." (or name.key = ...
// in JavaScript) before token before and returns its right-hand side.
func (e *extractor) indexAssigned(before int, name, key string) ([2]int, bool) {
	toks := e.toks
	for j := before - 1; j >= 0 && j >= before-lookBack; j-- {
		if !e.spend() {
			return [2]int{}, false
		}
		t := toks[j]
		if t.text != name || !e.isVarTok(t) {
			continue
		}
		n := at(toks, j+1)
		switch {
		case n.punct("[") && at(toks, j+2).k == tStr && at(toks, j+2).val == key && at(toks, j+3).punct("]") && at(toks, j+4).punct("="):
			return [2]int{j + 5, e.exprStop(j+5, before)}, true
		case n.punct(".") && at(toks, j+2).is(tName, key) && at(toks, j+3).punct("="):
			return [2]int{j + 4, e.exprStop(j+4, before)}, true
		}
	}
	return [2]int{}, false
}

// exprStop is where an expression starting at i ends: the first ; or
// , at depth zero, a closer of an outer bracket or a PHP tag, bounded
// by limit.
func (e *extractor) exprStop(i, limit int) int {
	for j := i; j < limit && j < len(e.toks); j++ {
		c := e.toks[j]
		switch {
		case c.punct("(") || c.punct("[") || c.punct("{"):
			j = min(e.st.close(j), limit)
		case c.punct(";") || c.punct(",") || c.punct(")") || c.punct("]") || c.punct("}") || c.k == tTag:
			return j
		}
	}
	return min(limit, len(e.toks))
}

// pathHints is what a token range is built from, in lower case.
type pathHints struct {
	all  []string // folded text, string literals and names
	lits []string // folded text and string literals only
}

// hints lists what a token range is built from: v's folded text, the
// range's string literals and names, plus what each variable in it was
// last assigned (two levels). Paths are classified
// from these: ABSPATH . 'wp-config.php' gives "abspath" and
// "wp-config.php".
func (e *extractor) hints(sp [2]int, v value) pathHints {
	var out pathHints
	if t, ok := v.str(); ok {
		l := strings.ToLower(t)
		out.all = append(out.all, l)
		out.lits = append(out.lits, l)
	}
	budget := 512
	e.hintsInto(sp, 2, &budget, &out)
	return out
}

func (e *extractor) hintsInto(sp [2]int, depth int, budget *int, out *pathHints) {
	for j := sp[0]; j < sp[1] && j < len(e.toks) && j < sp[0]+callWindow; j++ {
		*budget--
		if *budget < 0 {
			return
		}
		t := e.toks[j]
		switch {
		case t.k == tStr && t.known:
			l := strings.ToLower(t.val)
			out.all = append(out.all, l)
			out.lits = append(out.lits, l)
		case t.k == tName:
			name := strings.ToLower(t.text)
			// A member path reads as one name: os.homedir, process.env.HOME.
			for at(e.toks, j+1).punct(".") && at(e.toks, j+2).k == tName && e.lang == langJS && j+2 < sp[1] {
				name += "." + strings.ToLower(e.toks[j+2].text)
				j += 2
			}
			out.all = append(out.all, name)
			if depth > 0 && e.lang == langJS && !strings.Contains(name, ".") && e.isVarTok(t) && !at(e.toks, j+1).punct("(") {
				if r, ok := e.assigned(j, t.text); ok {
					e.hintsInto(r, depth-1, budget, out)
				}
			}
		case t.k == tVar:
			out.all = append(out.all, strings.ToLower(t.text))
			if depth > 0 {
				if r, ok := e.assigned(j, t.text); ok {
					e.hintsInto(r, depth-1, budget, out)
				}
			}
		}
	}
}

// rangeStr folds a short token range by hand: string literals,
// variables with a folded value and concatenation between them.
func (e *extractor) rangeStr(s *scope, sp [2]int) (string, bool) {
	var b strings.Builder
	want := true // a value is expected next
	for j := sp[0]; j < sp[1] && j < len(e.toks); j++ {
		t := e.toks[j]
		switch {
		case want && t.k == tStr && t.known:
			b.WriteString(t.val)
		case want && (t.k == tVar || (t.k == tName && e.lang == langJS)):
			v, ok := s.env[t.text].str()
			if !ok {
				return "", false
			}
			b.WriteString(v)
		case !want && (t.punct(".") && e.lang == langPHP || t.punct("+") && e.lang == langJS):
		default:
			return "", false
		}
		want = !want
		if b.Len() > maxFoldBytes {
			return "", false
		}
	}
	return b.String(), !want
}

// keyValue finds "'key' => value" (PHP) or "key: value" (JavaScript)
// inside a token range at any depth and returns the value's range.
func (e *extractor) keyValue(sp [2]int, key string) ([2]int, bool) {
	sep := "=>"
	if e.lang == langJS {
		sep = ":"
	}
	for j := sp[0]; j+1 < sp[1] && j < len(e.toks); j++ {
		t := e.toks[j]
		if (t.k == tStr && t.known && t.val == key || e.lang == langJS && t.is(tName, key)) && e.toks[j+1].punct(sep) {
			return [2]int{j + 2, e.exprStop(j+2, sp[1])}, true
		}
	}
	return [2]int{}, false
}

// valueRange is a range to read values from: the argument itself, or,
// when it is one variable, what that variable was last assigned.
func (e *extractor) valueRange(sp [2]int) [2]int {
	if sp[1]-sp[0] == 1 && e.isVarTok(e.toks[sp[0]]) {
		if r, ok := e.assigned(sp[0], e.toks[sp[0]].text); ok {
			return r
		}
	}
	return sp
}

// literalRange reports whether a range is an array or object literal.
func (e *extractor) literalRange(sp [2]int) bool {
	if sp[1] <= sp[0] {
		return false
	}
	t := e.toks[sp[0]]
	return t.punct("[") || t.is(tName, "array") || (e.lang == langJS && t.punct("{"))
}

// contains reports whether a token range holds a name (or string) for
// which match is true.
func (e *extractor) contains(sp [2]int, match func(tok) bool) bool {
	for j := sp[0]; j < sp[1] && j < len(e.toks); j++ {
		if match(e.toks[j]) {
			return true
		}
	}
	return false
}

// callbackBody finds the code a callback argument runs: a function
// literal in the argument, a function of the file named by a string,
// or a method named by array($this, 'name') or [ $this, 'name' ].
func (e *extractor) callbackBody(c *callSite, i int) ([2]int, string, bool) {
	sp := e.span(c, i)
	if sp[1] <= sp[0] {
		return [2]int{}, "", false
	}
	for j := sp[0]; j < sp[1]; j++ {
		t := e.toks[j]
		if t.is(tName, "function") || t.is(tName, "fn") || t.punct("=>") {
			for k := j; k < sp[1]; k++ {
				if e.toks[k].punct("{") {
					return [2]int{k + 1, min(e.st.close(k), sp[1])}, "closure", true
				}
			}
			// An arrow function with an expression body.
			if k := indexPunct(e.toks, j, sp[1], "=>"); k >= 0 {
				return [2]int{k + 1, sp[1]}, "closure", true
			}
			return [2]int{j, sp[1]}, "closure", true
		}
		if t.k == tPunct && t.text != "(" && t.text != "[" && t.text != "&" {
			break
		}
	}
	name, ok := argStr(c, i)
	method := false
	if !ok && e.literalRange(sp) {
		// array($this, 'name'): the last string names the method.
		for j := sp[1] - 1; j >= sp[0]; j-- {
			if t := e.toks[j]; t.k == tStr && t.known {
				name, ok, method = t.val, true, true
				break
			}
		}
	}
	if !ok || e.h == nil {
		return [2]int{}, name, false
	}
	if k := strings.LastIndex(name, "::"); k >= 0 {
		name, method = name[k+2:], true
	}
	key := name
	if e.lang == langPHP {
		key = strings.ToLower(strings.TrimPrefix(name, `\`))
	}
	idx := first(e.h.funcs[key])
	if method || idx < 0 {
		if m := first(e.h.methods[key]); m >= 0 {
			idx = m
		}
	}
	if idx < 0 {
		return [2]int{}, name, false
	}
	b := e.h.bodies[idx]
	return [2]int{b.start, b.end}, name, true
}

// indexPunct finds punctuation p in [i, end) or gives -1.
func indexPunct(toks []tok, i, end int, p string) int {
	for j := i; j < end && j < len(toks); j++ {
		if toks[j].punct(p) {
			return j
		}
	}
	return -1
}

// tokenLike reports whether an environment variable name looks like it
// holds a credential: NPM_TOKEN, GITHUB_TOKEN, AWS_*, *_SECRET, *_KEY
// and the like. NODE_ENV, PATH and HOME do not.
func tokenLike(name string) bool {
	n := strings.ToUpper(name)
	if strings.HasPrefix(n, "AWS_") {
		return true
	}
	for _, part := range strings.FieldsFunc(n, func(r rune) bool { return r == '_' || r == '-' || r == '.' }) {
		switch part {
		case "TOKEN", "SECRET", "SECRETS", "PASSWORD", "PASSWD", "PASS", "KEY", "APIKEY", "CREDENTIAL",
			"CREDENTIALS", "AUTH", "AUTHTOKEN", "PRIVATE", "PAT", "NPMRC":
			return true
		}
		if strings.HasSuffix(part, "TOKEN") || strings.HasSuffix(part, "SECRET") || strings.HasSuffix(part, "PASSWORD") {
			return true
		}
	}
	return false
}

// credTarget names the credential file a path reads, or "".
func credTarget(hints []string) string {
	for _, h := range hints {
		switch {
		case strings.Contains(h, "wp-config.php"):
			return "wp-config"
		case strings.Contains(h, ".npmrc"):
			return "npmrc"
		case strings.HasSuffix(h, "auth.json"):
			return "composer-auth"
		case strings.Contains(h, ".ssh"):
			return "ssh"
		case strings.Contains(h, ".git-credentials"):
			return "git-credentials"
		case strings.Contains(h, ".aws/credentials") || strings.Contains(h, ".aws\\credentials"):
			return "aws"
		}
	}
	return ""
}

// The write target classes of FWrite keys.
const (
	tgtWPConfig   = "wp-config"
	tgtHtaccess   = "htaccess"
	tgtMUPlugins  = "mu-plugins"
	tgtPluginsDir = "plugins-dir"
	tgtABSPath    = "abspath"
	tgtContentDir = "content-dir"
	tgtParentDir  = "parent-dir"
	tgtUploads    = "uploads"
	tgtOwn        = "own"
	tgtTemp       = "temp"
	tgtUnknown    = "unknown"
	tgtHome       = "homedir"
	tgtNpmrc      = "npmrc"
	tgtSSH        = "ssh"
	tgtGit        = "git"
	tgtCI         = "ci"
)

// writeTarget classifies where a write lands from the hints of its
// path. The most specific class wins: a file name (wp-config.php,
// .npmrc) over a folder (mu-plugins) over a base (ABSPATH).
func writeTarget(hints []string) string {
	has := func(pred func(string) bool) bool {
		for _, h := range hints {
			if pred(h) {
				return true
			}
		}
		return false
	}
	contains := func(subs ...string) bool {
		return has(func(h string) bool {
			for _, s := range subs {
				if strings.Contains(h, s) {
					return true
				}
			}
			return false
		})
	}
	is := func(names ...string) bool {
		return has(func(h string) bool {
			for _, n := range names {
				if h == n {
					return true
				}
			}
			return false
		})
	}
	switch {
	case contains("wp-config.php"):
		return tgtWPConfig
	case contains(".htaccess", ".user.ini"):
		return tgtHtaccess
	case contains(".npmrc", ".yarnrc"):
		return tgtNpmrc
	case contains(".ssh/", ".ssh\\") || is(".ssh"):
		return tgtSSH
	case contains(".github/workflows", ".gitlab-ci", ".circleci/", "azure-pipelines", ".travis.yml"):
		return tgtCI
	case contains(".git/", ".gitconfig", ".git-credentials") || is(".git"):
		return tgtGit
	case contains("mu-plugins") || is("wpmu_plugin_dir"):
		return tgtMUPlugins
	case contains("/plugins/", "wp-content/plugins") || is("wp_plugin_dir", "plugins"):
		return tgtPluginsDir
	case is("wp_upload_dir", "upload_dir") || contains("/uploads/", "wp-content/uploads") || is("uploads"):
		return tgtUploads
	case is("sys_get_temp_dir", "get_temp_dir", "wp_tempnam", "tmpfile", "tempnam", "os.tmpdir", "tmpdir") || contains("/tmp/") || is("/tmp"):
		return tgtTemp
	case is("os.homedir", "homedir", "process.env.home", "home", "userprofile") || has(func(h string) bool { return strings.HasPrefix(h, "~/") || h == "~" }):
		return tgtHome
	case contains("../", `..\`) || is(".."):
		return tgtParentDir
	case is("__dir__", "__file__", "__dirname", "__filename", "plugin_dir_path", "dirname", "get_template_directory", "get_stylesheet_directory", "process.cwd", "cwd"):
		return tgtOwn
	case is("wp_content_dir", "content_url", "wp-content"):
		return tgtContentDir
	case is("abspath", "get_home_path"):
		return tgtABSPath
	}
	return tgtUnknown
}

// pathExt is the extension of the last hint that has one: the file
// type a write creates.
func pathExt(hints []string) string {
	for i := len(hints) - 1; i >= 0; i-- {
		h := hints[i]
		if !strings.ContainsAny(h, "./") {
			continue
		}
		if ext := path.Ext(strings.TrimRight(h, " \t\"'")); ext != "" && len(ext) <= 8 && !strings.ContainsAny(ext, " /\\") {
			return ext
		}
	}
	return ""
}
