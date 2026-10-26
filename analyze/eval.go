// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import "strings"

// The evaluator walks one function body of a normalised stream. It is
// not a parser for either language: it reads expressions well enough to
// fold built strings (fold.go) and to follow tainted values from a
// source to a sink (flow.go). It always moves forward, so a broken or
// hostile file costs linear time at worst.

// source is a kind of untrusted or hidden data.
type source uint8

const (
	srcRemote  source = iota // fetched over the network
	srcRequest               // sent by the visitor of the site
	srcDecode                // produced by a decoder (base64_decode, atob...)
	srcEnv                   // read from the environment
	nSources
)

var sourceNames = [nSources]string{"remote", "request", "decode", "env"}

// Parameter markers sit above the real sources: while a function's
// summary is computed its parameters carry these bits, so the summary
// can say "parameter 2 reaches eval".
const (
	paramBase = 8
	maxParams = 16
	realMask  = 1<<paramBase - 1
)

// origin is where a source first entered a value.
type origin struct {
	line int
	name string
}

// taint is the set of sources a value may come from.
type taint struct {
	bits uint32
	from [nSources]origin
}

func (t taint) has(s source) bool { return t.bits&(1<<s) != 0 }

func (t taint) any() bool { return t.bits != 0 }

func (t *taint) add(s source, line int, name string) {
	if !t.has(s) {
		t.bits |= 1 << s
		t.from[s] = origin{line, name}
	}
}

func (t taint) union(o taint) taint {
	for s := range nSources {
		if o.has(s) {
			t.add(s, o.from[s].line, o.from[s].name)
		}
	}
	t.bits |= o.bits &^ realMask
	return t
}

func paramTaint(i int) taint {
	if i >= maxParams {
		return taint{}
	}
	return taint{bits: 1 << (paramBase + i)}
}

// res is what evaluating an expression gives.
type res struct {
	v   value
	t   taint
	pat [2]int // a destructuring pattern's token range, when set
}

// param is one parameter of a function or closure.
type param struct {
	name string
	idx  int
}

// closure is a function literal met inside a body: it runs inline, in
// the enclosing body's variables.
type closure struct {
	params     []param
	start, end int  // token range of the body
	expr       bool // an arrow function whose body is one expression
	running    bool
}

// callSite is one call the evaluator met.
type callSite struct {
	name    string // the callee: a PHP function name in lower case or a JS path
	method  string // for a method call, the method name
	folded  bool   // the name was built (concatenation, a variable, a callback argument)
	dynamic bool   // the callee was not written as a plain name
	via     string // the function that called this one by name, e.g. call_user_func
	callee  res    // the callee expression itself
	recv    *res   // the receiver of a method call
	args    []res
	spans   [][2]int // each argument's token range
	isNew   bool
	line    int
	pos     int // token index where the callee expression starts
}

// arg returns argument i or an empty result.
func (c *callSite) arg(i int) res {
	if i < len(c.args) {
		return c.args[i]
	}
	return res{}
}

// argsTaint is the union of the arguments' taint.
func (c *callSite) argsTaint() taint {
	var t taint
	for _, a := range c.args {
		t = t.union(a.t)
	}
	return t
}

// hooks are what flow.go plugs into the evaluator: what a call or read
// means and where sinks are.
type hooks interface {
	// call sees every call and returns the taint its result gets
	// beyond plain propagation (a source, a summary).
	call(s *scope, c *callSite) taint
	// include sees a PHP include or require of an expression; sp is
	// the expression's token range.
	include(s *scope, r res, sp [2]int, line int, kind string)
	// read returns the taint of reading a name: a PHP superglobal
	// ($_GET) or a JS path (process.env).
	read(s *scope, name string, line int) taint
	// propagates reports whether a call's result carries its
	// arguments' taint (json_decode, trim, JSON.parse...).
	propagates(name string) bool
}

// fileCtx is what every body of one file shares.
type fileCtx struct {
	st      *stream
	h       hooks
	aliases map[string]string // JS: local name -> module path
	skip    map[int]int       // start of a nested declaration -> index after it
	budget  int               // tokens closures may still run, against blowup
}

// scope evaluates one body.
type scope struct {
	f     *fileCtx
	toks  []tok
	lang  lang
	env   map[string]value // variables holding a folded value
	vars  map[string]taint // variables holding tainted data
	ret   taint            // what the body returns
	fold  folder
	depth int
	fn    string // the body's name, for evidence
}

const maxEvalDepth = 128

func newScope(f *fileCtx, fn string) *scope {
	return &scope{f: f, toks: f.st.toks, lang: f.st.lang, env: map[string]value{}, vars: map[string]taint{}, fn: fn}
}

func (s *scope) at(i int) tok {
	if i < len(s.toks) {
		return s.toks[i]
	}
	return tok{k: tPunct, text: ""}
}

// closeAt is the closing bracket of the one at i, bounded by end.
func (s *scope) closeAt(i, end int) int { return min(s.f.st.close(i), end) }

// walk evaluates the statements in [i, end).
func (s *scope) walk(i, end int) {
	for i < end {
		if j, ok := s.f.skip[i]; ok && j > i {
			i = j
			continue
		}
		s.fold.steps = 0
		j := s.stmt(i, end)
		if j <= i {
			j = i + 1
		}
		if s.f.st.clk.tick(j - i) {
			return
		}
		i = j
	}
}

func (s *scope) stmt(i, end int) int {
	t := s.toks[i]
	switch {
	case t.k == tTag || t.k == tPunct && len(t.text) == 1 && strings.Contains(";,{})]:", t.text):
		return i + 1
	case t.k != tName:
		_, j := s.expr(i, end)
		return j
	}
	php := s.lang == langPHP
	next := s.at(i + 1)
	switch t.text {
	case "return":
		r, j := s.expr(i+1, end)
		s.ret = s.ret.union(r.t)
		return j
	case "if", "elseif", "while", "switch", "catch", "for", "foreach", "with", "declare":
		if !next.punct("(") || i+1 >= end {
			return i + 1
		}
		k := s.closeAt(i+1, end)
		switch {
		case t.text == "foreach":
			s.loopBind(i+2, k, "as")
		case t.text == "for" && !php:
			if !s.loopBind(i+2, k, "of") && !s.loopBind(i+2, k, "in") {
				s.walk(i+2, k)
			}
		default:
			s.walk(i+2, k)
		}
		return k + 1
	case "case":
		// Skip the label: its colon is not a ternary.
		for j := i + 1; j < end; j++ {
			if s.toks[j].punct(":") {
				return j + 1
			}
			if c := s.toks[j]; c.punct("(") || c.punct("[") || c.punct("{") {
				j = s.closeAt(j, end)
			}
		}
		return end
	case "echo", "print":
		if php {
			return s.exprList(i+1, end)
		}
	case "var", "let", "const":
		if !php {
			return s.exprList(i+1, end)
		}
		return s.toSemicolon(i, end)
	case "global", "namespace", "use", "goto":
		if php {
			return s.toSemicolon(i, end)
		}
	case "import":
		if !php && !next.punct("(") && !next.punct(".") {
			for j := i + 1; j < end; j++ {
				if c := s.toks[j]; c.k == tStr || c.punct(";") {
					return j + 1
				}
			}
			return end
		}
	case "else", "try", "finally", "do", "default", "export", "public", "private", "protected",
		"final", "abstract", "readonly", "static":
		if t.text != "static" || (!next.is(tName, "function") && !next.is(tName, "fn")) {
			return i + 1
		}
	}
	_, j := s.expr(i, end)
	return j
}

func (s *scope) toSemicolon(i, end int) int {
	for j := i; j < end; j++ {
		if c := s.toks[j]; c.punct(";") || c.k == tTag {
			return j + 1
		}
	}
	return end
}

func (s *scope) exprList(i, end int) int {
	for i < end {
		_, j := s.expr(i, end)
		if j < end && s.toks[j].punct(",") {
			i = j + 1
			continue
		}
		if j == i {
			return i + 1
		}
		return j
	}
	return end
}

// loopBind handles "foreach ($a as $k => $v)" and "for (const x of a)":
// the loop variables get the taint of the collection. It reports false
// when [i, k) holds no such keyword at depth zero.
func (s *scope) loopBind(i, k int, kw string) bool {
	at := -1
	for j := i; j < k; j++ {
		c := s.toks[j]
		if c.is(tName, kw) {
			at = j
			break
		}
		if c.punct("(") || c.punct("[") || c.punct("{") {
			j = s.closeAt(j, k)
		}
	}
	if at < 0 {
		return false
	}
	var coll res
	var lhs [2]int
	if kw == "as" {
		coll, _ = s.expr(i, at)
		lhs = [2]int{at + 1, k}
	} else {
		coll, _ = s.expr(at+1, k)
		lhs = [2]int{i, at}
	}
	s.bindPattern(lhs, coll.t)
	return true
}

// bindPattern gives every variable named in the token range t: PHP
// $vars, or JS binding names (followed by , } ] = or the end).
func (s *scope) bindPattern(r [2]int, t taint) {
	for j := r[0]; j < r[1]; j++ {
		c := s.toks[j]
		switch {
		case c.k == tVar:
			s.vars[c.text] = t
			delete(s.env, c.text)
		case c.k == tName && s.lang == langJS && !isJSKeyword(c.text):
			n := s.at(j + 1)
			if j+1 >= r[1] || n.punct(",") || n.punct("}") || n.punct("]") || n.punct("=") {
				s.vars[c.text] = t
				delete(s.env, c.text)
			}
		}
	}
}

// expr evaluates a full expression. A function literal left over (not
// passed to a call) runs here, so code inside it is still read.
func (s *scope) expr(i, end int) (res, int) {
	r, j := s.exprArg(i, end)
	s.settle(&r)
	return r, j
}

// settle runs a pending closure with untainted parameters.
func (s *scope) settle(r *res) {
	if r.v.kind == vClosure && r.v.cl != nil {
		r.t = r.t.union(s.runClosure(r.v.cl, nil))
	}
}

// exprArg evaluates an expression and leaves a closure value unrun, for
// the caller to run with the right parameter taint.
func (s *scope) exprArg(i, end int) (res, int) {
	if i >= end {
		return res{}, i
	}
	if s.depth > maxEvalDepth {
		return res{}, s.skipExpr(i, end)
	}
	s.depth++
	defer func() { s.depth-- }()
	r, i := s.unary(i, end)
	for i < end {
		op := s.toks[i]
		if !s.binary(op) {
			break
		}
		i++
		r2, j := s.unary(i, end)
		if j == i {
			if i < end && s.binary(s.toks[i]) {
				continue // "?:" and the like
			}
			break
		}
		r = s.combine(op.text, r, r2)
		i = j
	}
	return r, i
}

// skipExpr moves past an expression too deep to evaluate.
func (s *scope) skipExpr(i, end int) int {
	for i < end {
		c := s.toks[i]
		switch {
		case c.punct("(") || c.punct("[") || c.punct("{"):
			i = s.closeAt(i, end) + 1
			continue
		case c.punct(",") || c.punct(";") || c.punct(")") || c.punct("]") || c.punct("}") || c.k == tTag:
			return i
		}
		i++
	}
	return end
}

var phpBinary = map[string]bool{
	".": true, "+": true, "-": true, "*": true, "/": true, "%": true, "**": true,
	"==": true, "!=": true, "===": true, "!==": true, "<>": true, "<": true, ">": true,
	"<=": true, ">=": true, "<=>": true, "&&": true, "||": true, "??": true, "&": true,
	"|": true, "^": true, "<<": true, ">>": true, "?": true, ":": true,
}

var jsBinary = map[string]bool{
	"+": true, "-": true, "*": true, "/": true, "%": true, "**": true,
	"==": true, "!=": true, "===": true, "!==": true, "<": true, ">": true,
	"<=": true, ">=": true, "&&": true, "||": true, "??": true, "&": true,
	"|": true, "^": true, "<<": true, ">>": true, ">>>": true, "?": true, ":": true,
}

func (s *scope) binary(t tok) bool {
	switch t.k {
	case tPunct:
		if s.lang == langPHP {
			return phpBinary[t.text]
		}
		return jsBinary[t.text]
	case tName:
		switch t.text {
		case "instanceof":
			return true
		case "and", "or", "xor":
			return s.lang == langPHP
		case "in":
			return s.lang == langJS
		}
	}
	return false
}

// combine applies a binary operator.
func (s *scope) combine(op string, a, b res) res {
	s.settle(&a)
	s.settle(&b)
	switch op {
	case ".":
		if s.lang == langPHP {
			return res{v: s.fold.concat(a.v, b.v, false), t: a.t.union(b.t)}
		}
	case "+":
		if s.lang == langJS {
			return res{v: s.fold.concat(a.v, b.v, true), t: a.t.union(b.t)}
		}
	case "==", "!=", "===", "!==", "<>", "<", ">", "<=", ">=", "<=>", "instanceof", "in", "and", "or", "xor":
		return res{} // a boolean or a number carries no data
	case "&&", "||":
		if s.lang == langPHP {
			return res{}
		}
	case "?":
		return res{t: b.t} // the condition does not flow into the result
	}
	return res{t: a.t.union(b.t)}
}

func (s *scope) unary(i, end int) (res, int) {
	if i >= end {
		return res{}, i
	}
	t := s.toks[i]
	switch t.k {
	case tPunct:
		switch t.text {
		case "!":
			r, j := s.unary(i+1, end)
			s.settle(&r)
			return res{}, j
		case "-", "+", "~", "++", "--", "&":
			r, j := s.unary(i+1, end)
			s.settle(&r)
			if t.text == "-" && r.v.kind == vNum {
				return res{v: value{kind: vNum, n: -r.v.n}, t: r.t}, j
			}
			return res{t: r.t}, j
		case "@", "...":
			return s.unary(i+1, end)
		}
	case tOther:
		if strings.HasPrefix(t.text, "(") { // a PHP cast
			r, j := s.unary(i+1, end)
			if t.text != "(string)" {
				r.v = unknown
			}
			return r, j
		}
	case tName:
		switch t.text {
		case "new":
			return s.postfix(i+1, end, true)
		case "typeof", "void", "delete":
			if s.lang == langJS {
				r, j := s.unary(i+1, end)
				s.settle(&r)
				return res{}, j
			}
		case "await", "yield", "clone", "throw":
			return s.unary(i+1, end)
		case "print":
			if s.lang == langPHP {
				return s.exprArg(i+1, end)
			}
		case "include", "include_once", "require", "require_once":
			if s.lang == langPHP {
				r, j := s.exprArg(i+1, end)
				s.settle(&r)
				s.f.h.include(s, r, [2]int{i + 1, j}, t.line, t.text)
				return res{}, j
			}
		}
	}
	return s.postfix(i, end, false)
}

var assignOps = map[string]bool{
	"=": true, ".=": true, "+=": true, "-=": true, "*=": true, "/=": true, "%=": true,
	"??=": true, "||=": true, "&&=": true, "|=": true, "&=": true, "^=": true, "**=": true,
	"<<=": true, ">>=": true, ">>>=": true,
}

// jsRoots are the global objects: window["eval"] is eval.
var jsRoots = map[string]bool{"window": true, "global": true, "globalThis": true, "self": true}

// postfix evaluates a primary expression and its calls, indexes, member
// accesses and assignment.
func (s *scope) postfix(i, end int, isNew bool) (res, int) {
	start := i
	r, j, lv := s.primary(i, end)
	if j == i {
		return r, j
	}
	weak := false // lv names a whole array or object of which one part is assigned
	plain := r.v.kind == vName && s.toks[start].k == tName && !strings.HasPrefix(s.toks[start].text, "(")
	var recv *res
	method := ""
	for j < end {
		t := s.toks[j]
		switch {
		case t.punct("("):
			k := s.closeAt(j, end)
			args, spans := s.args(j+1, k)
			r = s.call(r, recv, method, args, spans, plain, isNew, start)
			isNew = false
			recv, method, lv = nil, "", ""
			// require("m") gives the module, as plain as its name.
			plain = r.v.kind == vName && s.lang == langJS
			j = k + 1
		case t.punct("["):
			k := s.closeAt(j, end)
			idx, _ := s.expr(j+1, k)
			r = s.index(r, idx, t.line)
			weak = true
			recv, method, plain = nil, "", false
			j = k + 1
		case t.punct("->") || t.punct("?->") || t.punct("::") || t.punct(".") || t.punct("?."):
			if s.lang == langPHP && (t.text == "." || t.text == "?.") {
				return r, j
			}
			if s.lang == langJS && t.text != "." && t.text != "?." {
				return r, j
			}
			n := s.at(j + 1)
			if j+1 >= end {
				return r, j + 1
			}
			name := ""
			step := 2
			var extra taint
			switch {
			case n.k == tName:
				name = n.text
			case n.k == tVar:
				name = "" // $obj->$name: the name is data
				plain = false
				extra = s.vars[n.text]
			case n.punct("{"):
				k := s.closeAt(j+1, end)
				s.expr(j+2, k)
				step = k + 1 - j
				plain = false
			default:
				return r, j + 1
			}
			base := r
			recv = &base
			method = name
			r = s.member(r, name, t.line)
			r.t = r.t.union(extra)
			if lv != "" && name != "" {
				lv += "." + name
				r.t = r.t.union(s.vars[lv])
				if v, ok := s.env[lv]; ok {
					r.v = v
				}
			} else {
				lv = ""
			}
			j += step
		case t.punct("++") || t.punct("--"):
			j++
		case assignOps[t.text] && t.k == tPunct && (lv != "" || r.pat[1] > 0):
			rhs, k := s.exprArg(j+1, end)
			s.settle(&rhs)
			if r.pat[1] > 0 {
				s.bindPattern(r.pat, rhs.t)
				return rhs, k
			}
			s.assign(lv, t.text, r, rhs, weak)
			return rhs, k
		default:
			return r, j
		}
	}
	return r, j
}

func (s *scope) assign(lv, op string, old, rhs res, weak bool) {
	var v value
	var t taint
	switch op {
	case "=":
		v, t = rhs.v, rhs.t
	case ".=", "+=":
		v = s.fold.concat(old.v, rhs.v, op == "+=" && s.lang == langJS)
		t = old.t.union(rhs.t)
	default:
		t = old.t.union(rhs.t)
	}
	if weak {
		s.vars[lv] = s.vars[lv].union(t)
		delete(s.env, lv)
		return
	}
	s.vars[lv] = t
	if v.kind == vUnknown {
		delete(s.env, lv)
	} else {
		s.env[lv] = v
	}
}

// member reads name from r.
func (s *scope) member(r res, name string, line int) res {
	out := res{t: r.t}
	if r.v.kind == vName && name != "" {
		path := r.v.s + "." + name
		if s.lang == langPHP {
			path = r.v.s + "::" + name
		}
		out.v = value{kind: vName, s: path}
		out.t = out.t.union(s.f.h.read(s, path, line))
	}
	return out
}

// index reads r[idx] on line.
func (s *scope) index(r, idx res, line int) res {
	out := res{t: r.t}
	switch r.v.kind {
	case vArr:
		if n, ok := idx.v.num(); ok && n >= 0 && n < int64(len(r.v.arr)) {
			out.v = r.v.arr[n]
		}
	case vStr:
		if n, ok := idx.v.num(); ok && n >= 0 && n < int64(len(r.v.s)) && s.fold.step() {
			out.v = strVal(r.v.s[n : n+1])
		}
	case vName:
		key, ok := idx.v.str()
		switch {
		case ok && jsRoots[r.v.s] && s.lang == langJS:
			out.v = value{kind: vName, s: key}
		case ok && s.lang == langJS:
			out.v = value{kind: vName, s: r.v.s + "." + key}
			out.t = out.t.union(s.f.h.read(s, out.v.s, line))
		case jsRoots[r.v.s] || r.v.s == "this":
			// window[name] with a name from data: the callee is that data.
			out.t = out.t.union(idx.t)
		}
	}
	return out
}

func (s *scope) args(i, k int) ([]res, [][2]int) {
	var out []res
	var spans [][2]int
	for i < k {
		r, j := s.exprArg(i, k)
		if j == i {
			j = i + 1
		}
		// An unclosed bracket inside the argument lets the expression
		// run one past k.
		j = min(j, k)
		out = append(out, r)
		spans = append(spans, [2]int{i, j})
		for j < k && !s.toks[j].punct(",") {
			j++
		}
		i = j + 1
	}
	return out, spans
}

// phpCallbacks are PHP functions that call a function given by name, with
// the position of that argument.
var phpCallbacks = map[string]int{
	"call_user_func": 0, "call_user_func_array": 0, "array_map": 0, "usort": 1,
	"uasort": 1, "uksort": 1, "array_filter": 1, "array_walk": 1, "array_reduce": 1,
	"register_shutdown_function": 0, "forward_static_call": 0, "forward_static_call_array": 0,
	"iterator_apply": 1, "set_error_handler": 0, "set_exception_handler": 0,
	"spl_autoload_register": 0, "ob_start": 0, "array_walk_recursive": 1,
}

// call evaluates a call once its callee and arguments are known.
func (s *scope) call(callee res, recv *res, method string, args []res, spans [][2]int, plain, isNew bool, pos int) res {
	line := s.toks[pos].line
	c := &callSite{callee: callee, recv: recv, method: method, args: args, spans: spans, isNew: isNew, line: line, pos: pos}
	switch callee.v.kind {
	case vName:
		c.name = callee.v.s
		if s.lang == langJS {
			c.name = trimRoot(c.name)
		}
		c.dynamic = !plain
		c.folded = !plain
	case vStr:
		if printable(callee.v.s) {
			c.name = callee.v.s
			if s.lang == langPHP {
				c.name = strings.ToLower(strings.TrimPrefix(c.name, `\`))
			}
		}
		c.dynamic, c.folded = true, true
	case vClosure:
		// An immediately called function literal or a variable holding
		// one: its parameters get the arguments' taint.
		ps := make([]taint, len(args))
		for i, a := range args {
			s.settle(&a)
			ps[i] = a.t
		}
		ret := s.runClosure(callee.v.cl, ps)
		return res{t: ret}
	default:
		// A method with a written name ($this->run()) is not dynamic;
		// a variable function ($f()) or method ($o->$m()) is.
		c.dynamic = recv == nil || method == ""
	}
	if recv != nil && method == "" {
		c.name = ""
	}
	// Fold the result when the callee is a foldable built-in.
	vals := make([]value, len(args))
	for i, a := range args {
		vals[i] = a.v
	}
	var out res
	switch {
	case s.lang == langPHP && c.name != "":
		out.v = s.fold.callPHP(c.name, vals)
	case s.lang == langJS && recv != nil && method != "":
		out.v = s.fold.methodJS(recv.v, method, vals)
		if out.v.kind == vUnknown && c.name != "" {
			out.v = s.fold.callJS(c.name, vals)
		}
	case s.lang == langJS && c.name != "":
		out.v = s.fold.callJS(c.name, vals)
	}
	// Values the later code needs: the file a handle writes to, the
	// module require() returns.
	switch {
	case s.lang == langPHP && c.name == "fopen" && len(args) > 0:
		target, ok := args[0].v.str()
		if !ok {
			target = literalTail(s, spans[0])
		}
		out.v = value{kind: vName, s: "fopen:" + target}
	case s.lang == langJS && c.name == "require" && len(args) > 0:
		if m, ok := args[0].v.str(); ok {
			out.v = value{kind: vName, s: nodeModule(m)}
		}
	}
	// Taint of the result.
	if s.f.h.propagates(c.name) || (recv != nil && s.f.h.propagates(method)) {
		out.t = out.t.union(c.argsTaint())
	}
	if recv != nil {
		out.t = out.t.union(recv.t)
	}
	out.t = out.t.union(s.f.h.call(s, c))
	// Callbacks: a PHP function called by name, or JS f.call(...).
	cbParams := out.t
	if s.lang == langPHP {
		if pos, ok := phpCallbacks[c.name]; ok && pos < len(args) {
			out.t = out.t.union(s.callback(c, pos))
			for i, a := range args {
				if i != pos {
					cbParams = cbParams.union(a.t)
				}
			}
		}
	} else if recv != nil && (method == "call" || method == "apply") && recv.v.kind == vName {
		d := &callSite{name: trimRoot(recv.v.s), folded: c.folded, dynamic: c.dynamic, via: method,
			callee: *recv, line: line, pos: pos}
		if len(args) > 1 {
			d.args, d.spans = args[1:], spans[1:]
		}
		out.t = out.t.union(s.f.h.call(s, d))
	}
	// Function literals among the arguments run now, their parameters
	// carrying what the call hands them: https.get(url, res => ...) gets
	// a remote res, res.on("data", d => ...) a remote d.
	for _, a := range args {
		if a.v.kind == vClosure && a.v.cl != nil {
			ps := make([]taint, len(a.v.cl.params))
			for i := range ps {
				ps[i] = cbParams
			}
			out.t = out.t.union(s.runClosure(a.v.cl, ps))
		}
	}
	return out
}

// callback handles call_user_func and friends: a callback given by name
// is a call of that function with the other arguments; one given by
// tainted data is a dynamic call of that data.
func (s *scope) callback(c *callSite, pos int) taint {
	cb := c.args[pos]
	d := &callSite{via: c.name, callee: cb, line: c.line, pos: c.pos, dynamic: true}
	rest := 0
	if c.name == "call_user_func" || c.name == "call_user_func_array" || c.name == "forward_static_call" || c.name == "forward_static_call_array" {
		rest = pos + 1
		if rest < len(c.args) {
			d.args, d.spans = c.args[rest:], c.spans[rest:]
			if c.name == "call_user_func_array" && len(d.args) == 1 {
				// The arguments arrive as one array.
				d.args = []res{{t: d.args[0].t}}
			}
		}
	} else {
		for i, a := range c.args {
			if i != pos {
				d.args = append(d.args, a)
				d.spans = append(d.spans, c.spans[i])
			}
		}
	}
	if name, ok := cb.v.str(); ok && printable(name) {
		d.name = strings.ToLower(strings.TrimPrefix(name, `\`))
		sp := c.spans[pos]
		d.folded = sp[1]-sp[0] != 1 || s.toks[sp[0]].k != tStr
	} else if cb.v.kind != vClosure {
		d.folded = false
	} else {
		return taint{}
	}
	return s.f.h.call(s, d)
}

func trimRoot(path string) string {
	for r := range jsRoots {
		if strings.HasPrefix(path, r+".") {
			return path[len(r)+1:]
		}
	}
	return path
}

// runClosure evaluates a function literal's body with its parameters
// bound to ps and returns the taint of what it returns.
func (s *scope) runClosure(cl *closure, ps []taint) taint {
	if cl.running || s.f.budget <= 0 {
		return taint{}
	}
	s.f.budget -= cl.end - cl.start + 1
	cl.running = true
	defer func() { cl.running = false }()
	for _, p := range cl.params {
		var t taint
		if p.idx < len(ps) {
			t = ps[p.idx]
		}
		s.vars[p.name] = t
		delete(s.env, p.name)
	}
	if cl.expr {
		r, _ := s.expr(cl.start, cl.end)
		return r.t
	}
	saved := s.ret
	s.ret = taint{}
	s.walk(cl.start, cl.end)
	ret := s.ret
	s.ret = saved
	return ret
}

// primary evaluates the smallest expression at i and returns it, the
// index after it and its lvalue key ("" when it cannot be assigned).
func (s *scope) primary(i, end int) (res, int, string) {
	t := s.toks[i]
	switch t.k {
	case tStr:
		if t.known {
			return res{v: strVal(t.val)}, i + 1, ""
		}
		return res{}, i + 1, ""
	case tNum:
		return res{v: numLit(t.text)}, i + 1, ""
	case tOther:
		return res{}, i + 1, ""
	case tVar:
		return s.phpVar(i, end)
	case tPunct:
		return s.punctPrimary(i, end)
	case tName:
		if s.lang == langPHP {
			return s.phpName(i, end)
		}
		return s.jsName(i, end)
	}
	return res{}, i, ""
}

func (s *scope) phpVar(i, end int) (res, int, string) {
	t := s.toks[i]
	name := t.text
	if name == "$" && i+1 < end && s.toks[i+1].punct("{") {
		// ${'a'.'b'}: a variable named by an expression.
		k := s.closeAt(i+1, end)
		r, _ := s.expr(i+2, k)
		if n, ok := r.v.str(); ok {
			name = "$" + n
			return res{v: s.env[name], t: s.vars[name].union(s.f.h.read(s, name, t.line))}, k + 1, name
		}
		return res{t: r.t}, k + 1, ""
	}
	if strings.HasPrefix(name, "$$") {
		// $$x: the variable named by $x's value.
		inner := name[1:]
		if n, ok := s.env[inner].str(); ok {
			name = "$" + n
			return res{v: s.env[name], t: s.vars[name]}, i + 1, name
		}
		return res{t: s.vars[inner]}, i + 1, ""
	}
	r := res{v: s.env[name], t: s.vars[name].union(s.f.h.read(s, name, t.line))}
	return r, i + 1, name
}

func (s *scope) punctPrimary(i, end int) (res, int, string) {
	t := s.toks[i]
	switch t.text {
	case "(":
		k := s.closeAt(i, end)
		if s.lang == langJS && s.at(k+1).punct("=>") && k+1 < end {
			return s.arrow(i+1, k, k+2, end)
		}
		r := s.sequence(i+1, k)
		return r, k + 1, ""
	case "[":
		k := s.closeAt(i, end)
		if n := s.at(k + 1); n.punct("=") && k+1 < end {
			return res{pat: [2]int{i + 1, k}}, k + 1, ""
		}
		return s.arrayLit(i+1, k), k + 1, ""
	case "{":
		k := s.closeAt(i, end)
		if s.lang == langJS {
			if n := s.at(k + 1); n.punct("=") && k+1 < end {
				return res{pat: [2]int{i + 1, k}}, k + 1, ""
			}
			return s.objectLit(i+1, k), k + 1, ""
		}
		s.walk(i+1, k)
		return res{}, k + 1, ""
	}
	return res{}, i, ""
}

// sequence evaluates "a, b, c" and gives the last value, as the comma
// operator does: (0, eval)(x) calls eval.
func (s *scope) sequence(i, k int) res {
	var r res
	for i < k {
		var j int
		r, j = s.exprArg(i, k)
		if j == i {
			j = i + 1
		}
		if j < k && s.toks[j].punct(",") {
			s.settle(&r)
		}
		i = j
		for i < k && s.toks[i].punct(",") {
			i++
		}
	}
	return r
}

func (s *scope) arrayLit(i, k int) res {
	var out res
	arr := value{kind: vArr}
	for i < k {
		r, j := s.expr(i, k)
		if j < k && s.toks[j].punct("=>") {
			r, j = s.expr(j+1, k)
		}
		if j == i {
			j = i + 1
		}
		arr.arr = append(arr.arr, r.v)
		out.t = out.t.union(r.t)
		for j < k && !s.toks[j].punct(",") {
			j++
		}
		i = j + 1
	}
	out.v = arr
	return out
}

// objectLit evaluates a JavaScript object literal: its values' taint is
// the object's.
func (s *scope) objectLit(i, k int) res {
	var out res
	for i < k {
		t := s.toks[i]
		j := i
		switch {
		case t.punct("..."):
			r, e := s.expr(i+1, k)
			out.t = out.t.union(r.t)
			j = e
		default:
			// Skip modifiers, then the key.
			for j < k && s.toks[j].k == tName && (s.toks[j].text == "async" || s.toks[j].text == "get" || s.toks[j].text == "set") &&
				j+1 < k && !s.toks[j+1].punct(":") && !s.toks[j+1].punct("(") && !s.toks[j+1].punct(",") {
				j++
			}
			if j < k && s.toks[j].punct("*") {
				j++
			}
			if j < k && s.toks[j].punct("[") {
				e := s.closeAt(j, k)
				s.expr(j+1, e)
				j = e + 1
			} else {
				j++
			}
			switch n := s.at(j); {
			case j < k && n.punct(":"):
				r, e := s.expr(j+1, k)
				out.t = out.t.union(r.t)
				j = e
			case j < k && n.punct("("):
				pe := s.closeAt(j, k)
				if b := s.at(pe + 1); b.punct("{") && pe+1 < k {
					be := s.closeAt(pe+1, k)
					cl := &closure{params: s.jsParams(j+1, pe), start: pe + 2, end: be}
					s.runClosure(cl, nil)
					j = be + 1
				} else {
					j = pe + 1
				}
			default:
				if t.k == tName {
					out.t = out.t.union(s.vars[t.text])
				}
			}
		}
		if j <= i {
			j = i + 1
		}
		for j < k && !s.toks[j].punct(",") {
			j++
		}
		i = j + 1
	}
	return out
}

func (s *scope) phpName(i, end int) (res, int, string) {
	t := s.toks[i]
	n := s.at(i + 1)
	switch t.text {
	case "function", "fn":
		return s.phpClosure(i, end)
	case "static":
		if n.is(tName, "function") || n.is(tName, "fn") {
			return s.phpClosure(i+1, end)
		}
	case "array", "list":
		if n.punct("(") && i+1 < end {
			k := s.closeAt(i+1, end)
			if t.text == "list" || (s.at(k+1).punct("=") && k+1 < end) {
				return res{pat: [2]int{i + 2, k}}, k + 1, ""
			}
			return s.arrayLit(i+2, k), k + 1, ""
		}
	case "isset", "empty", "exit", "die", "unset":
		if n.punct("(") && i+1 < end {
			k := s.closeAt(i+1, end)
			s.walk(i+2, k)
			return res{}, k + 1, ""
		}
		return res{}, i + 1, ""
	case "true", "false", "null":
		return res{}, i + 1, ""
	case "match":
		if n.punct("(") && i+1 < end {
			k := s.closeAt(i+1, end)
			s.walk(i+2, k)
			if b := s.at(k + 1); b.punct("{") && k+1 < end {
				e := s.closeAt(k+1, end)
				s.walk(k+2, e)
				return res{}, e + 1, ""
			}
			return res{}, k + 1, ""
		}
	case "class":
		// An anonymous class: read its body for calls.
		for j := i + 1; j < end; j++ {
			if s.toks[j].punct("(") {
				j = s.closeAt(j, end)
				continue
			}
			if s.toks[j].punct("{") {
				e := s.closeAt(j, end)
				s.walk(j+1, e)
				return res{}, e + 1, ""
			}
		}
		return res{}, end, ""
	}
	return res{v: value{kind: vName, s: t.text}}, i + 1, ""
}

// phpClosure reads "function (...) use (...) {...}" and "fn (...) =>
// expr", returning the closure unrun.
func (s *scope) phpClosure(i, end int) (res, int, string) {
	j := i + 1
	if s.at(j).punct("&") {
		j++
	}
	if s.at(j).k == tName { // a named function inside an expression
		j++
	}
	if !s.at(j).punct("(") || j >= end {
		return res{}, i + 1, ""
	}
	pe := s.closeAt(j, end)
	cl := &closure{params: phpParams(s.toks, j+1, pe)}
	j = pe + 1
	if s.at(j).is(tName, "use") && s.at(j+1).punct("(") {
		j = s.closeAt(j+1, end) + 1
	}
	// Skip a return type up to the body.
	for j < end && !s.toks[j].punct("{") && !s.toks[j].punct("=>") && !s.toks[j].punct(";") {
		j++
	}
	switch {
	case j < end && s.toks[j].punct("{"):
		be := s.closeAt(j, end)
		cl.start, cl.end = j+1, be
		return res{v: value{kind: vClosure, cl: cl}}, be + 1, ""
	case j < end && s.toks[j].punct("=>"):
		e := s.exprEnd(j+1, end)
		cl.start, cl.end, cl.expr = j+1, e, true
		return res{v: value{kind: vClosure, cl: cl}}, e, ""
	}
	return res{}, j, ""
}

// exprEnd finds where an arrow function's expression body ends: the
// first , ; ) ] } or tag at depth zero.
func (s *scope) exprEnd(i, end int) int {
	for j := i; j < end; j++ {
		c := s.toks[j]
		switch {
		case c.punct("(") || c.punct("[") || c.punct("{"):
			j = s.closeAt(j, end)
		case c.punct(",") || c.punct(";") || c.punct(")") || c.punct("]") || c.punct("}") || c.k == tTag:
			return j
		}
	}
	return end
}

// phpParams lists the $parameters at depth zero of [i, k).
func phpParams(toks []tok, i, k int) []param {
	var out []param
	idx, depth := 0, 0
	for j := i; j < k; j++ {
		c := toks[j]
		switch {
		case c.punct("(") || c.punct("[") || c.punct("{"):
			depth++
		case c.punct(")") || c.punct("]") || c.punct("}"):
			depth--
		case c.punct(",") && depth == 0:
			idx++
		case c.k == tVar && depth == 0 && (j == i || !toks[j-1].punct("=")):
			out = append(out, param{c.text, idx})
		}
	}
	return out
}

// jsParams lists the binding names of a parameter list, each with the
// index of the parameter it belongs to.
func (s *scope) jsParams(i, k int) []param { return jsParams(s.toks, i, k) }

func jsParams(toks []tok, i, k int) []param {
	var out []param
	idx, depth := 0, 0
	for j := i; j < k; j++ {
		c := toks[j]
		switch {
		case c.punct("(") || c.punct("[") || c.punct("{"):
			depth++
		case c.punct(")") || c.punct("]") || c.punct("}"):
			depth--
		case c.punct(",") && depth == 0:
			idx++
		case c.k == tName && !isJSKeyword(c.text):
			var n tok
			if j+1 < k {
				n = toks[j+1]
			}
			if j+1 >= k || n.punct(",") || n.punct("}") || n.punct("]") || n.punct("=") || n.punct(")") {
				// After "=" a name is a default value, not a binding.
				if j > i && toks[j-1].punct("=") {
					continue
				}
				out = append(out, param{c.text, idx})
			}
		}
	}
	return out
}

func isJSKeyword(s string) bool {
	switch s {
	case "var", "let", "const", "this", "null", "true", "false", "undefined", "new", "typeof",
		"function", "return", "async", "await", "of", "in", "class", "static", "get", "set":
		return true
	}
	return false
}

func (s *scope) jsName(i, end int) (res, int, string) {
	t := s.toks[i]
	n := s.at(i + 1)
	switch t.text {
	case "function":
		return s.jsFunction(i, end)
	case "async":
		if n.is(tName, "function") {
			return s.jsFunction(i+1, end)
		}
		if n.punct("(") || (n.k == tName && s.at(i+2).punct("=>")) {
			return s.primary(i+1, end)
		}
	case "class":
		for j := i + 1; j < end; j++ {
			if s.toks[j].punct("{") {
				return res{}, s.closeAt(j, end) + 1, ""
			}
		}
		return res{}, end, ""
	case "true", "false", "null", "undefined":
		return res{}, i + 1, ""
	case "this":
		return res{v: value{kind: vName, s: "this"}, t: s.vars["this"]}, i + 1, "this"
	}
	if n.punct("=>") && i+1 < end && !isJSKeyword(t.text) {
		return s.arrow(i, i+1, i+2, end)
	}
	if v, ok := s.env[t.text]; ok {
		return res{v: v, t: s.vars[t.text]}, i + 1, t.text
	}
	path := t.text
	if a, ok := s.f.aliases[t.text]; ok {
		path = a
	}
	r := res{v: value{kind: vName, s: path}, t: s.vars[t.text].union(s.f.h.read(s, path, t.line))}
	return r, i + 1, t.text
}

// arrow reads an arrow function whose parameters are in [ps, pe) and
// whose body starts at b.
func (s *scope) arrow(ps, pe, b, end int) (res, int, string) {
	cl := &closure{params: s.jsParams(ps, pe)}
	if b < end && s.toks[b].punct("{") {
		be := s.closeAt(b, end)
		cl.start, cl.end = b+1, be
		return res{v: value{kind: vClosure, cl: cl}}, be + 1, ""
	}
	e := s.exprEnd(b, end)
	cl.start, cl.end, cl.expr = b, e, true
	return res{v: value{kind: vClosure, cl: cl}}, e, ""
}

func (s *scope) jsFunction(i, end int) (res, int, string) {
	j := i + 1
	if s.at(j).punct("*") {
		j++
	}
	if s.at(j).k == tName {
		j++
	}
	if !s.at(j).punct("(") || j >= end {
		return res{}, i + 1, ""
	}
	pe := s.closeAt(j, end)
	cl := &closure{params: s.jsParams(j+1, pe)}
	if b := pe + 1; b < end && s.toks[b].punct("{") {
		be := s.closeAt(b, end)
		cl.start, cl.end = b+1, be
		return res{v: value{kind: vClosure, cl: cl}}, be + 1, ""
	}
	return res{}, pe + 1, ""
}

// literalTail is the last known string literal in a token range: in
// ABSPATH . 'wp-config.php' it is 'wp-config.php'.
func literalTail(s *scope, sp [2]int) string {
	last := ""
	for j := sp[0]; j < sp[1] && j < len(s.toks); j++ {
		if t := s.toks[j]; t.k == tStr && t.known {
			last = t.val
		}
	}
	return last
}
