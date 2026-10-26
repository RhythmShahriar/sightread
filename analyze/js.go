// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"strings"

	"github.com/RhythmShahriar/sightread/core"
)

// JavaScript feature extraction. Module aliases are resolved by the
// evaluator (const cp = require('child_process'); cp.exec is
// child_process.exec), so the rules here match full paths.

// jsModules are the Node modules whose import is a feature on its own:
// they reach the shell, the file system, the network or the engine.
var jsModules = map[string]bool{
	"child_process": true, "fs": true, "net": true, "http": true, "https": true, "http2": true,
	"dns": true, "os": true, "vm": true, "worker_threads": true, "tls": true, "dgram": true,
}

// jsExecCalls are the calls that start a program.
var jsExecCalls = map[string]bool{
	"child_process.exec": true, "child_process.execSync": true, "child_process.spawn": true,
	"child_process.spawnSync": true, "child_process.execFile": true, "child_process.execFileSync": true,
	"child_process.fork": true,
}

// jsWrites are the fs calls that create or change a file, with the
// position of the target argument.
var jsWrites = map[string]int{
	"fs.writeFile": 0, "fs.writeFileSync": 0, "fs.appendFile": 0, "fs.appendFileSync": 0,
	"fs.createWriteStream": 0, "fs.copyFile": 1, "fs.copyFileSync": 1, "fs.rename": 1,
	"fs.renameSync": 1, "fs.cp": 1, "fs.cpSync": 1, "fs.symlink": 1, "fs.symlinkSync": 1,
	"fs.outputFile": 0, "fs.outputFileSync": 0,
}

// jsReads are the fs calls that read a file.
var jsReads = map[string]bool{
	"fs.readFile": true, "fs.readFileSync": true, "fs.createReadStream": true, "fs.open": true, "fs.openSync": true,
}

// jsSendRoots are packages and globals whose every call sends a
// request.
var jsSendRoots = map[string]bool{"axios": true, "got": true, "superagent": true, "needle": true, "node-fetch": true, "undici": true}

// jsSends are the other calls that send data over the network.
var jsSends = map[string]bool{
	"fetch": true, "http.request": true, "http.get": true, "https.request": true, "https.get": true,
	"http2.connect": true, "net.connect": true, "net.createConnection": true, "tls.connect": true,
	"dgram.createSocket": true, "XMLHttpRequest": true, "navigator.sendBeacon": true, "WebSocket": true,
	"request": true,
}

// jsEvalCalls run a string as code.
var jsEvalCalls = map[string]bool{
	"eval": true, "Function": true, "vm.runInNewContext": true, "vm.runInThisContext": true,
	"vm.runInContext": true, "vm.compileFunction": true, "vm.Script": true, "vm.SourceTextModule": true,
	"execScript": true,
}

// webpackGlobal is the body of the global object shim bundlers emit:
// new Function("return this")() runs no package text.
const webpackGlobal = "return this"

// jsName normalises a callee path: fs/promises is fs.
func jsName(name string) string {
	if strings.HasPrefix(name, "fs.promises.") {
		return "fs." + strings.TrimPrefix(name, "fs.promises.")
	}
	return name
}

func (e *extractor) jsCall(_ *scope, c *callSite) {
	name := jsName(c.name)
	root := name
	if k := strings.IndexByte(root, '.'); k > 0 {
		root = root[:k]
	}
	switch {
	case jsExecCalls[name]:
		e.callFeature(core.FCall, name, c, argAttrs(c))
	case jsEvalCalls[name]:
		e.jsEval(c, name)
	case jsTimers[name]:
		if e.stringArg(c, 0) {
			e.jsEval(c, name)
		}
	case name == "require" || name == "module.require":
		e.jsRequire(c)
	case jsReads[name]:
		e.credRead(c, name)
	case jsSends[name] || jsSendRoots[root] || strings.HasPrefix(name, "dns.resolve") || name == "dns.lookup" ||
		strings.HasPrefix(name, "dns.promises.resolve"):
		e.send(c, name, map[string]string{"channel": jsChannel(root)})
	}
	if pos, ok := jsWrites[name]; ok {
		e.write(c, pos, name)
	}
	e.jsDynCall(c, name)
}

func jsChannel(root string) string {
	switch root {
	case "net", "tls", "dgram", "WebSocket":
		return "socket"
	case "dns":
		return "dns"
	}
	return "http"
}

// stringArg reports whether argument i is a string: written, folded,
// built with + from a string or data. A function or a function's name
// is not.
func (e *extractor) stringArg(c *callSite, i int) bool {
	a := c.arg(i)
	if a.v.kind == vClosure || a.v.kind == vName {
		return false
	}
	if _, ok := a.v.str(); ok {
		return true
	}
	if a.t.any() {
		return true
	}
	return e.contains(e.span(c, i), func(t tok) bool { return t.k == tStr })
}

// jsEval records eval, Function, vm and string timers.
func (e *extractor) jsEval(c *callSite, name string) {
	i := 0
	if name == "Function" {
		// The body is the last argument; the others name parameters.
		i = max(len(c.args)-1, 0)
		if v, ok := argStr(c, i); ok && strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(v), ";")) == webpackGlobal {
			return
		}
	}
	a := map[string]string{"arg": e.argKind(c, i)}
	if src := sourceAttr(c.arg(i).t); src != "" {
		a["source"] = src
	}
	if e.contains(e.span(c, i), func(t tok) bool { return t.k == tName && (t.text == "atob" || t.text == "fromCharCode") }) {
		a["decode"] = "true"
	}
	if c.via != "" {
		a["via"] = c.via
	}
	e.callFeature(core.FEval, name, c, a)
}

// jsRequire records a require of something that is not a written
// module name: code loaded from data.
func (e *extractor) jsRequire(c *callSite) {
	if len(c.args) == 0 {
		return
	}
	sp := e.span(c, 0)
	if sp[1]-sp[0] == 1 && e.toks[sp[0]].k == tStr {
		return
	}
	if _, ok := argStr(c, 0); ok {
		return // a built but known name: the import scan reports it
	}
	src := sourceAttr(c.arg(0).t)
	if src == "" {
		src = "unknown"
	}
	e.callFeature(core.FDynCall, "require", c, map[string]string{"source": src, "via": "require"})
}

// jsDynCall records a call through a global looked up by a built or
// data name: window['ev'+'al'](...), global[x](...).
func (e *extractor) jsDynCall(c *callSite, name string) {
	if !c.dynamic || c.via != "" {
		return
	}
	src := sourceAttr(c.callee.t)
	switch {
	case name != "" && c.folded && e.globalLookup(c):
		if src == "" {
			src = "folded"
		}
		e.callFeature(core.FDynCall, name, c, map[string]string{"source": src})
	case name == "" && src != "":
		e.callFeature(core.FDynCall, "variable function", c, map[string]string{"source": src})
	}
}

// globalLookup reports whether a call's callee starts at a global
// object (window, global, globalThis, self) or a built string.
func (e *extractor) globalLookup(c *callSite) bool {
	t := at(e.toks, c.pos)
	return jsRoots[t.text] || t.k == tStr || t.punct("(") || t.punct("[")
}

// jsScan reads imports and environment reads from the token stream.
func (e *extractor) jsScan() {
	toks := e.toks
	envAlias := map[string]bool{}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch {
		case t.k == tName && (t.text == "require" || t.text == "import") && at(toks, i+1).punct("(") &&
			at(toks, i+2).k == tStr && at(toks, i+3).punct(")") && !at(toks, i-1).punct("."):
			e.jsImport(i, at(toks, i+2).val)
		case t.k == tName && t.text == "from" && at(toks, i+1).k == tStr:
			e.jsImport(i, toks[i+1].val)
		case t.k == tName && t.text == "import" && at(toks, i+1).k == tStr:
			e.jsImport(i, toks[i+1].val)
		case t.is(tName, "process") && at(toks, i+1).punct(".") && at(toks, i+2).is(tName, "env") && !at(toks, i-1).punct("."):
			i = e.jsEnv(i, i+3, envAlias)
		case t.k == tName && envAlias[t.text] && !at(toks, i-1).punct(".") && !at(toks, i+1).punct("="):
			e.jsEnv(i, i+1, envAlias)
		}
	}
}

// jsImport records an import of a watched module.
func (e *extractor) jsImport(i int, mod string) {
	m := nodeModule(mod)
	if k := strings.IndexByte(m, '/'); k > 0 && !strings.HasPrefix(m, "@") {
		m = m[:k]
	}
	if jsModules[m] {
		t := e.toks[i]
		e.col.addAt(t.off, core.FCall, "import:"+m, t.line, t.line, e.fnAt(i), map[string]string{"module": attrText(mod)})
	}
}

// jsEnv reads what follows process.env (or an alias of it) at j: one
// variable, a destructuring of several, an alias, or the whole
// environment handed somewhere. It returns the index to go on from.
func (e *extractor) jsEnv(i, j int, alias map[string]bool) int {
	toks := e.toks
	t := toks[i]
	read := func(name string) {
		e.note(i, readEnv)
		e.col.addAt(t.off, core.FEnvRead, attrText(name), t.line, t.line, e.fnAt(i), map[string]string{"fn": "process.env"})
	}
	switch n := at(toks, j); {
	case n.punct(".") || n.punct("?."):
		if v := at(toks, j+1); v.k == tName && tokenLike(v.text) {
			read(v.text)
		}
		return j + 1
	case n.punct("["):
		if v := at(toks, j+1); v.k == tStr && at(toks, j+2).punct("]") {
			if tokenLike(v.val) {
				read(v.val)
			}
			return j + 2
		}
		read("*") // process.env[name]: any variable
		return j
	}
	p := at(toks, i-1)
	switch {
	case p.punct("=") && at(toks, i-2).punct("}"):
		// const { NPM_TOKEN, HOME } = process.env
		open := int(e.st.match[i-2])
		if open < 0 || open >= i-2 {
			break
		}
		for k := open + 1; k < i-2; k++ {
			if v := toks[k]; v.k == tName && !at(toks, k-1).punct(":") && tokenLike(v.text) {
				read(v.text)
			}
		}
	case p.punct("=") && at(toks, i-2).k == tName:
		alias[at(toks, i-2).text] = true // const env = process.env
	case p.punct(":") && at(toks, i-2).is(tName, "env"), p.punct("..."), p.punct("||") || p.punct("??"):
		// { env: process.env } or { ...process.env }: a child gets the
		// environment it would inherit anyway.
	default:
		read("*")
	}
	return j - 1
}
