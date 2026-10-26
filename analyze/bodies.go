// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import "strings"

// body is one function, method or the top level of a file. Closures and
// arrow functions are not bodies of their own: they run inline in the
// body that holds them, so a value they capture keeps its taint.
type body struct {
	name       string // for evidence: "fetch_ver_info", "Plugin::run", "Api.send"; "" for the top level
	key        string // lookup key for calls: a PHP name in lower case, a JS name
	method     bool
	params     []param
	start, end int // token range of the statements
}

// splitBodies finds the named functions and methods of a stream. skip
// maps the first token of each declaration (and of each class) to the
// index after it, so the body that holds it steps over it. The top
// level comes first in the result.
func splitBodies(st *stream) ([]body, map[int]int) {
	bodies := []body{{start: 0, end: len(st.toks)}}
	skip := map[int]int{}
	if st.lang == langPHP {
		bodies = splitPHP(st, bodies, skip)
	} else {
		bodies = splitJS(st, bodies, skip)
	}
	return bodies, skip
}

func at(toks []tok, i int) tok {
	if i >= 0 && i < len(toks) {
		return toks[i]
	}
	return tok{k: tPunct}
}

func splitPHP(st *stream, bodies []body, skip map[int]int) []body {
	toks := st.toks
	type class struct {
		name string
		end  int
	}
	var classes []class
	for i := 0; i < len(toks); i++ {
		for len(classes) > 0 && i > classes[len(classes)-1].end {
			classes = classes[:len(classes)-1]
		}
		t := toks[i]
		if t.k != tName {
			continue
		}
		prev := at(toks, i-1)
		if prev.punct("::") || prev.punct("->") || prev.punct("?->") {
			continue
		}
		switch t.text {
		case "class", "trait", "interface", "enum":
			if prev.is(tName, "new") || at(toks, i+1).k != tName {
				continue
			}
			for j := i + 2; j < len(toks); j++ {
				if toks[j].punct(";") {
					break
				}
				if toks[j].punct("{") {
					e := st.close(j)
					classes = append(classes, class{toks[i+1].raw, e})
					skip[i] = e + 1
					break
				}
			}
		case "function":
			j := i + 1
			if at(toks, j).punct("&") {
				j++
			}
			if at(toks, j).k != tName || !at(toks, j+1).punct("(") {
				continue
			}
			pe := st.close(j + 1)
			k := pe + 1
			for k < len(toks) && !toks[k].punct("{") && !toks[k].punct(";") {
				k++
			}
			if k >= len(toks) || toks[k].punct(";") {
				continue // abstract or interface method
			}
			be := st.close(k)
			b := body{name: toks[j].raw, key: toks[j].text, params: phpParams(toks, j+2, pe), start: k + 1, end: be}
			if len(classes) > 0 {
				b.name = classes[len(classes)-1].name + "::" + b.name
				b.method = true
			} else {
				skip[i] = be + 1
			}
			bodies = append(bodies, b)
		}
	}
	return bodies
}

// jsStatementStart reports whether the token before i lets a function
// declaration start at i.
func jsStatementStart(toks []tok, i int) bool {
	p := at(toks, i-1)
	if i == 0 {
		return true
	}
	return p.punct(";") || p.punct("{") || p.punct("}") || p.is(tName, "export") || p.is(tName, "default") ||
		p.is(tName, "async") || p.is(tName, "else") || p.punct(")")
}

func splitJS(st *stream, bodies []body, skip map[int]int) []body {
	toks := st.toks
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.k != tName || at(toks, i-1).punct(".") || at(toks, i-1).punct("?.") {
			continue
		}
		switch t.text {
		case "class":
			bodies = jsClass(st, i, bodies, skip)
		case "function":
			if !jsStatementStart(toks, i) {
				continue
			}
			j := i + 1
			if at(toks, j).punct("*") {
				j++
			}
			if at(toks, j).k != tName || !at(toks, j+1).punct("(") {
				continue
			}
			pe := st.close(j + 1)
			if !at(toks, pe+1).punct("{") {
				continue
			}
			be := st.close(pe + 1)
			bodies = append(bodies, body{name: toks[j].raw, key: toks[j].text, params: jsParams(toks, j+2, pe), start: pe + 2, end: be})
			skip[i] = be + 1
			if at(toks, i-1).is(tName, "async") {
				skip[i-1] = be + 1
			}
		case "const", "let", "var":
			// const f = function (...) {...} and const f = (...) => {...}
			// are named functions in all but syntax.
			if at(toks, i+1).k != tName || !at(toks, i+2).punct("=") {
				continue
			}
			name := toks[i+1]
			v := i + 3
			if at(toks, v).is(tName, "async") {
				v++
			}
			var ps, pe, b int
			switch {
			case at(toks, v).is(tName, "function"):
				p := v + 1
				if at(toks, p).punct("*") {
					p++
				}
				if at(toks, p).k == tName {
					p++
				}
				if !at(toks, p).punct("(") {
					continue
				}
				ps, pe = p+1, st.close(p)
				b = pe + 1
			case at(toks, v).punct("("):
				ps, pe = v+1, st.close(v)
				if !at(toks, pe+1).punct("=>") {
					continue
				}
				b = pe + 2
			case at(toks, v).k == tName && at(toks, v+1).punct("=>"):
				ps, pe = v, v+1
				b = v + 2
			default:
				continue
			}
			if !at(toks, b).punct("{") {
				continue
			}
			be := st.close(b)
			if !endsDeclaration(at(toks, be+1)) {
				continue // an immediately called function and the like
			}
			bodies = append(bodies, body{name: name.raw, key: name.text, params: jsParams(toks, ps, pe), start: b + 1, end: be})
			skip[i] = be + 1
		}
	}
	return bodies
}

func endsDeclaration(t tok) bool {
	return t.text == "" || t.punct(";") || t.punct(",") || t.punct("}") || t.k == tName
}

// jsClass registers the methods of the class whose keyword is at i.
// Field initialisers become bodies of their own, named after the class.
func jsClass(st *stream, i int, bodies []body, skip map[int]int) []body {
	toks := st.toks
	name := ""
	j := i + 1
	if n := at(toks, j); n.k == tName && n.text != "extends" {
		name = n.raw
		j++
	}
	for j < len(toks) && !toks[j].punct("{") {
		if toks[j].punct("(") || toks[j].punct("[") {
			j = st.close(j)
		}
		j++
	}
	if j >= len(toks) {
		return bodies
	}
	e := st.close(j)
	if jsStatementStart(toks, i) {
		skip[i] = e + 1
	}
	prefix := name
	if prefix == "" {
		prefix = "(class)"
	}
	for m := j + 1; m < e; {
		if toks[m].punct(";") {
			m++
			continue
		}
		k := m
		for k < e && toks[k].k == tName && isModifier(toks[k].text) && !at(toks, k+1).punct("(") && !at(toks, k+1).punct("=") {
			k++
		}
		if at(toks, k).punct("*") {
			k++
		}
		member := ""
		switch t := at(toks, k); {
		case t.k == tName:
			member = t.raw
			k++
		case t.k == tStr:
			member = t.val
			k++
		case t.punct("["):
			k = st.close(k) + 1
			member = "[computed]"
		case t.punct("{"): // a static block
			be := st.close(k)
			bodies = append(bodies, body{name: prefix, start: k + 1, end: be})
			m = be + 1
			continue
		default:
			m = k + 1
			continue
		}
		if at(toks, k).punct("(") {
			pe := st.close(k)
			if at(toks, pe+1).punct("{") {
				be := st.close(pe + 1)
				bodies = append(bodies, body{name: prefix + "." + member, key: member, method: true,
					params: jsParams(toks, k+1, pe), start: pe + 2, end: be})
				m = be + 1
				continue
			}
		}
		fe := fieldEnd(st, k, e)
		bodies = append(bodies, body{name: prefix, start: m, end: fe})
		m = max(fe, m+1)
	}
	return bodies
}

func isModifier(s string) bool {
	switch s {
	case "static", "async", "get", "set", "accessor", "readonly", "public", "private", "protected":
		return true
	}
	return false
}

// fieldEnd finds the end of a class field: a semicolon, or a line break
// where the expression cannot go on.
func fieldEnd(st *stream, i, e int) int {
	toks := st.toks
	for j := i; j < e; j++ {
		t := toks[j]
		switch {
		case t.punct(";"):
			return j + 1
		case t.punct("(") || t.punct("[") || t.punct("{"):
			j = min(st.close(j), e)
			continue
		}
		if j > i && t.line > toks[j-1].line && !continues(toks[j-1]) && !continues(t) {
			return j
		}
	}
	return e
}

// continues reports whether an expression goes on across a line break
// next to t.
func continues(t tok) bool {
	return t.k == tPunct && !strings.Contains(")]}", t.text) && t.text != "++" && t.text != "--"
}

// jsAliases maps local names to the modules they hold: const cp =
// require("child_process"), const { exec } = require("child_process"),
// import https from "https", import { get as g } from "https".
func jsAliases(st *stream) map[string]string {
	toks := st.toks
	out := map[string]string{}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch {
		case t.is(tName, "require") && at(toks, i+1).punct("(") && at(toks, i+2).k == tStr && at(toks, i+3).punct(")"):
			path := nodeModule(toks[i+2].val)
			j := i + 4
			for at(toks, j).punct(".") && at(toks, j+1).k == tName {
				path += "." + toks[j+1].text
				j += 2
			}
			if !at(toks, i-1).punct("=") {
				continue
			}
			lhs := at(toks, i-2)
			switch {
			case lhs.k == tName:
				out[lhs.text] = path
			case lhs.punct("}") && i-2 < len(st.match) && st.match[i-2] >= 0:
				bindImports(toks, st.match[i-2]+1, i-2, path, ":", out)
			}
		case t.is(tName, "import") && !at(toks, i+1).punct("(") && !at(toks, i+1).punct("."):
			from := -1
			for j := i + 1; j < len(toks) && j < i+256; j++ {
				if toks[j].is(tName, "from") && at(toks, j+1).k == tStr {
					from = j
					break
				}
				if toks[j].punct(";") || toks[j].k == tStr {
					break
				}
			}
			if from < 0 {
				continue
			}
			mod := nodeModule(toks[from+1].val)
			for j := i + 1; j < from; j++ {
				c := toks[j]
				switch {
				case c.punct("{"):
					e := min(st.close(j), from)
					bindImports(toks, j+1, e, mod, "as", out)
					j = e
				case c.punct("*") && at(toks, j+1).is(tName, "as") && at(toks, j+2).k == tName:
					out[toks[j+2].text] = mod
					j += 2
				case c.k == tName && c.text != "type":
					out[c.text] = mod
				}
			}
		}
	}
	// Second order: const exec = cp.exec.
	for i := 2; i+1 < len(toks); i++ {
		if toks[i].k != tName || !toks[i-1].punct("=") || toks[i-2].k != tName {
			continue
		}
		base, ok := out[toks[i].text]
		if !ok || !at(toks, i+1).punct(".") {
			continue
		}
		path := base
		j := i + 1
		for at(toks, j).punct(".") && at(toks, j+1).k == tName {
			path += "." + toks[j+1].text
			j += 2
		}
		out[toks[i-2].text] = path
	}
	return out
}

// bindImports reads "a, b as c" (sep "as") or "a, b: c" (sep ":") in
// [i, e) and maps each local name to mod.<exported name>.
func bindImports(toks []tok, i, e int, mod, sep string, out map[string]string) {
	for j := i; j < e; j++ {
		c := toks[j]
		if c.k != tName {
			continue
		}
		n := at(toks, j+1)
		if (sep == "as" && n.is(tName, "as")) || (sep == ":" && n.punct(":")) {
			if l := at(toks, j+2); l.k == tName && j+2 < e {
				out[l.text] = mod + "." + c.text
				j += 2
			}
			continue
		}
		out[c.text] = mod + "." + c.text
	}
}

// nodeModule normalises a module name: "node:fs" is "fs" and
// "fs/promises" is "fs".
func nodeModule(m string) string {
	m = strings.TrimPrefix(m, "node:")
	if m == "fs/promises" {
		return "fs"
	}
	return m
}
