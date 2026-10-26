// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"bytes"
	"encoding/json"
	"path"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/secrets"

	"github.com/RhythmShahriar/sightread/core"
)

// npm install hooks: the package.json scripts npm runs by itself plus
// the shell text of a script (AnalyzeText).

// npmScripts are the scripts npm runs on install or publish, in the
// order the features are reported.
var npmScripts = []string{"preinstall", "install", "postinstall", "prepare", "prepublish"}

// maxScript is the most bytes of a script FHook carries in its
// "script" attribute, for the detector to analyse.
const maxScript = 4 << 10

// packageJSONFeatures returns the install hooks of a package.json:
// FHook "npm:<script>" with the script text; "npm:gyp" when npm would
// run node-gyp by itself (a binding.gyp or "gypfile": true and no
// install or preinstall script). hasGyp says the tree has a binding.gyp
// next to the file.
func packageJSONFeatures(p string, src []byte, hasGyp bool) []core.Feature {
	var pkg struct {
		Scripts map[string]json.RawMessage `json:"scripts"`
		Gypfile json.RawMessage            `json:"gypfile"`
	}
	if json.Unmarshal(src, &pkg) != nil {
		return nil
	}
	col := newCollector(p, pathContext(p), newLineIndex(src))
	line := func(key string) int {
		k := bytes.Index(src, []byte(`"`+key+`"`))
		if s := bytes.Index(src, []byte(`"scripts"`)); key != "gypfile" && s >= 0 {
			if k2 := bytes.Index(src[s:], []byte(`"`+key+`"`)); k2 >= 0 {
				k = s + k2
			}
		}
		if k < 0 {
			return 1
		}
		return bytes.Count(src[:k], []byte("\n")) + 1
	}
	installs := false
	for _, name := range npmScripts {
		var text string
		if json.Unmarshal(pkg.Scripts[name], &text) != nil || strings.TrimSpace(text) == "" {
			continue
		}
		if name == "install" || name == "preinstall" {
			installs = true
		}
		l := line(name)
		col.add(core.FHook, "npm:"+name, l, l, "", map[string]string{"script": scriptAttr(text)})
	}
	gyp := hasGyp || strings.TrimSpace(string(pkg.Gypfile)) == "true"
	if gyp && !installs {
		l := line("gypfile")
		col.add(core.FHook, "npm:gyp", l, l, "", map[string]string{"script": "node-gyp rebuild", "implicit": "true"})
	}
	return col.out
}

// scriptAttr is a script's text with secrets masked, cut to maxScript.
func scriptAttr(s string) string {
	s = secrets.Redact(s)
	if len(s) > maxScript {
		cut := maxScript
		for cut > 0 && s[cut]&0xc0 == 0x80 {
			cut--
		}
		s = s[:cut]
	}
	return s
}

// textFeatures is AnalyzeText: PHP and JavaScript text is analysed as a
// file of that kind; anything else is read as shell lines, the way npm
// runs a script.
func textFeatures(kind core.FileKind, p string, src []byte) []core.Feature {
	switch kind {
	case core.KindPHP:
		return codeFeatures(langPHP, p, src, pathContext(p))
	case core.KindJS:
		return codeFeatures(langJS, p, src, pathContext(p))
	}
	return shellFeatures(p, src)
}

// fetchers are commands that download; shells are commands that run
// what they are given.
var (
	fetchers = map[string]bool{"curl": true, "wget": true, "fetch": true, "iwr": true, "invoke-webrequest": true, "invoke-restmethod": true}
	shells   = map[string]bool{
		"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "node": true, "nodejs": true,
		"python": true, "python3": true, "perl": true, "ruby": true, "php": true, "iex": true,
		"invoke-expression": true, "pwsh": true, "powershell": true, "source": true, "eval": true, ".": true,
	}
)

// shellFeatures reads shell text: a download piped or substituted into
// a shell is FFlow remote->exec; "node <file>" and "sh <file>" are
// FInclude of that file so the detector can analyse it too; "node -e
// <code>" is analysed as JavaScript.
func shellFeatures(p string, src []byte) []core.Feature {
	ctx := pathContext(p)
	lines := newLineIndex(src)
	col := newCollector(p, ctx, lines)
	var out []core.Feature
	for n, text := range strings.Split(string(src), "\n") {
		line := n + 1
		col.addTextHosts(ctx, text, -1, line, "", false, false)
		for _, pipe := range shellCommands(text) {
			fetched := ""
			for _, seg := range pipe {
				words := commandWords(shellWords(seg))
				if len(words) == 0 {
					continue
				}
				cmd := strings.ToLower(path.Base(words[0]))
				switch {
				case fetchers[cmd]:
					fetched = cmd
				case shells[cmd] && fetched != "":
					col.add(core.FFlow, sourceNames[srcRemote]+"->"+sinkExec, line, line, "",
						map[string]string{"source": fetched, "sink": cmd})
				case shells[cmd]:
					if f := substitutedFetch(seg); f != "" {
						col.add(core.FFlow, sourceNames[srcRemote]+"->"+sinkExec, line, line, "",
							map[string]string{"source": f, "sink": cmd})
					}
				}
				out = append(out, shellRun(col, p, ctx, line, cmd, words)...)
			}
		}
	}
	out = append(out, col.out...)
	sortFeatures(out)
	return out
}

// substitutedFetch finds a download run through command or process
// substitution: bash <(curl ...), sh -c "$(wget ...)", eval `curl ...`.
func substitutedFetch(seg string) string {
	l := strings.ToLower(seg)
	for f := range fetchers {
		for _, open := range []string{"$(", "<(", "`"} {
			if strings.Contains(l, open+f+" ") || strings.Contains(l, open+" "+f+" ") {
				return f
			}
		}
	}
	return ""
}

// shellRun handles a command that runs a file of the package or inline
// JavaScript.
func shellRun(col *collector, p, ctx string, line int, cmd string, words []string) []core.Feature {
	var via string
	switch cmd {
	case "node", "nodejs":
		via = "node"
	case "sh", "bash", "zsh", "dash", "source", ".":
		via = "sh"
	default:
		return nil
	}
	for i := 1; i < len(words); i++ {
		w := words[i]
		switch {
		case via == "node" && (w == "-e" || w == "--eval" || w == "-p" || w == "--print") && i+1 < len(words):
			fs := codeFeatures(langJS, p, []byte(words[i+1]), ctx)
			for k := range fs {
				fs[k].Ev.Line, fs[k].Ev.EndLine = line, line
			}
			return fs
		case strings.HasPrefix(w, "-"):
			if via == "node" && (w == "-r" || w == "--require" || w == "--import") {
				i++ // the next word is a module preloaded, not the script
			}
			continue
		}
		target := strings.TrimLeft(path.Clean("/"+w), "/")
		if target == "" || strings.Contains(w, "://") || strings.ContainsAny(w, "$`") {
			return nil
		}
		ext := path.Ext(target)
		if via == "sh" && ext != ".sh" && ext != ".bash" {
			return nil
		}
		col.add(core.FInclude, attrText(target), line, line, "", map[string]string{"via": via, "ext": ext})
		return nil
	}
	return nil
}

// commandWords drops what runs before the command proper: variable
// assignments and wrappers such as env, cross-env, sudo and exec.
func commandWords(words []string) []string {
	for len(words) > 0 {
		w := words[0]
		switch {
		case strings.Contains(w, "=") && !strings.HasPrefix(w, "="):
		case w == "env" || w == "cross-env" || w == "sudo" || w == "exec" || w == "time" || w == "nohup" || w == "command":
		default:
			return words
		}
		words = words[1:]
	}
	return words
}

// shellCommands splits a line into pipelines (split at unquoted ;, &&
// and ||) of commands (split at unquoted |).
func shellCommands(line string) [][]string {
	var out [][]string
	var pipe []string
	var cur strings.Builder
	quote := byte(0)
	flush := func(endPipe bool) {
		if s := strings.TrimSpace(cur.String()); s != "" {
			pipe = append(pipe, s)
		}
		cur.Reset()
		if endPipe && len(pipe) > 0 {
			out = append(out, pipe)
			pipe = nil
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			} else if c == '\\' && quote == '"' && i+1 < len(line) {
				cur.WriteByte(c)
				i++
				c = line[i]
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '\\' && i+1 < len(line):
			cur.WriteByte(c)
			i++
			c = line[i]
		case c == '#' && (i == 0 || line[i-1] == ' ' || line[i-1] == '\t'):
			flush(true)
			return out
		case c == ';':
			flush(true)
			continue
		case (c == '&' || c == '|') && i+1 < len(line) && line[i+1] == c:
			flush(true)
			i++
			continue
		case c == '|':
			flush(false)
			continue
		}
		cur.WriteByte(c)
	}
	flush(true)
	return out
}

// shellWords splits a command into words, removing quotes.
func shellWords(cmd string) []string {
	var out []string
	var cur strings.Builder
	in, quote := false, byte(0)
	for i := 0; i < len(cmd); i++ {
		c := cmd[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
				continue
			}
			if c == '\\' && quote == '"' && i+1 < len(cmd) {
				i++
				c = cmd[i]
			}
			cur.WriteByte(c)
		case c == '\'' || c == '"':
			quote, in = c, true
		case c == ' ' || c == '\t' || c == '\r':
			if in {
				out = append(out, cur.String())
				cur.Reset()
				in = false
			}
		case c == '\\' && i+1 < len(cmd):
			i++
			cur.WriteByte(cmd[i])
			in = true
		default:
			cur.WriteByte(c)
			in = true
		}
	}
	if in {
		out = append(out, cur.String())
	}
	return out
}
