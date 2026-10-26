// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package meta

import (
	"context"
	"io"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/detect/code"
)

// The signals of the install time detector.
const (
	SigInstallScriptNew = "npm-install-script-new"
	SigComposerPlugin   = "composer-plugin-new"
	SigAutoloadFiles    = "composer-autoload-files"
)

// lifecycleScripts are the npm scripts that run when a package is
// installed (prepare also runs for git and local installs).
var lifecycleScripts = []string{"preinstall", "install", "postinstall", "prepare"}

// The manifests install time findings point at.
const (
	npmManifest      = "package.json"
	composerManifest = "composer.json"
	bindingGyp       = "binding.gyp"
)

// maxScriptFile is the most of one file an install script names that is
// read for analysis.
const maxScriptFile = 4 << 20

func init() { core.RegisterDetector(installDetector{}) }

// installDetector reports code that runs when the package is installed:
// new or changed npm install scripts and binding.gyp, Composer plugins
// and event hooks plus new autoload.files entries (PRD 12.1, qa.md b10,
// b11, b15, b16). It also hands the code an install script runs to the
// code detectors, so a postinstall that downloads and runs a script is
// reported as remote-fetch-exec even when the file it runs is not new.
type installDetector struct{}

func (installDetector) Info() core.DetectorInfo {
	return core.DetectorInfo{Name: "meta-install", Signals: []string{
		SigInstallScriptNew, SigComposerPlugin, SigAutoloadFiles,
	}}
}

func (installDetector) Detect(ctx context.Context, s *core.Subject, emit func(core.Finding)) {
	out := newEmitter(s, emit)
	if s.New == nil {
		return
	}
	switch s.Update.Eco {
	case core.NPM:
		keys := changedInstallScripts(s)
		for _, k := range keys {
			f := newFinding(SigInstallScriptNew, scriptEvidence(s, k))
			f.File = npmManifest
			out.send(f)
		}
		gyp := newBindingGyp(s)
		if gyp {
			f := newFinding(SigInstallScriptNew, "binding.gyp added: npm builds it with node-gyp at install")
			f.File = bindingGyp
			out.send(f)
		}
		if len(keys) > 0 || gyp {
			installCode(ctx, s, keys, emit)
		}
	case core.Composer:
		for _, f := range composerHookFindings(s) {
			out.send(f)
		}
		for _, f := range autoloadFindings(s) {
			out.send(f)
		}
	}
}

// collapse folds runs of white space, so re-indenting a script is no
// change.
func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

// changedInstallScripts lists the lifecycle scripts that are new or
// changed in the candidate and not covered by a guard.
func changedInstallScripts(s *core.Subject) []string {
	var old map[string]string
	if s.Old != nil {
		old = s.Old.Scripts
	}
	var out []string
	for _, k := range lifecycleScripts {
		// The guards read the raw text: collapse would turn a newline,
		// which the shell runs as a second command, into a space.
		raw, rawOld := s.New.Scripts[k], old[k]
		nv, ov := collapse(raw), collapse(rawOld)
		switch {
		case nv == "" || nv == ov:
		case nodeGyp(raw) && (nodeGyp(rawOld) || ov == "" && hadBindingGyp(s)):
			// One native build command swapped for another, or the
			// implicit node-gyp rebuild of binding.gyp written out.
		case k == "prepare" && benignPrepare(raw, s.Old, s.New):
		default:
			out = append(out, k)
		}
	}
	return out
}

// scriptEvidence is "postinstall: node setup.js" for a new script and
// "postinstall changed: node setup.js" for a changed one.
func scriptEvidence(s *core.Subject, k string) string {
	label := k + ": "
	if s.Old != nil && strings.TrimSpace(s.Old.Scripts[k]) != "" {
		label = k + " changed: "
	}
	return label + collapse(s.New.Scripts[k])
}

// nativeBuild are the commands that build a native addon from source or
// fetch its prebuilt binary.
var nativeBuild = []string{
	"node-gyp rebuild", "node-gyp-build", "node-pre-gyp install", "prebuild-install",
	"cmake-js compile", "cmake-js rebuild", "node-gyp configure",
}

// nodeGyp reports whether every command of script is a native build
// with nothing but plain flags after it. Anything the shell could turn
// into a second program (substitution, backticks, redirection) makes it
// no native build, so "node-gyp rebuild $(node x.js)" is not one.
func nodeGyp(script string) bool {
	if hasShellMeta(script) {
		return false
	}
	cmds := commands(script)
	if len(cmds) == 0 {
		return false
	}
	for _, c := range cmds {
		ok := false
		for _, b := range nativeBuild {
			if c == b || strings.HasPrefix(c, b+" ") && plainFlags(strings.Fields(c[len(b):])) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// hasShellMeta reports text the shell runs or redirects beyond the
// plain command: $( ), ${ }, backticks and < or >.
func hasShellMeta(script string) bool {
	return strings.ContainsAny(script, "`<>") || strings.Contains(script, "$(") || strings.Contains(script, "${")
}

// plainFlags reports whether args are only flags ("--release",
// "--target=20", "-j") plus the one value right after a flag without
// "=" ("-O build"), all in a plain character set. A loose word such as
// "node-gyp rebuild node x.js" is refused.
func plainFlags(args []string) bool {
	prevFlag := false
	for _, a := range args {
		if !plainWord(a) {
			return false
		}
		switch {
		case strings.HasPrefix(a, "-"):
			prevFlag = !strings.Contains(a, "=")
		case prevFlag:
			prevFlag = false
		default:
			return false
		}
	}
	return true
}

// plainWord reports whether w has only letters, digits and . _ , / : = @ + -.
func plainWord(w string) bool {
	for _, r := range w {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("._,/:=@+-", r):
		default:
			return false
		}
	}
	return w != ""
}

// commands splits a script at &&, ||, ;, |, & and line breaks (the
// shell runs each line as its own command), trimming each part.
func commands(script string) []string {
	f := func(r rune) bool { return r == '&' || r == '|' || r == ';' || r == '\n' || r == '\r' }
	var out []string
	for _, c := range strings.FieldsFunc(script, f) {
		if c = collapse(c); c != "" {
			out = append(out, c)
		}
	}
	return out
}

// hadBindingGyp reports whether the installed version shipped a
// binding.gyp, which npm builds with node-gyp rebuild on its own.
func hadBindingGyp(s *core.Subject) bool {
	if s.OldTree == nil {
		return false
	}
	_, ok := s.OldTree.Lookup(bindingGyp)
	return ok
}

// newBindingGyp reports a binding.gyp the installed version lacked, with
// no install script of its own: npm then runs node-gyp rebuild, which
// runs whatever the build file says. An install script already gets its
// own finding.
func newBindingGyp(s *core.Subject) bool {
	if s.NewTree == nil || hadBindingGyp(s) {
		return false
	}
	if _, ok := s.NewTree.Lookup(bindingGyp); !ok {
		return false
	}
	return s.New.Scripts["install"] == "" && s.New.Scripts["preinstall"] == ""
}

// prepareTools are build tools a prepare script runs, by the package
// that provides them, for the "tools already present" guard.
var prepareTools = map[string]string{
	"tsc": "typescript", "babel": "@babel/cli", "rollup": "rollup", "webpack": "webpack",
	"vite": "vite", "tsup": "tsup", "esbuild": "esbuild", "husky": "husky", "ngc": "@angular/compiler-cli",
	"svelte-kit": "@sveltejs/kit", "patch-package": "patch-package", "unbuild": "unbuild",
}

// runners run whatever file or text they are given, so having run one
// before vouches for nothing.
var runners = map[string]bool{
	"node": true, "sh": true, "bash": true, "zsh": true, "python": true, "python3": true, "perl": true,
	"ruby": true, "php": true, "curl": true, "wget": true, "pwsh": true, "powershell": true, "cmd": true,
	"deno": true, "bun": true, "eval": true, "exec": true, "env": true,
	// A package manager runs any script or package it is given; only the
	// "same script as before" case of benignPrepare vouches for it.
	"npm": true, "yarn": true, "pnpm": true, "npx": true,
}

// benignPrepare reports whether every command of a prepare script only
// runs husky, a script the installed version had with the same text or
// a build tool the installed version already depended on or ran:
// prepare runs for git and local installs; those commands were trusted
// before. Substitution, redirection and environment assignments are
// never benign: NODE_OPTIONS=--require=./x.js makes even tsc load code.
func benignPrepare(script string, old, cur *core.Meta) bool {
	if hasShellMeta(script) {
		return false
	}
	cmds := commands(script)
	if len(cmds) == 0 {
		return false
	}
	for _, c := range cmds {
		words := strings.Fields(c)
		for len(words) > 0 && (words[0] == "npx" || words[0] == "is-ci") {
			words = words[1:]
		}
		if len(words) == 0 {
			continue
		}
		prog := words[0]
		switch {
		case isAssignment(prog):
			return false
		case prog == "husky":
		case (prog == "npm" || prog == "yarn" || prog == "pnpm") && len(words) > 1 && oldRunsScript(prog, words[1:], old, cur):
		case old != nil && !runners[prog] && toolPresent(prog, old):
		default:
			return false
		}
	}
	return true
}

// isAssignment reports a VAR=value word in command position.
func isAssignment(w string) bool {
	name, _, ok := strings.Cut(w, "=")
	return ok && name != "" && !strings.HasPrefix(name, "-")
}

// pmBuiltins are package manager commands that are not scripts: yarn
// and pnpm run a bare name as a script only when it is none of these.
var pmBuiltins = map[string]bool{
	"add": true, "install": true, "i": true, "ci": true, "exec": true, "dlx": true, "x": true,
	"create": true, "link": true, "unlink": true, "remove": true, "rm": true, "up": true, "upgrade": true,
	"publish": true, "pack": true, "rebuild": true, "patch": true, "node": true, "set": true, "config": true,
}

// npmScriptCmds are the npm commands that run a script of the same name.
var npmScriptCmds = map[string]bool{"test": true, "start": true, "stop": true, "restart": true}

// oldRunsScript reports whether "run build" (or "build" for yarn and
// pnpm) names a script the installed version had with the same text in
// the candidate. Every script it runs in turn must be unchanged too, so
// an untouched "build: npm run gen" can't vouch for a new gen.
func oldRunsScript(pm string, args []string, old, cur *core.Meta) bool {
	if old == nil || cur == nil {
		return false
	}
	name := args[0]
	switch {
	case name == "run" || name == "run-script":
		if len(args) < 2 {
			return false
		}
		name = args[1]
	case pm == "npm" && !npmScriptCmds[name], pm != "npm" && pmBuiltins[name]:
		return false
	}
	return sameScript(name, old, cur, map[string]bool{})
}

// sameScript reports whether script name has the same text in old and
// cur, as does every script it runs through a package manager.
func sameScript(name string, old, cur *core.Meta, seen map[string]bool) bool {
	if seen[name] {
		return true
	}
	seen[name] = true
	ov, ok := old.Scripts[name]
	nv, ok2 := cur.Scripts[name]
	if !ok || !ok2 || collapse(ov) != collapse(nv) {
		return false
	}
	for _, c := range commands(nv) {
		w := strings.Fields(c)
		if len(w) < 2 || w[0] != "npm" && w[0] != "yarn" && w[0] != "pnpm" {
			continue
		}
		next := w[1]
		if (next == "run" || next == "run-script") && len(w) > 2 {
			next = w[2]
		}
		if _, ok := cur.Scripts[next]; ok && !sameScript(next, old, cur, seen) {
			return false
		}
	}
	return true
}

// toolPresent reports whether prog comes from a package the installed
// version depended on, or was run by one of its scripts.
func toolPresent(prog string, old *core.Meta) bool {
	pkg := prog
	if p, ok := prepareTools[prog]; ok {
		pkg = p
	}
	if _, ok := old.DevDeps[pkg]; ok {
		return true
	}
	if _, ok := old.Deps[pkg]; ok {
		return true
	}
	for _, v := range old.Scripts {
		for _, c := range commands(v) {
			if f := strings.Fields(c); len(f) > 0 && f[0] == prog {
				return true
			}
		}
	}
	return false
}

// installCode analyses the scripts in keys plus the package files they
// name, then runs the feature detectors on what that code does. Old
// gives the features the installed version's install code had, so only
// what is new to install time fires. A feature the main pass reports
// already (new code in a new file) is left out, so nothing is reported
// twice.
func installCode(ctx context.Context, s *core.Subject, keys []string, emit func(core.Finding)) {
	a := core.GetAnalyzer()
	if a == nil {
		return
	}
	newSet := analyseScripts(ctx, a, s.New, s.NewTree, keys)
	var oldSet *core.FeatureSet
	if s.Old != nil {
		oldSet = analyseScripts(ctx, a, s.Old, s.OldTree, lifecycleScripts)
	}
	kept := core.NewFeatureSet()
	for _, fs := range newSet.ByKey {
		for _, f := range fs {
			if !mainPassReports(s, f) {
				kept.Add(f)
			}
		}
	}
	nested := &core.Subject{
		Update: s.Update, Old: s.Old, New: s.New, OldTree: s.OldTree, NewTree: s.NewTree,
		OldFeatures: oldSet, NewFeatures: kept, Config: s.Config, Now: s.Now,
	}
	for _, d := range code.FeatureDetectors() {
		d.Detect(ctx, nested, emit)
	}
}

// mainPassReports reports whether the main run of the code detectors
// already fires on f: the candidate has the same feature in the same
// file and the installed version did not have it anywhere.
func mainPassReports(s *core.Subject, f core.Feature) bool {
	if s.NewFeatures == nil || s.OldFeatures.Has(f.Kind, f.Key) {
		return false
	}
	return slices.ContainsFunc(s.NewFeatures.ByKey[f.SetKey()], func(g core.Feature) bool {
		return g.Ev.Path == f.Ev.Path
	})
}

// analyseScripts runs the analyzer over the scripts in keys (as
// JavaScript, PRD 12.1) and over each file of t they name.
func analyseScripts(ctx context.Context, a core.Analyzer, m *core.Meta, t *core.Tree, keys []string) *core.FeatureSet {
	out := core.NewFeatureSet()
	files := map[string]bool{}
	for _, k := range keys {
		script := m.Scripts[k]
		if strings.TrimSpace(script) == "" {
			continue
		}
		if fs, err := a.AnalyzeText(ctx, core.KindJS, npmManifest, []byte(script)); err == nil {
			addAll(out, fs)
		}
		for _, p := range scriptFiles(script, t) {
			files[p] = true
		}
	}
	for _, p := range slices.Sorted(maps.Keys(files)) {
		f, _ := t.Lookup(p)
		b, ok := readFile(t, f, maxScriptFile)
		if !ok {
			continue
		}
		kind := f.Kind
		if kind == "" || kind == core.KindText {
			kind = core.KindJS
		}
		if fs, err := a.AnalyzeText(ctx, kind, p, b); err == nil {
			addAll(out, fs)
		}
	}
	return out
}

func addAll(dst, src *core.FeatureSet) {
	if src == nil {
		return
	}
	for _, fs := range src.ByKey {
		for _, f := range fs {
			dst.Add(f)
		}
	}
}

// scriptFiles returns the files of t a script names, such as
// "node scripts/setup.js" or "sh ./install.sh".
func scriptFiles(script string, t *core.Tree) []string {
	if t == nil {
		return nil
	}
	var out []string
	for _, w := range strings.FieldsFunc(script, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '&' || r == '|' || r == ';' || r == '=' || r == '(' || r == ')'
	}) {
		w = strings.Trim(w, `"'`)
		w = path.Clean(strings.TrimPrefix(w, "./"))
		if w == "." || strings.HasPrefix(w, "../") || strings.HasPrefix(w, "/") {
			continue
		}
		if _, ok := t.Lookup(w); ok && !slices.Contains(out, w) {
			out = append(out, w)
		}
	}
	return out
}

// readFile reads up to limit bytes of f from t.
func readFile(t *core.Tree, f core.File, limit int64) ([]byte, bool) {
	if t == nil || t.Blobs == nil || f.Mode&^0o777 != 0 {
		return nil, false
	}
	r, err := t.Blobs.Open(f.SHA256)
	if err != nil {
		return nil, false
	}
	defer func() { _ = r.Close() }()
	b, err := io.ReadAll(io.LimitReader(r, limit))
	if err != nil {
		return nil, false
	}
	return b, true
}

// composerType is the Composer default when type is left out.
func composerType(m *core.Meta) string {
	if m == nil || m.Type == "" {
		return "library"
	}
	return m.Type
}

// composerEvent reports whether a scripts key is a Composer event, which
// Composer runs on its own, rather than a command run by hand
// (composer test, composer lint).
func composerEvent(name string) bool {
	return strings.HasPrefix(name, "pre-") || strings.HasPrefix(name, "post-")
}

// composerHookFindings reports a package that became a Composer plugin
// and new or changed event scripts.
func composerHookFindings(s *core.Subject) []core.Finding {
	var out []core.Finding
	if s.New.Type == "composer-plugin" && (s.Old == nil || s.Old.Type != "composer-plugin") {
		ev := "type composer-plugin"
		if s.Old != nil {
			ev = "type changed from " + composerType(s.Old) + " to composer-plugin"
		}
		f := newFinding(SigComposerPlugin, ev)
		f.File = composerManifest
		out = append(out, f)
	}
	for _, name := range changedComposerEvents(s) {
		f := newFinding(SigComposerPlugin, name+": "+strings.Join(s.New.ComposerScripts[name], " && "))
		f.File = composerManifest
		out = append(out, f)
	}
	return out
}

// changedComposerEvents lists the event scripts that are new or changed.
func changedComposerEvents(s *core.Subject) []string {
	var old map[string][]string
	if s.Old != nil {
		old = s.Old.ComposerScripts
	}
	var out []string
	for _, name := range slices.Sorted(maps.Keys(s.New.ComposerScripts)) {
		if !composerEvent(name) || len(s.New.ComposerScripts[name]) == 0 {
			continue
		}
		if !slices.Equal(s.New.ComposerScripts[name], old[name]) {
			out = append(out, name)
		}
	}
	return out
}

// autoloadFindings reports new autoload.files entries: Composer includes
// each on every request. The file's code goes through the code signals
// anyway; a file whose features are only calls inside function bodies
// is low.
func autoloadFindings(s *core.Subject) []core.Finding {
	old := map[string]bool{}
	if s.Old != nil {
		for _, p := range s.Old.AutoloadFiles {
			old[cleanPath(p)] = true
		}
	}
	var out []core.Finding
	for _, p := range s.New.AutoloadFiles {
		p = cleanPath(p)
		if old[p] || p == "" {
			continue
		}
		old[p] = true
		f := newFinding(SigAutoloadFiles, "autoload.files: "+p)
		f.File = p
		if onlyDefinitions(s, p) {
			f.Severity, f.Demoted = cli.SeverityLow, "only defines functions"
		}
		out = append(out, f)
	}
	return out
}

func cleanPath(p string) string {
	p = path.Clean(strings.TrimPrefix(strings.TrimSpace(p), "./"))
	if p == "." {
		return ""
	}
	return p
}

// onlyDefinitions reports whether the analyzer read p and found nothing
// in it but plain calls: no hook, flow, eval, network, write or other
// capability that would run when the file is included.
func onlyDefinitions(s *core.Subject, p string) bool {
	if s.NewTree == nil || s.NewFeatures == nil {
		return false
	}
	if _, ok := s.NewTree.Lookup(p); !ok {
		return false
	}
	for _, u := range s.NewFeatures.Unanalysed {
		if u.Path == p {
			return false
		}
	}
	for _, fs := range s.NewFeatures.ByKey {
		for _, f := range fs {
			if f.Ev.Path == p && f.Kind != core.FCall {
				return false
			}
		}
	}
	return true
}
