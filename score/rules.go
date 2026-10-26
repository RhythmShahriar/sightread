// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package score

import (
	"path"
	"slices"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

// The context rules of PRD 12.2.

// RuleOwnerChange is the RaisedBy entry of rule 1.
const RuleOwnerChange = "owner-change"

// DemotedVendored is the Demoted text of rule 3.
const DemotedVendored = "vendored path"

// raisedByOwner are the signals a new owner makes worse (rule 1).
var raisedByOwner = []string{
	"eval-dynamic", "obfuscation", "input-unserialize", "write-outside-package",
	"admin-user-create", "capability-change", "outbound-new-domain", "data-exfil",
	"dormant-release",
}

// codeSignals are the signals found in code, the ones rule 2 pairs up
// when two of them sit in the same function.
var codeSignals = []string{
	"remote-fetch-exec", "decode-exec", "admin-user-hidden", "eval-dynamic",
	"obfuscation", "input-unserialize", "write-outside-package", "admin-user-create",
	"capability-change", "update-suppression", "bot-cloaking", "credential-access",
	"data-exfil", "outbound-new-domain", "rest-open-route", "cron-new-hook",
}

// funcOf returns the function a finding is in, "" when unknown. The
// analyzer records it on Feature evidence (core.Evidence.Func);
// core.Finding has no field to carry it yet, so until it does every
// finding is in no known function and rule 2 never fires. Tests set it.
var funcOf = func(*core.Finding) string { return "" }

func raise(s cli.Severity) cli.Severity { return min(s+1, cli.SeverityCritical) }

// raiseOwnerChange is rule 1: with owner-change in the update, each
// listed signal goes up one level.
func raiseOwnerChange(fs []core.Finding) {
	if !slices.ContainsFunc(fs, func(f core.Finding) bool { return f.ID == RuleOwnerChange }) {
		return
	}
	for i := range fs {
		f := &fs[i]
		if slices.Contains(raisedByOwner, f.ID) {
			f.Severity = raise(f.Severity)
			f.RaisedBy = append(f.RaisedBy, RuleOwnerChange)
		}
	}
}

// raiseSameFunction is rule 2: when two different code signals sit in
// the same function of the same file, the lower one goes up a level,
// raised by the higher. With equal severities the later one by line is
// raised, so the pair always counts for more than either alone. Each
// finding is raised once by this rule however many others share its
// function.
func raiseSameFunction(fs []core.Finding) {
	type key struct{ file, fn string }
	groups := map[key][]int{}
	var order []key
	for i := range fs {
		f := &fs[i]
		fn := funcOf(f)
		if fn == "" || !slices.Contains(codeSignals, f.ID) {
			continue
		}
		k := key{f.File, fn}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], i)
	}
	for _, k := range order {
		idx := groups[k]
		if len(idx) < 2 {
			continue
		}
		// The top finding: highest severity, then earliest line.
		top := idx[0]
		for _, i := range idx[1:] {
			if fs[i].Severity > fs[top].Severity || fs[i].Severity == fs[top].Severity && fs[i].Line < fs[top].Line {
				top = i
			}
		}
		before := make(map[int]cli.Severity, len(idx))
		for _, i := range idx {
			before[i] = fs[i].Severity
		}
		for _, i := range idx {
			if i == top || fs[i].ID == fs[top].ID || before[i] > before[top] {
				continue
			}
			fs[i].Severity = raise(before[i])
			fs[i].RaisedBy = append(fs[i].RaisedBy, fs[top].ID)
		}
	}
}

// demoteVendored is rule 3: findings in tests, docs, examples, a
// package's own node_modules and a WordPress package's vendor folder,
// and obfuscation in minified or bundled JavaScript, go down one level.
// Critical never goes below high and info stays info; unignorable
// signals are never demoted.
func demoteVendored(eco core.Ecosystem, fs []core.Finding) {
	for i := range fs {
		f := &fs[i]
		if core.Unignorable(f.ID) || !vendored(eco, f) {
			continue
		}
		if f.Severity > cli.SeverityInfo {
			f.Severity--
		}
		f.Demoted = DemotedVendored
	}
}

// vendoredDirs are folder names whose code a site doesn't run as the
// package's own.
var vendoredDirs = []string{"tests", "test", "docs", "examples", "node_modules"}

func vendored(eco core.Ecosystem, f *core.Finding) bool {
	p := strings.ToLower(strings.ReplaceAll(f.File, `\`, "/"))
	if f.ID == "obfuscation" && (strings.HasSuffix(p, ".min.js") || strings.HasSuffix(p, ".bundle.js")) {
		return true
	}
	dir := path.Dir(strings.TrimPrefix(p, "/"))
	if dir == "." {
		return false
	}
	for _, seg := range strings.Split(dir, "/") {
		if slices.Contains(vendoredDirs, seg) {
			return true
		}
		if seg == "vendor" && (eco == core.WPPlugin || eco == core.WPTheme) {
			return true
		}
	}
	return false
}
