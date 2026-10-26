// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package meta

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
)

// The signals of the size detector.
const (
	SigSizeJump     = "size-jump"
	SigFilesRemoved = "files-removed"
)

// Size jump thresholds (PRD 12.1): growth over 100 KB plus either over
// the median plus 3 median absolute deviations of the last releases
// (with at least 4 known) or over 30% of the installed code.
const (
	jumpBytes       = 100 << 10
	jumpHistory     = 10
	jumpMinHistory  = 4
	jumpMADs        = 3
	jumpGrowthRatio = 0.30
)

// bulkFolders hold translations, vendored libraries or build output: a
// new one is a reason for growth, so the jump is info.
var bulkFolders = []string{"languages", "vendor", "dist"}

// maxGuardFile is the most of a removed file read for security checks.
const maxGuardFile = 1 << 20

func init() { core.RegisterDetector(sizeDetector{}) }

// sizeDetector reports code that grew far more than usual or gained a
// minified or binary file, plus removed files that held security checks
// (PRD 12.1).
type sizeDetector struct{}

func (sizeDetector) Info() core.DetectorInfo {
	return core.DetectorInfo{Name: "meta-size", Signals: []string{SigSizeJump, SigFilesRemoved}}
}

func (sizeDetector) Detect(_ context.Context, s *core.Subject, emit func(core.Finding)) {
	out := newEmitter(s, emit)
	if s.Old == nil || s.OldTree == nil || s.NewTree == nil {
		return
	}
	for _, f := range sizeFindings(s) {
		out.send(f)
	}
	for _, f := range removedFindings(s) {
		out.send(f)
	}
}

// codeFile reports whether f counts as code for the size: PHP and
// JavaScript, minified included.
func codeFile(f core.File) bool {
	switch f.Kind {
	case core.KindPHP, core.KindJS, core.KindMinified:
		return true
	case "":
		switch strings.ToLower(path.Ext(f.Path)) {
		case ".php", ".js", ".mjs", ".cjs", ".inc", ".phtml":
			return true
		}
	}
	return false
}

// bulkFile reports whether f is minified or binary.
func bulkFile(f core.File) bool { return f.Kind == core.KindMinified || f.Kind == core.KindBinary }

// newBulkFolders lists the bulk folders (at any depth) the candidate has
// and the installed version did not, as "languages/" or "lib/vendor/".
func newBulkFolders(s *core.Subject) []string {
	has := func(t *core.Tree) map[string]bool {
		m := map[string]bool{}
		for _, f := range t.Files {
			segs := strings.Split(f.Path, "/")
			for i := range len(segs) - 1 {
				if slices.Contains(bulkFolders, strings.ToLower(segs[i])) {
					m[strings.Join(segs[:i+1], "/")+"/"] = true
				}
			}
		}
		return m
	}
	old := has(s.OldTree)
	var out []string
	for d := range has(s.NewTree) {
		if !old[d] {
			out = append(out, d)
		}
	}
	slices.Sort(out)
	return out
}

// under reports whether p is inside one of the folders.
func under(p string, folders []string) bool {
	return slices.ContainsFunc(folders, func(d string) bool { return strings.HasPrefix(p, d) })
}

// codeSize sums the code of t, leaving out files under skip.
func codeSize(t *core.Tree, skip []string) int64 {
	var n int64
	for _, f := range t.Files {
		if codeFile(f) && !under(f.Path, skip) {
			n += f.Size
		}
	}
	return n
}

// kb prints a byte count in KB, rounded.
func kb(n int64) string { return fmt.Sprintf("%d KB", (n+512)>>10) }

// sizeFindings gives the size-jump findings.
func sizeFindings(s *core.Subject) []core.Finding {
	var out []core.Finding
	folders := newBulkFolders(s)
	oldSize, newSize := codeSize(s.OldTree, nil), codeSize(s.NewTree, nil)
	jump, why := sizeJumps(s, oldSize, newSize)
	if jump {
		f := newFinding(SigSizeJump, fmt.Sprintf("code grew from %s to %s (+%s)%s", kb(oldSize), kb(newSize), kb(newSize-oldSize), why))
		if outside, _ := sizeJumps(s, oldSize, codeSize(s.NewTree, folders)); !outside {
			f.Severity, f.Demoted = cli.SeverityInfo, "new "+strings.Join(folders, ", ")+" folder"
		}
		out = append(out, f)
	}
	if f, ok := bulkFinding(s, folders); ok {
		out = append(out, f)
	}
	return out
}

// sizeJumps applies the thresholds to a growth from oldSize to newSize
// and says which one held.
func sizeJumps(s *core.Subject, oldSize, newSize int64) (bool, string) {
	growth := newSize - oldSize
	if growth <= jumpBytes {
		return false, ""
	}
	var sizes []int64
	for _, r := range s.New.History {
		if r.Size > 0 {
			sizes = append(sizes, r.Size)
		}
	}
	if len(sizes) > jumpHistory {
		sizes = sizes[len(sizes)-jumpHistory:]
	}
	if len(sizes) >= jumpMinHistory {
		med := median(sizes)
		devs := make([]int64, len(sizes))
		for i, v := range sizes {
			devs[i] = abs(v - med)
		}
		limit := med + jumpMADs*median(devs)
		cand := s.New.Archive.Size
		if cand == 0 {
			cand = s.NewTree.Bytes
		}
		if cand <= limit {
			return false, ""
		}
		return true, fmt.Sprintf("; %s is over the usual size of the last %d releases (median %s)", kb(cand), len(sizes), kb(med))
	}
	if float64(growth) <= jumpGrowthRatio*float64(oldSize) {
		return false, ""
	}
	return true, ""
}

func median(v []int64) int64 {
	c := slices.Clone(v)
	slices.Sort(c)
	n := len(c)
	if n%2 == 1 {
		return c[n/2]
	}
	return (c[n/2-1] + c[n/2]) / 2
}

func abs(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// bulkFinding reports a minified or binary file added to a package that
// had none; info when every such file is in a new bulk folder.
func bulkFinding(s *core.Subject, folders []string) (core.Finding, bool) {
	if slices.ContainsFunc(s.OldTree.Files, bulkFile) {
		return core.Finding{}, false
	}
	var added []string
	allBulk := true
	for _, f := range s.NewTree.Files {
		if !bulkFile(f) {
			continue
		}
		if _, ok := s.OldTree.Lookup(f.Path); ok {
			continue
		}
		added = append(added, f.Path)
		allBulk = allBulk && under(f.Path, folders)
	}
	if len(added) == 0 {
		return core.Finding{}, false
	}
	f := newFinding(SigSizeJump, "adds "+plural(len(added), "minified or binary file", "minified or binary files")+
		" to a package that had none: "+list(added))
	f.File = added[0]
	if allBulk {
		f.Severity, f.Demoted = cli.SeverityInfo, "new "+strings.Join(folders, ", ")+" folder"
	}
	return f, true
}

// guards are the security checks a removed file can hold, with what the
// evidence says it did.
var guards = []struct {
	re   *regexp.Regexp
	what string
}{
	{regexp.MustCompile(`\b(wp_verify_nonce|check_admin_referer|check_ajax_referer)\s*\(`), "checked nonces"},
	{regexp.MustCompile(`\b(current_user_can|user_can|current_user_can_for_blog)\s*\(`), "checked capabilities"},
	{regexp.MustCompile(`\bsanitize_[a-z_]+\s*\(`), "sanitised input"},
	{regexp.MustCompile(`\besc_(html|attr|url|js|textarea|sql|xml)[a-z_]*\s*\(`), "escaped output"},
}

// htaccessDeny matches the rules that stop a web server from serving a
// folder.
var htaccessDeny = regexp.MustCompile(`(?im)^\s*(deny\s+from\s+all|require\s+all\s+denied|order\s+deny\s*,\s*allow)`)

// silence matches an index.php that only stops a folder listing.
var silence = regexp.MustCompile(`(?i)silence\s+is\s+golden`)

// removedFindings reports each removed file that held a security check,
// at most maxPerSignal; the last then says how many were left out.
func removedFindings(s *core.Subject) []core.Finding {
	type hit struct {
		path, ev string
	}
	var hits []hit
	for _, f := range removedFiles(s) {
		if did := guardsOf(s.OldTree, f); len(did) > 0 {
			hits = append(hits, hit{f.Path, "removes " + f.Path + ", which " + joinAnd(did)})
		}
	}
	if len(hits) > maxPerSignal {
		last := &hits[maxPerSignal-1]
		last.ev += fmt.Sprintf(" (and %d more like it)", len(hits)-maxPerSignal)
		hits = hits[:maxPerSignal]
	}
	out := make([]core.Finding, 0, len(hits))
	for _, h := range hits {
		f := newFinding(SigFilesRemoved, h.ev)
		f.File = h.path
		out = append(out, f)
	}
	return out
}

// removedFiles lists the installed version's files the candidate lacks,
// from the diff when there is one (a rename is not a removal).
func removedFiles(s *core.Subject) []core.File {
	var out []core.File
	if s.Diff != nil {
		for _, c := range s.Diff.Changes {
			if c.Kind == core.Removed && c.Old != nil {
				out = append(out, *c.Old)
			}
		}
		return out
	}
	for _, f := range s.OldTree.Files {
		if _, ok := s.NewTree.Lookup(f.Path); !ok {
			out = append(out, f)
		}
	}
	return out
}

// guardsOf lists the checks a removed file held.
func guardsOf(t *core.Tree, f core.File) []string {
	base := path.Base(f.Path)
	isHtaccess := base == ".htaccess"
	if !isHtaccess && !codeFile(f) {
		return nil
	}
	b, ok := readFile(t, f, maxGuardFile)
	if !ok {
		return nil
	}
	var did []string
	if isHtaccess {
		if htaccessDeny.Match(b) {
			did = append(did, "denied web access to its folder")
		}
		return did
	}
	if base == "index.php" && (silence.Match(b) || len(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(b)), "<?php"))) == 0) {
		did = append(did, "kept its folder from being listed")
	}
	for _, g := range guards {
		if g.re.Match(b) {
			did = append(did, g.what)
		}
	}
	return did
}

// joinAnd joins "a", "a and b", "a, b and c".
func joinAnd(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}
