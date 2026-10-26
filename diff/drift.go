// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package diff

import (
	"context"
	"path"
	"slices"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
)

// Drift compares an installed copy with the official tree of the same
// version by SHA-256, path by path. Matched lists the files that are the
// same, Differ the ones edited, Missing the official files absent
// locally and Extra the files only the installed copy has, each sorted.
// Official is false when under half the official files match, so the
// copy is not the package the source knows (an unrelated namesake).
//
// Files a site changes without touching code are left out on both
// sides: readme.txt, translations (*.mo anywhere; *.po, *.pot and *.json
// in a languages folder) and .DS_Store. Translation PHP files
// (*.l10n.php) are code and are compared. Modes are not compared, since
// a site's file system decides them.
func (Differ) Drift(_ context.Context, local, official *core.Tree) core.Drift {
	var d core.Drift
	l, o := driftFiles(local), driftFiles(official)
	for _, p := range sortedKeys(o) {
		switch sum, ok := l[p]; {
		case !ok:
			d.Missing = append(d.Missing, p)
		case sum == o[p]:
			d.Matched = append(d.Matched, p)
		default:
			d.Differ = append(d.Differ, p)
		}
	}
	for _, p := range sortedKeys(l) {
		if _, ok := o[p]; !ok {
			d.Extra = append(d.Extra, p)
		}
	}
	d.Official = len(o) > 0 && 2*len(d.Matched) >= len(o)
	return d
}

// driftFiles maps the compared files of t to their hashes.
func driftFiles(t *core.Tree) map[string][32]byte {
	m := map[string][32]byte{}
	if t == nil {
		return m
	}
	for _, f := range t.Files {
		if !DriftIgnored(f.Path) {
			m[f.Path] = identity(&f)
		}
	}
	return m
}

// sortedKeys returns the keys of m in order.
func sortedKeys(m map[string][32]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// DriftIgnored reports whether Drift leaves the file at p out: a
// readme.txt, a .DS_Store, a *.mo file, or a *.po, *.pot or *.json file
// in a languages folder. Names are matched without regard to case.
func DriftIgnored(p string) bool {
	lower := strings.ToLower(p)
	base := path.Base(lower)
	switch {
	case base == "readme.txt" || base == ".ds_store" || path.Ext(base) == ".mo":
		return true
	}
	dir := "/" + path.Dir(lower) + "/"
	if !strings.Contains(dir, "/languages/") {
		return false
	}
	switch path.Ext(base) {
	case ".po", ".pot", ".json":
		return true
	}
	return false
}
