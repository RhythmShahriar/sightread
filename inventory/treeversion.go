// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"encoding/json"
	"io"
	"path"
	"slices"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
)

// maxManifest caps how much of a package.json or composer.json
// TreeVersion reads; a real one is a few KB.
const maxManifest = 1 << 20

// maxVersionLen caps a declared version, which reports print.
const maxVersionLen = 64

// TreeVersion reads the version t's own files declare, as WordPress,
// npm or Composer would after an install: the Version header of a
// plugin's main file (<name>.php first, then the other top-level PHP
// files) or of a theme's style.css, else the version field of
// package.json or composer.json. A tree whose files sit in one top
// folder (a zip that wasn't stripped) is read inside it. It returns ""
// when nothing declares a version or the value is not a plain version
// token. It implements core.TreeVersioner.
func (rd *Reader) TreeVersion(eco core.Ecosystem, name string, t *core.Tree) string {
	if t == nil || t.Blobs == nil {
		return ""
	}
	prefix := topFolder(t)
	var v string
	switch eco {
	case core.WPPlugin:
		files := []string{prefix + name + ".php"}
		for _, f := range t.Files {
			if p, ok := strings.CutPrefix(f.Path, prefix); ok && !strings.Contains(p, "/") &&
				strings.EqualFold(path.Ext(p), ".php") && !slices.Contains(files, f.Path) {
				files = append(files, f.Path)
			}
		}
		for _, p := range files {
			if h, ok := ParseWPHeader(treeHead(t, p, headerBytes), "Plugin Name"); ok && h.Version != "" {
				v = h.Version
				break
			}
		}
	case core.WPTheme:
		if h, ok := ParseWPHeader(treeHead(t, prefix+"style.css", headerBytes), "Theme Name"); ok {
			v = h.Version
		}
	case core.NPM, core.Composer:
		manifest := "package.json"
		if eco == core.Composer {
			manifest = "composer.json"
		}
		var doc struct {
			Version string `json:"version"`
		}
		if json.Unmarshal(treeHead(t, prefix+manifest, maxManifest), &doc) == nil {
			v = strings.TrimSpace(doc.Version)
		}
	}
	if len(v) > maxVersionLen || versionToken.FindString(v) != v {
		return ""
	}
	return v
}

// topFolder is "<dir>/" when every file of t sits in that one folder,
// else "".
func topFolder(t *core.Tree) string {
	dir := ""
	for _, f := range t.Files {
		first, _, ok := strings.Cut(f.Path, "/")
		if !ok || (dir != "" && first != dir) {
			return ""
		}
		dir = first
	}
	if dir == "" {
		return ""
	}
	return dir + "/"
}

// treeHead returns up to limit bytes of the regular file p of t, or nil.
// A tree read from disk may not be sorted, so Lookup is not used.
func treeHead(t *core.Tree, p string, limit int64) []byte {
	i := slices.IndexFunc(t.Files, func(f core.File) bool { return f.Path == p })
	if i < 0 || !t.Files[i].Mode.IsRegular() {
		return nil
	}
	f := t.Files[i]
	rc, err := t.Blobs.Open(f.SHA256)
	if err != nil {
		return nil
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, limit))
	if err != nil {
		return nil
	}
	return b
}

// Reader reads declared versions for run.
var _ core.TreeVersioner = (*Reader)(nil)
