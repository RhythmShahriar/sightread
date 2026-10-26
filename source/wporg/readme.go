// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package wporg

import (
	"bufio"
	"bytes"
	"io"
	"slices"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/source/changelog"
)

// maxReadme caps the readme read for its header.
const maxReadme = 1 << 20

// metaFromTree fills what m takes from the release itself: the
// changelog and, when the readme names them, the contributors. The info
// API lists the contributors of the current release only, so without
// this every version would carry the same list and a new committer
// would look like an old one.
func metaFromTree(m *core.Meta, tree *core.Tree) {
	m.Changelog = changelog.FromTree(tree)
	if c := readmeContributors(tree); len(c) > 0 {
		m.Contributors = c
	}
}

// readmeContributors returns the logins of the "Contributors:" header
// line of the tree's readme.txt, lower case, sorted and unique, or nil.
// The header runs from the "=== Name ===" title to the first "=="
// section.
func readmeContributors(tree *core.Tree) []string {
	data := readTreeFile(tree, "readme.txt")
	if data == nil {
		data = readTreeFile(tree, "README.txt")
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "==") && !strings.HasPrefix(line, "===") {
			return nil // "== Description ==": the header is over
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok || !strings.EqualFold(strings.TrimSpace(k), "contributors") {
			continue
		}
		var out []string
		for _, c := range strings.Split(v, ",") {
			if c = strings.ToLower(strings.TrimSpace(c)); c != "" && len(c) <= 60 {
				out = append(out, clip(c))
			}
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	return nil
}

// readTreeFile returns a regular file of tree up to maxReadme bytes, or
// nil.
func readTreeFile(tree *core.Tree, p string) []byte {
	f, ok := tree.Lookup(p)
	if !ok || !f.Mode.IsRegular() || f.Size > maxReadme || tree.Blobs == nil {
		return nil
	}
	rc, err := tree.Blobs.Open(f.SHA256)
	if err != nil {
		return nil
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, maxReadme))
	if err != nil {
		return nil
	}
	return b
}
