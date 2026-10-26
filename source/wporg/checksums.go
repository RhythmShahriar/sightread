// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package wporg

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"

	"github.com/RhythmShahriar/sightread/archive"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/fetch"
)

// The Integrity.Method texts of a plugin (PRD 18 item 4).
const (
	MethodChecksums       = "matches WordPress.org's own checksums (both come from WordPress.org, so this proves the copy was not changed on the way, not what the author intended)"
	MethodChecksumsFailed = "does not match WordPress.org's own checksums"
	MethodChecksumsNone   = "not verified: WordPress.org's checksums for this version are unavailable"
	MethodChecksumsCut    = "not verified: the archive hit a limit, so not every file could be checked against WordPress.org's checksums"
)

// reasonNoChecksums is the E5 reason of a release WordPress.org lists
// no checksums for.
const reasonNoChecksums = "wordpress.org has no checksums for this version"

// sums maps a path inside the plugin folder to the SHA-256 values
// WordPress.org accepts for it, in lower-case hex. A release that was
// rebuilt lists more than one.
type sums map[string][]string

// errNoChecksums is a checksums file that lists no file.
var errNoChecksums = errors.New("no files listed")

// decodeChecksums reads a plugin-checksums answer. Each sha256 is one
// hex string or a list of them; anything else is an error, since a
// checksum Sightread can't read must not count as a match or a change.
func decodeChecksums(body []byte) (sums, error) {
	var top struct {
		Files json.RawMessage `json:"files"`
	}
	if err := json.Unmarshal(body, &top); err != nil {
		return nil, err
	}
	// PHP writes an empty map as [].
	if len(top.Files) == 0 || isNull(top.Files) || isEmptyArray(top.Files) {
		return nil, errNoChecksums
	}
	var r struct {
		Files map[string]struct {
			SHA256 json.RawMessage `json:"sha256"`
		}
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	if len(r.Files) == 0 {
		return nil, errNoChecksums
	}
	out := make(sums, len(r.Files))
	for p, f := range r.Files {
		var many []string
		if bytes.HasPrefix(bytes.TrimSpace(f.SHA256), []byte("[")) {
			if err := json.Unmarshal(f.SHA256, &many); err != nil {
				return nil, fmt.Errorf("the sha256 of %q: %w", p, err)
			}
		} else {
			var one string
			if err := json.Unmarshal(f.SHA256, &one); err != nil {
				return nil, fmt.Errorf("the sha256 of %q: %w", p, err)
			}
			many = []string{one}
		}
		for i, h := range many {
			h = strings.ToLower(strings.TrimSpace(h))
			if b, err := hex.DecodeString(h); err != nil || len(b) != 32 {
				return nil, fmt.Errorf("the sha256 of %q is not a SHA-256", p)
			}
			many[i] = h
		}
		if len(many) == 0 {
			return nil, fmt.Errorf("the sha256 of %q is empty", p)
		}
		out[p] = many
	}
	return out, nil
}

// checksums loads WordPress.org's per-file SHA-256 of slug at v (cached
// for good: a release's checksums never change). When there are none to
// use, reason says why in the words of E5 and err is nil.
func (s *site) checksums(ctx context.Context, slug, v string) (sums, string, error) {
	u := s.dl + "/plugin-checksums/" + url.PathEscape(slug) + "/" + url.PathEscape(v) + ".json"
	var body json.RawMessage
	err := s.env.Get.JSON(ctx, u, &body, fetch.KindChecksums)
	switch st := fetch.StatusOf(err); {
	case st == 404:
		return nil, reasonNoChecksums, nil
	case st >= 500:
		return nil, fmt.Sprintf("wordpress.org checksums answered %d", st), nil
	case err != nil:
		return nil, "", err
	}
	got, err := decodeChecksums(body)
	switch {
	case errors.Is(err, errNoChecksums):
		return nil, reasonNoChecksums, nil
	case err != nil:
		s.logf("unreadable checksums for %s %s: %v", slug, v, err)
		return nil, "wordpress.org checksums could not be read", nil
	}
	return got, "", nil
}

// hexOf is the lower-case hex of a file's SHA-256.
func hexOf(f core.File) string { return hex.EncodeToString(f.SHA256[:]) }

// isReadme reports whether p is the plugin's readme.txt, which
// WordPress.org rewrites (Stable tag, Tested up to) without a release,
// so a change there is normal and never a mismatch.
func isReadme(p string) bool { return strings.EqualFold(p, "readme.txt") }

// verifyTree compares every file of tree with want. Every file must be
// listed with a matching hash and every listed file must be there,
// except readme.txt. A tree a limit cut short can't prove a file is
// missing, so it is unverified unless a file it did read differs.
func verifyTree(tree *core.Tree, want sums) core.Integrity {
	var bad []string
	seen := map[string]bool{}
	for _, f := range tree.Files {
		if isReadme(f.Path) {
			continue
		}
		seen[f.Path] = true
		hashes, listed := want[f.Path]
		if !listed || !f.Mode.IsRegular() || !slices.Contains(hashes, hexOf(f)) {
			bad = append(bad, f.Path)
		}
	}
	cut := slices.ContainsFunc(tree.Issues, func(i core.ArchiveIssue) bool { return i.Kind == core.IssueLimit })
	for _, p := range slices.Sorted(maps.Keys(want)) {
		if !seen[p] && !isReadme(p) && !cut {
			bad = append(bad, p)
		}
	}
	slices.Sort(bad)
	switch {
	case len(bad) > 0:
		return core.Integrity{By: core.ByFailed, Method: MethodChecksumsFailed, Mismatch: bad,
			Detail: fmt.Sprintf("%d %s from WordPress.org's checksums", len(bad), plural(len(bad), "file differs", "files differ"))}
	case cut:
		// The checksums were there: the archive's limit is why nothing
		// is verified. The Integrity fact must say so.
		return core.Integrity{By: core.ByNone, Method: MethodChecksumsCut,
			Detail: "the archive hit a limit, so not every file could be checked"}
	}
	return core.Integrity{By: core.ByChecksums, Method: MethodChecksums}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// officialTree is the official copy as the checksums describe it, for
// core.Differ.Drift: paths and hashes, no contents. Where a file has
// several accepted hashes, the one the local copy has is used, so a
// rebuilt release still matches.
func officialTree(want sums, local *core.Tree) *core.Tree {
	t := &core.Tree{HashKind: core.HashManifest}
	have := byPath(local)
	for p, hashes := range want {
		h := hashes[0]
		if f, ok := have[p]; ok && slices.Contains(hashes, hexOf(f)) {
			h = hexOf(f)
		}
		f := core.File{Path: p, Kind: archive.KindOf(p)}
		_, _ = hex.Decode(f.SHA256[:], []byte(h))
		t.Files = append(t.Files, f)
	}
	t.SortFiles()
	return t
}

// byPath indexes a tree's files; a local tree from disk may not be
// sorted, so Lookup is not used.
func byPath(t *core.Tree) map[string]core.File {
	m := make(map[string]core.File, len(t.Files))
	for _, f := range t.Files {
		m[f.Path] = f
	}
	return m
}
