// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package packagist

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	"github.com/RhythmShahriar/sightread/archive"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/fetch"
	"github.com/RhythmShahriar/sightread/source/changelog"
)

// The Integrity.Method texts of a Composer package (PRD 18 item 4).
const (
	MethodShasum       = "the archive's SHA-1 matches the dist.shasum its repository publishes"
	MethodShasumFailed = "the archive's SHA-1 does not match the dist.shasum its repository publishes"
	// MethodCommit is completed with the short commit.
	MethodCommit       = "pinned to commit %s; Packagist publishes no archive hash for this package"
	MethodCommitFailed = "the archive is not the commit its repository pins"
	MethodNone         = "not verified: the repository publishes neither an archive hash nor a commit for this version"
)

// shortCommit is how many hex digits name a commit in messages and in a
// GitHub zipball's top folder.
const shortCommit = 7

// maxComposerJSON caps the composer.json read from a package.
const maxComposerJSON = 1 << 20

// Fetch downloads the dist archive, unpacks it under its single top
// folder, checks it against dist.shasum or, when Packagist has none (a
// GitHub zipball, whose bytes GitHub does not keep stable), against the
// commit dist.reference pins. It fills Type, ComposerScripts,
// AutoloadFiles, License, Deps and RequiresPHP from the composer.json
// inside; Changelog comes from its CHANGELOG.md or the like.
func (s *Source) Fetch(ctx context.Context, m *core.Meta) (*core.Tree, core.Integrity, error) {
	name, v := m.Ref.Name, m.Ref.Version
	pk := fetch.Package{Command: command, Name: name, Version: v, Archive: "zip"}
	if m.Archive.URL == "" {
		host := publicHost
		if m.Private {
			host = "its repository"
		}
		return nil, core.Integrity{}, noDist(name, v, host)
	}
	d, err := s.env.Get.Download(ctx, s.distURL(m.Archive.URL), s.lim.Download, s.env.Blobs)
	if err != nil {
		return nil, core.Integrity{}, pk.Wrap(err)
	}
	tree, err := s.unpack(ctx, d)
	if err != nil {
		return nil, core.Integrity{}, pk.Wrap(err)
	}
	in := verify(m.Archive, d, tree)
	s.MetaFromTree(m, tree)
	return tree, in, nil
}

// MetaFromTree fills what m takes from the package's own files: the
// composer.json fields Fetch names and the changelog. Fetch calls it; a
// caller that cached the tree calls it instead of fetching.
func (s *Source) MetaFromTree(m *core.Meta, tree *core.Tree) {
	s.readComposerJSON(tree, m)
	m.Changelog = changelog.FromTree(tree)
}

// distURL points a dist URL at the configured GitHub mirror when there
// is one (the testbed), so a zipball of api.github.com and its redirect
// to codeload reach the mirror instead.
func (s *Source) distURL(u string) string {
	for _, key := range []string{core.BaseGitHubAPI, core.BaseGitHubCodeload} {
		official := fetch.DefaultBases()[key]
		mirror := base(s.env, key)
		if mirror != official && strings.HasPrefix(u, official+"/") {
			return mirror + strings.TrimPrefix(u, official)
		}
	}
	return u
}

// unpack indexes a zip (almost every dist) or a tar.gz, picked by its
// first bytes, stripping the single top folder.
func (s *Source) unpack(ctx context.Context, d core.Download) (*core.Tree, error) {
	rc, err := s.env.Blobs.Open(d.SHA256)
	if err != nil {
		return nil, fmt.Errorf("open the downloaded archive: %w", err)
	}
	defer func() { _ = rc.Close() }()
	magic := make([]byte, 2)
	if _, err := io.ReadFull(rc, magic); err != nil {
		return nil, fmt.Errorf("the dist archive is not a zip or tgz")
	}
	switch {
	case bytes.Equal(magic, []byte("PK")):
		return archive.ReadZipDownload(ctx, d, s.env.Blobs, s.lim, archive.StripSingle)
	case bytes.Equal(magic, []byte{0x1f, 0x8b}):
		tgz, err := s.env.Blobs.Open(d.SHA256)
		if err != nil {
			return nil, fmt.Errorf("open the downloaded archive: %w", err)
		}
		defer func() { _ = tgz.Close() }()
		tree, err := archive.ReadTarGz(ctx, tgz, s.env.Blobs, s.lim, archive.StripSingle)
		if err != nil {
			return nil, err
		}
		tree.SHA256, tree.HashKind = d.SHA256, core.HashArchive
		return tree, nil
	}
	return nil, fmt.Errorf("the dist archive is not a zip or tgz")
}

// verify checks one download as SR-19 asks: a published shasum must be
// the archive's SHA-1; without one the archive must be the commit
// dist.reference names (a zipball's top folder ends in it). An empty
// shasum is never reported as a matching hash.
func verify(ref core.ArchiveRef, d core.Download, tree *core.Tree) core.Integrity {
	if want := strings.ToLower(strings.TrimSpace(ref.Shasum)); want != "" {
		got := hex.EncodeToString(d.SHA1[:])
		if got == want {
			return core.Integrity{By: core.ByShasum, Method: MethodShasum}
		}
		return core.Integrity{By: core.ByFailed, Method: MethodShasumFailed, Mismatch: []string{"dist.shasum"},
			Detail: fmt.Sprintf("SHA-1 %s, the repository lists %s", got, clip(want))}
	}
	commit := strings.ToLower(strings.TrimSpace(ref.Reference))
	if !isCommit(commit) {
		return core.Integrity{By: core.ByNone, Method: MethodNone, Detail: "no dist.shasum and no commit in dist.reference"}
	}
	short := commit[:shortCommit]
	top := strings.TrimSuffix(tree.Root, "/")
	if namesCommit(top, commit) {
		return core.Integrity{By: core.ByCommit, Method: fmt.Sprintf(MethodCommit, short)}
	}
	detail := fmt.Sprintf("the archive has no single top folder naming commit %s", short)
	if top != "" {
		detail = fmt.Sprintf("the archive's top folder %s does not name commit %s", clip(top), short)
	}
	return core.Integrity{By: core.ByFailed, Method: MethodCommitFailed, Mismatch: []string{"dist.reference"}, Detail: detail}
}

// isCommit reports whether s is a git commit id: 7 to 64 hex digits
// (SHA-1 or SHA-256 repositories).
func isCommit(s string) bool {
	if len(s) < shortCommit || len(s) > 64 {
		return false
	}
	_, err := hex.DecodeString(s + strings.Repeat("0", len(s)%2))
	return err == nil
}

// namesCommit reports whether a zip's top folder ends in commit's
// abbreviation: "<owner>-<repo>-<7 hex>" from GitHub, 12 from
// Bitbucket, the full id from GitLab.
func namesCommit(top, commit string) bool {
	i := strings.LastIndexByte(top, '-')
	if i < 0 {
		return false
	}
	tail := strings.ToLower(top[i+1:])
	return len(tail) >= shortCommit && isCommit(tail) && strings.HasPrefix(commit, tail)
}

// clip shortens text from an answer for a message.
func clip(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}

// composerJSON is the part of a package's composer.json Sightread reads.
type composerJSON struct {
	Type       json.RawMessage            `json:"type"`
	License    json.RawMessage            `json:"license"`
	Require    json.RawMessage            `json:"require"`
	RequireDev json.RawMessage            `json:"require-dev"`
	Scripts    map[string]json.RawMessage `json:"scripts"`
	Autoload   struct {
		Files []json.RawMessage `json:"files"`
	} `json:"autoload"`
}

// readComposerJSON fills m from the composer.json at the top of tree.
// Fields it lacks keep what the metadata said. It is read as data only:
// its scripts are listed, never run.
func (s *Source) readComposerJSON(tree *core.Tree, m *core.Meta) {
	f, ok := tree.Lookup("composer.json")
	if !ok || !f.Mode.IsRegular() || f.Size > maxComposerJSON {
		return
	}
	rc, err := tree.Blobs.Open(f.SHA256)
	if err != nil {
		s.logf("can't read composer.json of %s: %v", m.Ref.Name, err)
		return
	}
	defer func() { _ = rc.Close() }()
	data, err := io.ReadAll(io.LimitReader(rc, maxComposerJSON+1))
	if err != nil {
		s.logf("can't read composer.json of %s: %v", m.Ref.Name, err)
		return
	}
	cj, err := parseComposerJSON(data)
	if err != nil {
		s.logf("composer.json of %s is not valid JSON: %v", m.Ref.Name, err)
		return
	}
	cj.apply(m)
}

// parseComposerJSON decodes composer.json leniently: a field of an
// unexpected type is skipped, not an error.
func parseComposerJSON(data []byte) (*composerJSON, error) {
	var cj composerJSON
	if err := json.Unmarshal(data, &cj); err != nil {
		var loose struct {
			Type, License, Require json.RawMessage
			RequireDev             json.RawMessage `json:"require-dev"`
			Scripts, Autoload      json.RawMessage
		}
		if err := json.Unmarshal(data, &loose); err != nil {
			return nil, err
		}
		cj = composerJSON{Type: loose.Type, License: loose.License, Require: loose.Require, RequireDev: loose.RequireDev}
		_ = json.Unmarshal(loose.Scripts, &cj.Scripts)
		_ = json.Unmarshal(loose.Autoload, &cj.Autoload)
	}
	return &cj, nil
}

// apply copies the fields cj has into m.
func (cj *composerJSON) apply(m *core.Meta) {
	if t := str(cj.Type); t != "" {
		m.Type = t
	}
	if l := license(cj.License); l != "" {
		m.License = l
	}
	if req := strMap(cj.Require); req != nil {
		m.Deps = req
		m.RequiresPHP = req["php"]
	}
	if dev := strMap(cj.RequireDev); dev != nil {
		m.DevDeps = dev
	}
	if len(cj.Scripts) > 0 {
		scripts := map[string][]string{}
		for _, ev := range slices.Sorted(maps.Keys(cj.Scripts)) {
			raw := cj.Scripts[ev]
			if one := str(raw); one != "" {
				scripts[ev] = []string{one}
				continue
			}
			var many []json.RawMessage
			if json.Unmarshal(raw, &many) != nil {
				continue
			}
			for _, c := range many {
				if c := str(c); c != "" {
					scripts[ev] = append(scripts[ev], c)
				}
			}
		}
		m.ComposerScripts = scripts
	}
	var files []string
	for _, f := range cj.Autoload.Files {
		if f := str(f); f != "" {
			files = append(files, f)
		}
	}
	if len(files) > 0 {
		m.AutoloadFiles = files
	}
}

// VerifyLocal compares an installed vendor/<name> with the archive of
// the same version from its repository, file by file with SHA-256 that
// Sightread computes itself (SR-19: a zipball has no published hash to
// compare with). Fewer than half the files matching makes the copy not
// the package the repository knows. An official archive that fails its
// own check can't be compared with: that is E5.
func (s *Source) VerifyLocal(ctx context.Context, ref core.Ref, local *core.Tree) (core.Drift, error) {
	m, err := s.Meta(ctx, ref)
	if err != nil {
		return core.Drift{}, err
	}
	official, in, err := s.Fetch(ctx, m)
	if err != nil {
		return core.Drift{}, err
	}
	if in.By == core.ByFailed {
		return core.Drift{}, fetch.Unverified(command, ref.Name, m.Ref.Version, in.Detail)
	}
	if d := core.GetDiffer(); d != nil {
		return d.Drift(ctx, local, official), nil
	}
	return drift(local, official), nil
}

// drift compares local with official by path and SHA-256. It is used
// only when no core.Differ is linked (package diff owns the one
// implementation run uses).
func drift(local, official *core.Tree) core.Drift {
	var d core.Drift
	have := map[string]core.File{}
	for _, f := range local.Files {
		have[f.Path] = f
	}
	want := map[string]bool{}
	for _, f := range official.Files {
		want[f.Path] = true
		switch l, ok := have[f.Path]; {
		case !ok:
			d.Missing = append(d.Missing, f.Path)
		case l.Mode.IsRegular() == f.Mode.IsRegular() && l.SHA256 == f.SHA256:
			d.Matched = append(d.Matched, f.Path)
		default:
			d.Differ = append(d.Differ, f.Path)
		}
	}
	for _, f := range local.Files {
		if !want[f.Path] {
			d.Extra = append(d.Extra, f.Path)
		}
	}
	slices.Sort(d.Extra)
	d.Official = len(official.Files) > 0 && 2*len(d.Matched) >= len(official.Files)
	return d
}
