// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package npm

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/RhythmShahriar/sightread/archive"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/fetch"
	"github.com/RhythmShahriar/sightread/source/changelog"
)

// The Integrity.Method texts of an npm package (PRD 18 item 4).
const (
	MethodSignature = "SHA-512 matches dist.integrity and the registry signature verifies with a pinned npm key (this proves the registry published it, not that the content is harmless)"
	MethodIntegrity = "SHA-512 matches the dist.integrity the registry publishes; no registry signature was checked"
	// MethodWeak is completed with the hash and the field: "SHA-1",
	// "dist.shasum".
	MethodWeak            = "%s matches the %s the registry publishes; this version has no SHA-512 integrity"
	MethodIntegrityFailed = "the tarball does not match the dist.integrity the registry publishes"
	MethodShasumFailed    = "the tarball does not match the dist.shasum the registry publishes"
	MethodSignatureFailed = "the registry signature does not verify with a pinned npm key"
	MethodNone            = "not verified: the registry publishes no hash for this version"
)

// Fetch downloads the tarball (hashed with SHA-512 while it streams),
// indexes it under package/, checks the hash against dist.integrity and
// the registry signature against the pinned keys. Changelog comes from
// the package's CHANGELOG.md or the like.
func (s *Source) Fetch(ctx context.Context, m *core.Meta) (*core.Tree, core.Integrity, error) {
	name, v := m.Ref.Name, m.Ref.Version
	pk := fetch.Package{Command: command, Name: name, Version: v, Archive: "tarball"}
	if m.Archive.URL == "" {
		return nil, core.Integrity{}, versionError(fmt.Sprintf("%s %s lists no tarball", name, v), name, m.Latest)
	}
	d, err := s.env.Get.Download(ctx, s.tarballURL(m.Archive.URL), s.lim.Download, s.env.Blobs)
	if err != nil {
		return nil, core.Integrity{}, pk.Wrap(err)
	}
	in := s.verify(ctx, m, d)
	tree, err := s.unpack(ctx, d)
	if err != nil {
		if in.By == core.ByFailed {
			// A tarball that fails its hash and can't be read is still
			// an integrity mismatch to report, not a gap.
			s.logf("can't read the %s tarball of %s: %v", v, name, err)
			return &core.Tree{SHA256: d.SHA256, HashKind: core.HashArchive, Blobs: s.env.Blobs}, in, nil
		}
		return nil, core.Integrity{}, pk.Wrap(err)
	}
	m.Changelog = changelog.FromTree(tree)
	// npm runs node-gyp for a binding.gyp when no install script is set.
	if f, ok := tree.Lookup("binding.gyp"); ok && f.Mode.IsRegular() {
		m.HasInstallScript = true
	}
	return tree, in, nil
}

// unpack indexes a downloaded tarball, stripping package/.
func (s *Source) unpack(ctx context.Context, d core.Download) (*core.Tree, error) {
	rc, err := s.env.Blobs.Open(d.SHA256)
	if err != nil {
		return nil, fmt.Errorf("open the downloaded tarball: %w", err)
	}
	defer func() { _ = rc.Close() }()
	tree, err := archive.ReadTarGz(ctx, rc, s.env.Blobs, s.lim, archive.StripFolder("package"))
	if err != nil {
		return nil, err
	}
	tree.SHA256, tree.HashKind = d.SHA256, core.HashArchive
	return tree, nil
}

// tarballURL points a tarball URL of the official registry at the
// configured mirror, so a mirror that copies packuments verbatim works.
func (s *Source) tarballURL(u string) string {
	official := fetch.DefaultBases()[core.BaseNPM]
	if s.base != official && strings.HasPrefix(u, official+"/") {
		return s.base + strings.TrimPrefix(u, official)
	}
	return u
}

// verify checks one download (SR-17): the strongest hash of dist.integrity
// (SHA-512; SHA-256 or SHA-1 only for old versions), the old SHA-1
// shasum only when there is no integrity at all, then the registry
// signature with a key that is both served and pinned.
func (s *Source) verify(ctx context.Context, m *core.Meta, d core.Download) core.Integrity {
	algo, digests := strongest(ParseSRI(m.Archive.Integrity))
	var got []byte
	switch algo {
	case "sha512":
		got = d.SHA512[:]
	case "sha256":
		got = d.SHA256[:]
	case "sha1":
		got = d.SHA1[:]
	default:
		want, err := hex.DecodeString(strings.TrimSpace(m.Archive.Shasum))
		if err != nil || len(want) != len(d.SHA1) {
			return core.Integrity{By: core.ByNone, Method: MethodNone, Detail: "no dist.integrity or dist.shasum"}
		}
		if !bytes.Equal(want, d.SHA1[:]) {
			return core.Integrity{By: core.ByFailed, Method: MethodShasumFailed, Mismatch: []string{"dist.shasum"},
				Detail: "SHA-1 " + hex.EncodeToString(d.SHA1[:])}
		}
		return core.Integrity{By: core.ByIntegrity, Method: fmt.Sprintf(MethodWeak, "SHA-1", "dist.shasum")}
	}
	if !matchesAny(got, digests) {
		return core.Integrity{By: core.ByFailed, Method: MethodIntegrityFailed, Mismatch: []string{"dist.integrity"},
			Detail: fmt.Sprintf("the tarball's %s is not the one dist.integrity lists", strings.ToUpper(algo))}
	}
	weak := algo != "sha512"
	in := core.Integrity{By: core.ByIntegrity, Method: MethodIntegrity}
	if weak {
		in.Method = fmt.Sprintf(MethodWeak, strings.ToUpper(algo[:3])+"-"+algo[3:], "dist.integrity")
	}
	reg, private := s.registry(m.Ref.Name)
	switch {
	case private && len(m.Archive.Signatures) == 0:
		in.Detail = "the private registry signs nothing"
		return in
	case private:
		in.Detail = "a private registry's signatures are not checked: its keys are not pinned"
		return in
	case len(m.Archive.Signatures) == 0:
		in.Detail = "the registry sent no signature for this version"
		return in
	}
	keys, err := s.keysFor(ctx, reg)
	if err != nil {
		in.Detail = "the registry keys could not be read: " + err.Error()
		return in
	}
	var why []string
	undated := false
	for _, sg := range m.Archive.Signatures {
		k, ok := keys[sg.KeyID]
		if !ok {
			why = append(why, fmt.Sprintf("key %s is not both served and pinned", clip(sg.KeyID)))
			continue
		}
		if err := verifySig(k, m.Ref.Name, m.Ref.Version, m.Archive.Integrity, sg.Sig, m.Published); err != nil {
			if errors.Is(err, errUndated) {
				undated = true
			}
			why = append(why, fmt.Sprintf("key %s: %v", clip(sg.KeyID), err))
			continue
		}
		if weak {
			return in // signed over a hash too weak to call this signature
		}
		return core.Integrity{By: core.BySignature, Method: MethodSignature}
	}
	if undated {
		in.Detail = errUndated.Error()
		return in
	}
	return core.Integrity{By: core.ByFailed, Method: MethodSignatureFailed, Mismatch: []string{"dist.signatures"},
		Detail: strings.Join(why, "; ")}
}

// keysFor loads a registry's pinned keys once per run.
func (s *Source) keysFor(ctx context.Context, reg string) (map[string]key, error) {
	s.keysMu.Lock()
	defer s.keysMu.Unlock()
	if r, ok := s.keys[reg]; ok {
		return r.keys, r.err
	}
	k, err := s.registryKeys(ctx, reg)
	s.keys[reg] = keysResult{keys: k, err: err}
	return k, err
}

func matchesAny(got []byte, digests [][]byte) bool {
	for _, d := range digests {
		if bytes.Equal(got, d) {
			return true
		}
	}
	return false
}

// clip shortens text from an answer for a message.
func clip(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}
