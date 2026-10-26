// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package stage

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/internal/proc"
)

// applyTimeout bounds one install on the staging copy.
const applyTimeout = 15 * time.Minute

// verifiedZip writes the reviewed archive of ref to a temp file named
// <slug>.<version>.zip, for WP-CLI. Every byte comes from the cache and
// is hashed again on the way: an archive kept whole must equal the
// reviewed sha256 and a WordPress.org release, whose zip is rebuilt
// from its files, must have every file match its recorded hash (SR-71).
// done removes the temp folder.
func (s *stager) verifiedZip(ref core.Ref, sha string) (path string, done func(), err error) {
	t, ok := s.p.Tree(ref)
	if !ok {
		return "", nil, &core.Error{Code: core.ESoundcheckMissing, Exit: cli.ExitUnavailable, Command: s.p.Command,
			What: fmt.Sprintf("%s %s isn't in the archive cache, so --soundcheck can't install the reviewed bytes", ref.Name, ref.Version),
			Hint: []string{"review it again: verified archives stay cached for 30 days (an unverified one is never cached)"}}
	}
	if hex.EncodeToString(t.SHA256[:]) != sha || sha == "" {
		return "", nil, s.tampered(ref)
	}
	dir, err := os.MkdirTemp("", "sightread-stage-*")
	if err != nil {
		return "", nil, err
	}
	done = func() { _ = os.RemoveAll(dir) }
	path = filepath.Join(dir, unsafeSnapshot.ReplaceAllString(ref.Name+"."+ref.Version, "-")+".zip")
	if t.HashKind == core.HashManifest {
		err = s.zipTree(t, ref, path)
	} else {
		err = s.copyArchive(t, ref, path)
	}
	if err != nil {
		done()
		return "", nil, err
	}
	return path, done, nil
}

// tampered is the refusal when cached bytes differ from the reviewed
// ones.
func (s *stager) tampered(ref core.Ref) error {
	return &core.Error{Code: core.EIntegrityMismatch, Exit: cli.ExitUnavailable, Command: s.p.Command,
		What: fmt.Sprintf("the cached archive of %s %s doesn't match the reviewed sha256, so --soundcheck won't install it", ref.Name, ref.Version),
		Hint: []string{"the cache changed after the review; run the review again and look at why"}}
}

// copyArchive copies an archive kept whole, hashing it as it goes.
func (s *stager) copyArchive(t *core.Tree, ref core.Ref, dst string) error {
	src, ok := s.p.Blobs.Path(t.SHA256)
	if !ok {
		return &core.Error{Code: core.ESoundcheckMissing, Exit: cli.ExitUnavailable, Command: s.p.Command,
			What: fmt.Sprintf("the archive of %s %s isn't a file in the cache, so --soundcheck can't hand it to WP-CLI", ref.Name, ref.Version)}
	}
	in, err := os.Open(src) //nolint:gosec // a blob of Sightread's own cache, by hash
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // inside a fresh temp folder
	if err != nil {
		return err
	}
	h := sha256.New()
	_, err = io.Copy(io.MultiWriter(out, h), in)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	if !equalSum(h.Sum(nil), t.SHA256) {
		return s.tampered(ref)
	}
	return nil
}

// zipTree packs a tree into a zip under its top folder, checking each
// file's bytes against its recorded hash.
func (s *stager) zipTree(t *core.Tree, ref core.Ref, dst string) error {
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) //nolint:gosec // inside a fresh temp folder
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()
	zw := zip.NewWriter(out)
	root := strings.TrimSuffix(t.Root, "/")
	if root == "" {
		root = ref.Name
	}
	for _, f := range t.Files {
		if !f.Mode.IsRegular() {
			continue // links and other entries are never installed
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: root + "/" + f.Path, Method: zip.Deflate, Modified: time.Unix(0, 0).UTC()})
		if err != nil {
			return err
		}
		rc, err := t.Blobs.Open(f.SHA256)
		if err != nil {
			return s.tampered(ref)
		}
		h := sha256.New()
		_, err = io.Copy(io.MultiWriter(w, h), rc)
		_ = rc.Close()
		if err != nil || !equalSum(h.Sum(nil), f.SHA256) {
			return s.tampered(ref)
		}
	}
	if core.ManifestHash(t.Files) != t.SHA256 {
		return s.tampered(ref)
	}
	if err := zw.Close(); err != nil {
		return err
	}
	return out.Close()
}

func equalSum(got []byte, want [32]byte) bool {
	return hex.EncodeToString(got) == hex.EncodeToString(want[:])
}

// installZip has WP-CLI install the verified zip on the staging copy.
func (s *stager) installZip(ctx context.Context, eco core.Ecosystem, ref core.Ref, zipPath string) error {
	kind := "plugin"
	if eco == core.WPTheme {
		kind = "theme"
	}
	argv := append(append([]string{}, s.p.WP...), kind, "install", zipPath, "--force")
	return s.runApply(ctx, argv, proc.PurposeWPCLI, ref)
}

// runApply runs an install command on the staging copy.
func (s *stager) runApply(ctx context.Context, argv []string, purpose string, ref core.Ref) error {
	res, err := proc.Run(ctx, proc.Spec{Argv: argv, Purpose: purpose, Timeout: applyTimeout, Log: s.p.Log})
	if err != nil || res.Code != 0 {
		e := s.ranBadly("the install", res.Code, res.Stderr, err).(*core.Error) //nolint:errorlint,forcetypeassert // ranBadly returns *core.Error
		e.What = fmt.Sprintf("couldn't install %s %s on %s: %s exited %d", ref.Name, ref.Version, s.host, filepath.Base(argv[0]), res.Code)
		return e
	}
	return nil
}
