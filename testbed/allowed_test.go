// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package testbed_test

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/testbed/registry"
)

// TestB18AllowEntryMatchesRelease keeps b18 the case it claims to be: the
// allow entry in projects/wp pins the manifest hash of the reviewed
// 1.0.0 release, computed here with core.ManifestHash over the archive
// the registry builds. If the files or the hash definition change, the
// entry would stop matching and b18 would silently test something else.
func TestB18AllowEntryMatchesRelease(t *testing.T) {
	reg, err := registry.New(registry.Options{PackagesDir: "packages", StateDir: t.TempDir(), PlainHTTP: true, AnyPort: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reg.Close() }()
	archive, ok := reg.Archive("b18-approved", "1.0.0")
	if !ok {
		t.Fatal("the registry built no b18-approved 1.0.0")
	}
	got := manifestHash(t, archive, "b18-approved/")

	var allowed struct {
		Allowed []struct {
			Package, Version, SHA256, Hash string
		}
	}
	b, err := os.ReadFile(filepath.Join("projects", "wp", ".sightread", "allowed.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(b, &allowed); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range allowed.Allowed {
		if a.Package != "wp-plugin:b18-approved" || a.Version != "1.0.0" {
			continue
		}
		found = true
		if a.Hash != core.HashManifest {
			t.Errorf("the b18 entry has hash %q, want %q", a.Hash, core.HashManifest)
		}
		if a.SHA256 != got {
			t.Errorf("the b18 entry pins %s, the 1.0.0 release hashes to %s", a.SHA256, got)
		}
	}
	if !found {
		t.Fatal("allowed.yaml has no entry for wp-plugin:b18-approved 1.0.0")
	}

	// The check can fail: the republished 1.0.0 (the bad candidate) has
	// other files and so another manifest hash.
	if bad := manifestHashOfDir(t, filepath.Join("packages", "b18-approved", "new")); bad == got {
		t.Error("the republished tree hashes like the reviewed one; b18 would be allowed")
	}
}

// manifestHash unzips archive, strips root and returns core.ManifestHash
// of its regular files in hex.
func manifestHash(t *testing.T, archive []byte, root string) string {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		t.Fatal(err)
	}
	var files []core.File
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, core.File{Path: strings.TrimPrefix(f.Name, root), Size: int64(len(data)), SHA256: sha256.Sum256(data)})
	}
	sum := core.ManifestHash(files)
	return hex.EncodeToString(sum[:])
}

// manifestHashOfDir returns core.ManifestHash of the files under dir.
func manifestHashOfDir(t *testing.T, dir string) string {
	t.Helper()
	var files []core.File
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(p) //nolint:gosec // our own fixture tree
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		files = append(files, core.File{Path: filepath.ToSlash(rel), Size: int64(len(data)), SHA256: sha256.Sum256(data)})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sum := core.ManifestHash(files)
	return hex.EncodeToString(sum[:])
}
