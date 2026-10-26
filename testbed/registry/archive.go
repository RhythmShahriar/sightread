// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha1" //nolint:gosec // Composer publishes a SHA-1 dist.shasum; the testbed must match it
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"time"
)

// epoch is the fixed modification time every archive entry carries so a
// scenario's archive bytes are identical across runs (the npm signature
// is the only thing that changes, because its key is generated per run).
var epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// treeFile is one file read from a scenario subtree, with fake key
// placeholders already expanded.
type treeFile struct {
	// Name is the slash path relative to the subtree root.
	Name string
	// Data is the file content.
	Data []byte
	// Mode is the file mode as read from disk.
	Mode fs.FileMode
}

// readTree reads every regular file under dir, expands fake key
// placeholders and returns the files sorted by name. A missing dir is an
// empty tree, so a scenario can add a package with no "from" side.
func readTree(dir string) ([]treeFile, error) {
	var files []treeFile
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) && p == dir {
				return filepath.SkipAll
			}
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		b, err := os.ReadFile(p) //nolint:gosec // fixture files under our own tree
		if err != nil {
			return err
		}
		b, err = expandFakeKeys(b)
		if err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		files = append(files, treeFile{Name: filepath.ToSlash(rel), Data: b, Mode: info.Mode()})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Name < files[j].Name })
	return files, nil
}

// buildZip packs files into a deterministic zip whose entries are all
// under top/ (the folder WordPress.org and GitHub archives carry). The
// bytes are stable across runs: fixed modification times and sorted
// entries.
func buildZip(top string, files []treeFile) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		hdr := &zip.FileHeader{Name: path.Join(top, f.Name), Method: zip.Deflate}
		hdr.SetMode(0o644)
		hdr.Modified = epoch
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(f.Data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// buildTarGz packs files into a deterministic gzipped tar whose entries
// are all under package/, the layout npm publishes.
func buildTarGz(files []treeFile) ([]byte, error) {
	var buf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	gw.ModTime = epoch
	tw := tar.NewWriter(gw)
	for _, f := range files {
		hdr := &tar.Header{
			Name:    path.Join("package", f.Name),
			Mode:    0o644,
			Size:    int64(len(f.Data)),
			ModTime: epoch,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write(f.Data); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// sha256hex returns the hex SHA-256 of b.
func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// sha1hex returns the hex SHA-1 of b, the hash Packagist publishes as
// dist.shasum.
func sha1hex(b []byte) string {
	sum := sha1.Sum(b) //nolint:gosec // matching Packagist's published shasum, not a security check
	return hex.EncodeToString(sum[:])
}

// sha512b64 returns the base64 SHA-512 of b in the npm SRI form
// "sha512-<base64>".
func sha512b64(b []byte) string {
	sum := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

// checksumsFor returns the per-file SHA-256 map WordPress.org publishes
// for a plugin or theme version, keyed by the path inside the package.
func checksumsFor(files []treeFile) map[string]string {
	m := make(map[string]string, len(files))
	for _, f := range files {
		m[f.Name] = sha256hex(f.Data)
	}
	return m
}
