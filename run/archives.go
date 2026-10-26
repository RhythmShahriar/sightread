// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/RhythmShahriar/sightread/core"
)

// The archive index keeps, per version, the tree an official archive
// unpacked to (paths, sizes and blob hashes) and how it was verified, at
// <cache>/archives/<eco>/<name>/<version>.json. The bytes stay in the
// blob store, so a second review of the same version downloads nothing.

// indexSchema names the index file format.
const indexSchema = "sightread-archive/v1"

// maxIndex bounds an index file read back from the cache.
const maxIndex = 64 << 20

type indexFile struct {
	Schema    string        `json:"schema"`
	Ref       string        `json:"ref"`
	Saved     time.Time     `json:"saved"`
	Tree      indexTree     `json:"tree"`
	Integrity indexIntegrty `json:"integrity"`
}

type indexTree struct {
	Root     string              `json:"root"`
	SHA256   string              `json:"sha256"`
	HashKind string              `json:"hash_kind"`
	Bytes    int64               `json:"bytes"`
	Files    []indexEntry        `json:"files"`
	Issues   []core.ArchiveIssue `json:"issues,omitempty"`
}

type indexEntry struct {
	Path   string        `json:"path"`
	Size   int64         `json:"size"`
	SHA256 string        `json:"sha256"`
	Mode   fs.FileMode   `json:"mode"`
	Link   string        `json:"link,omitempty"`
	Kind   core.FileKind `json:"kind"`
}

type indexIntegrty struct {
	By       core.VerifiedBy `json:"by"`
	Method   string          `json:"method"`
	Mismatch []string        `json:"mismatch,omitempty"`
	Detail   string          `json:"detail,omitempty"`
}

// indexPath is where the index of ref lives, or "" when the name or
// version can't be a file name (they are escaped; "." or ".." would
// still climb out of the folder).
func indexPath(cache string, ref core.Ref) string {
	name, ver := url.PathEscape(ref.Name), url.PathEscape(ref.Version)
	for _, p := range []string{name, ver} {
		if p == "" || p == "." || p == ".." {
			return ""
		}
	}
	return filepath.Join(cache, "archives", string(ref.Eco), name, ver+".json")
}

// loadIndex returns the cached tree of ref when its index exists and
// every blob it names is still in blobs.
func loadIndex(cache string, ref core.Ref, blobs core.BlobStore) (*core.Tree, core.Integrity, bool) {
	path := indexPath(cache, ref)
	if path == "" {
		return nil, core.Integrity{}, false
	}
	f, err := os.Open(path) //nolint:gosec // a file of Sightread's own cache, by an escaped name
	if err != nil {
		return nil, core.Integrity{}, false
	}
	defer func() { _ = f.Close() }()
	var idx indexFile
	if err := json.NewDecoder(io.LimitReader(f, maxIndex)).Decode(&idx); err != nil || idx.Schema != indexSchema || idx.Ref != ref.String() {
		return nil, core.Integrity{}, false
	}
	t := &core.Tree{Root: idx.Tree.Root, HashKind: idx.Tree.HashKind, Bytes: idx.Tree.Bytes, Issues: idx.Tree.Issues, Blobs: blobs}
	if !decodeSum(idx.Tree.SHA256, &t.SHA256) {
		return nil, core.Integrity{}, false
	}
	for _, e := range idx.Tree.Files {
		file := core.File{Path: e.Path, Size: e.Size, Mode: e.Mode, Link: e.Link, Kind: e.Kind}
		if !decodeSum(e.SHA256, &file.SHA256) {
			return nil, core.Integrity{}, false
		}
		if hasContent(file) && !blobs.Has(file.SHA256) {
			return nil, core.Integrity{}, false
		}
		t.Files = append(t.Files, file)
	}
	t.SortFiles()
	in := core.Integrity{By: idx.Integrity.By, Method: idx.Integrity.Method, Mismatch: idx.Integrity.Mismatch, Detail: idx.Integrity.Detail}
	return t, in, true
}

// saveIndex records t and in for ref. A failure only costs a download
// next time, so it is returned for -v and otherwise ignored.
func saveIndex(cache string, ref core.Ref, t *core.Tree, in core.Integrity, now time.Time) error {
	path := indexPath(cache, ref)
	if path == "" {
		return fmt.Errorf("%s can't be cached under its name", ref)
	}
	idx := indexFile{Schema: indexSchema, Ref: ref.String(), Saved: now.UTC(),
		Tree:      indexTree{Root: t.Root, SHA256: hex.EncodeToString(t.SHA256[:]), HashKind: t.HashKind, Bytes: t.Bytes, Issues: t.Issues},
		Integrity: indexIntegrty{By: in.By, Method: in.Method, Mismatch: in.Mismatch, Detail: in.Detail}}
	for _, f := range t.Files {
		idx.Tree.Files = append(idx.Tree.Files, indexEntry{Path: f.Path, Size: f.Size, SHA256: hex.EncodeToString(f.SHA256[:]),
			Mode: f.Mode, Link: f.Link, Kind: f.Kind})
	}
	b, err := json.Marshal(idx)
	if err != nil {
		return err
	}
	return WriteFile(path, b)
}

// hasContent reports whether f's bytes are in the blob store: links and
// other special entries are recorded by name only.
func hasContent(f core.File) bool { return f.Mode.IsRegular() }

func decodeSum(s string, dst *[32]byte) bool {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(dst) {
		return false
	}
	copy(dst[:], b)
	return true
}

// adoptBlobs moves t's contents into dst when a source unpacked into
// another store, so the archive index always points at blobs the cache
// holds.
func adoptBlobs(ctx context.Context, t *core.Tree, dst core.BlobStore) error {
	if t.Blobs == nil || t.Blobs == dst {
		t.Blobs = dst
		return nil
	}
	for _, f := range t.Files {
		if !hasContent(f) || dst.Has(f.SHA256) {
			continue
		}
		rc, err := t.Blobs.Open(f.SHA256)
		if err != nil {
			return err
		}
		sum, _, err := dst.Put(ctx, rc, f.Size)
		_ = rc.Close()
		if err != nil {
			return err
		}
		if sum != f.SHA256 {
			return core.ErrBlobCorrupt
		}
	}
	t.Blobs = dst
	return nil
}

// WriteFile writes b to path through a temp file in the same
// folder and a rename, mode 0600 and folders 0700 (SR-13), so a reader
// never sees half a file.
func WriteFile(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, werr := tmp.Write(b)
	if err := tmp.Chmod(0o600); err != nil && werr == nil {
		werr = err
	}
	if err := tmp.Close(); err != nil && werr == nil {
		werr = err
	}
	if werr == nil {
		werr = os.Rename(name, path)
	}
	if werr != nil {
		_ = os.Remove(name)
		return errors.Join(errors.New("write "+filepath.Base(path)), werr)
	}
	return nil
}
