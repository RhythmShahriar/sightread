// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"slices"
	"sort"
	"strings"
)

// FileKind is how the analyzer treats a file.
type FileKind string

// The file kinds.
const (
	KindPHP      FileKind = "php"
	KindJS       FileKind = "js"
	KindJSON     FileKind = "json"
	KindText     FileKind = "text"
	KindBinary   FileKind = "binary"
	KindMinified FileKind = "minified"
	KindArchive  FileKind = "archive"
	KindAsset    FileKind = "asset"
)

// File is one entry of a package. Its bytes live in the tree's
// BlobStore under SHA256, never on disk under their own name.
type File struct {
	Path   string // validated, slash separated, relative to Tree.Root
	Size   int64
	SHA256 [32]byte
	Mode   fs.FileMode // regular, or ModeSymlink and friends (never followed)
	Link   string      // link target text as written in the archive
	Kind   FileKind
}

// ArchiveIssueKind is a problem found while unpacking an archive.
type ArchiveIssueKind string

// The archive issues; each maps to an archive-* or unanalysed finding.
const (
	IssuePathEscape ArchiveIssueKind = "path-escape"
	IssueLink       ArchiveIssueKind = "link"
	IssueLinkEscape ArchiveIssueKind = "link-escape"
	IssueCollision  ArchiveIssueKind = "collision"
	IssueLimit      ArchiveIssueKind = "limit"
	IssueEncrypted  ArchiveIssueKind = "encrypted"
	IssueMalformed  ArchiveIssueKind = "malformed"
)

// ArchiveIssue is one problem with one entry. Path is the entry name as
// the archive wrote it, sanitised by whoever prints it.
type ArchiveIssue struct {
	Kind   ArchiveIssueKind
	Path   string
	Other  string // the colliding name, or the link target
	Detail string
}

// Hash kinds of Tree.HashKind.
const (
	HashArchive  = "archive"  // sha256 of the archive bytes
	HashManifest = "manifest" // ManifestHash of the files (WordPress.org zips are rebuilt)
)

// Tree is one unpacked version of a package.
type Tree struct {
	Root     string // stripped top folder ("akismet/", "package/", "<owner>-<repo>-<sha>/")
	Files    []File // sorted by Path
	Issues   []ArchiveIssue
	Bytes    int64    // uncompressed total
	SHA256   [32]byte // archive bytes, or manifest hash when HashKind == "manifest"
	HashKind string   // HashArchive or HashManifest
	Blobs    BlobStore
}

// Lookup finds the file at path. Files must be sorted by Path.
func (t *Tree) Lookup(path string) (File, bool) {
	i := sort.Search(len(t.Files), func(i int) bool { return t.Files[i].Path >= path })
	if i < len(t.Files) && t.Files[i].Path == path {
		return t.Files[i], true
	}
	return File{}, false
}

// SortFiles sorts t.Files by Path, as Lookup needs.
func (t *Tree) SortFiles() {
	slices.SortFunc(t.Files, func(a, b File) int { return strings.Compare(a.Path, b.Path) })
}

// ManifestHash is sha256 over the sorted "path\tsha256hex\n" lines of
// files. It identifies a WordPress.org release whose zip can be rebuilt
// with other bytes but the same files.
func ManifestHash(files []File) [32]byte {
	lines := make([]string, len(files))
	for i, f := range files {
		lines[i] = f.Path + "\t" + hex.EncodeToString(f.SHA256[:]) + "\n"
	}
	sort.Strings(lines)
	h := sha256.New()
	for _, l := range lines {
		_, _ = io.WriteString(h, l)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

// BlobStore keeps file contents by their sha256.
type BlobStore interface {
	// Put stores up to limit bytes of r. More than limit is ErrTooLarge
	// and stores nothing.
	Put(ctx context.Context, r io.Reader, limit int64) (sum [32]byte, n int64, err error)
	// Open reads a blob back and re-hashes it as it goes; a mismatch is
	// ErrBlobCorrupt at the end of the read.
	Open(sum [32]byte) (io.ReadCloser, error)
	Has(sum [32]byte) bool
	// Path is the blob's file on disk for the --soundcheck hand-off;
	// false for memory stores.
	Path(sum [32]byte) (string, bool)
}

// Errors shared by blob stores, archives and downloads.
var (
	ErrBlobCorrupt = errors.New("cached blob does not match its hash")
	ErrTooLarge    = errors.New("over the size limit")
)
