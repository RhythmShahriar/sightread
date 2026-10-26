// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package coretest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"maps"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/RhythmShahriar/sightread/core"
)

// memBlobs is a BlobStore in memory.
type memBlobs struct {
	mu sync.Mutex
	m  map[[32]byte][]byte
}

// MemBlobs returns an empty in-memory BlobStore. Path always reports
// false.
func MemBlobs() core.BlobStore { return &memBlobs{m: map[[32]byte][]byte{}} }

func (b *memBlobs) Put(ctx context.Context, r io.Reader, limit int64) ([32]byte, int64, error) {
	if err := ctx.Err(); err != nil {
		return [32]byte{}, 0, err
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return [32]byte{}, 0, err
	}
	if int64(len(data)) > limit {
		return [32]byte{}, 0, core.ErrTooLarge
	}
	sum := sha256.Sum256(data)
	b.mu.Lock()
	b.m[sum] = data
	b.mu.Unlock()
	return sum, int64(len(data)), nil
}

func (b *memBlobs) Open(sum [32]byte) (io.ReadCloser, error) {
	b.mu.Lock()
	data, ok := b.m[sum]
	b.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("blob %x: not stored", sum[:4])
	}
	if sha256.Sum256(data) != sum {
		return nil, core.ErrBlobCorrupt
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

func (b *memBlobs) Has(sum [32]byte) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.m[sum]
	return ok
}

func (b *memBlobs) Path([32]byte) (string, bool) { return "", false }

// Tree builds a tree from path to contents in a fresh MemBlobs. It
// panics on a path an archive would refuse, so a fixture can't hold one
// by accident; use TreeWith to add archive issues.
func Tree(files map[string]string) *core.Tree { return TreeWith(files, nil) }

// TreeWith is Tree with archive issues attached.
func TreeWith(files map[string]string, issues []core.ArchiveIssue) *core.Tree {
	t := &core.Tree{Blobs: MemBlobs(), HashKind: core.HashManifest, Issues: issues}
	for _, p := range slices.Sorted(maps.Keys(files)) {
		if err := checkPath(p); err != nil {
			panic("coretest.Tree: " + err.Error())
		}
		data := files[p]
		sum, n, err := t.Blobs.Put(context.Background(), strings.NewReader(data), int64(len(data)))
		if err != nil {
			panic("coretest.Tree: " + err.Error())
		}
		t.Files = append(t.Files, core.File{Path: p, Size: n, SHA256: sum, Mode: 0o644, Kind: KindOf(p, data)})
		t.Bytes += n
	}
	t.SHA256 = core.ManifestHash(t.Files)
	return t
}

// checkPath refuses what the archive rules of PRD 11 refuse.
func checkPath(p string) error {
	switch {
	case p == "" || len(p) > 1024:
		return fmt.Errorf("path %q: empty or over 1,024 bytes", p)
	case strings.HasPrefix(p, "/") || strings.Contains(p, `\`) || len(p) > 1 && p[1] == ':':
		return fmt.Errorf("path %q: absolute, drive or backslash", p)
	case strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }):
		return fmt.Errorf("path %q: control byte", p)
	}
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." || seg == "." || seg == "" {
			return fmt.Errorf("path %q: %q segment", p, seg)
		}
	}
	return nil
}

// KindOf guesses a fixture file's kind from its name and contents, the
// way tests need it: .php is PHP, .js and friends are JS (minified when
// one line is long), images and fonts are assets.
func KindOf(p, data string) core.FileKind {
	switch strings.ToLower(path.Ext(p)) {
	case ".php", ".phtml", ".inc":
		return core.KindPHP
	case ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx":
		if strings.HasSuffix(p, ".min.js") || len(data) > 1000 && !strings.Contains(data[:1000], "\n") {
			return core.KindMinified
		}
		return core.KindJS
	case ".json":
		return core.KindJSON
	case ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".woff", ".woff2", ".ttf", ".eot", ".mo":
		return core.KindAsset
	case ".zip", ".tgz", ".gz", ".tar", ".phar":
		return core.KindArchive
	}
	if strings.ContainsRune(data, 0) {
		return core.KindBinary
	}
	return core.KindText
}

// Read returns a file's contents from t, failing loudly on a fixture
// mistake.
func Read(t *core.Tree, p string) string {
	f, ok := t.Lookup(p)
	if !ok {
		panic("coretest.Read: no " + p)
	}
	rc, err := t.Blobs.Open(f.SHA256)
	if err != nil {
		panic("coretest.Read: " + err.Error())
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(rc)
	if err != nil {
		panic("coretest.Read: " + err.Error())
	}
	return string(b)
}
