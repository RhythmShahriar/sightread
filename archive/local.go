// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package archive

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/term"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/fetch"
)

func init() { core.SetLocalArchive(ReadLocal) }

// Magic bytes of the formats ReadLocal reads.
var (
	zipMagic      = []byte("PK\x03\x04")
	zipEmptyMagic = []byte("PK\x05\x06")
	gzipMagic     = []byte{0x1f, 0x8b}
)

// ReadLocal reads a zip or tgz on disk (--to-file, --from-file and
// config local_files), picking the format by its first bytes rather
// than its name. A single top folder is stripped. Anything else is an
// E12 *core.Error naming the file. A folder is not an archive: run reads
// one with Inventory.LocalTree.
func ReadLocal(ctx context.Context, path string, blobs core.BlobStore, lim core.Limits) (*core.Tree, error) {
	lim = withDefaults(lim)
	f, err := os.Open(path) //nolint:gosec // a file the user named
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", term.Sanitize(path), err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, notArchive(path)
	}
	if fi.Size() > lim.Download {
		return nil, fetch.OverSize(term.Sanitize(path), lim.Download)
	}
	head := make([]byte, 4)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	switch {
	case bytes.HasPrefix(head, zipMagic), bytes.HasPrefix(head, zipEmptyMagic):
		return ReadZip(ctx, f, fi.Size(), blobs, lim, StripSingle)
	case bytes.HasPrefix(head, gzipMagic):
		return readLocalTarGz(ctx, f, fi.Size(), blobs, lim)
	}
	return nil, notArchive(path)
}

// notArchive is the E12 error of a file that is neither zip nor tgz.
func notArchive(path string) *core.Error {
	return &core.Error{
		Code: core.EBadConfig, Exit: cli.ExitUsage,
		What: term.Sanitize(path) + " is not a zip or tgz archive",
		Hint: []string{"give the plugin, theme or package archive itself (.zip, .tgz or .tar.gz)"},
	}
}

// readLocalTarGz reads a local tgz. The file's hash is taken first, so
// Tree.SHA256 is set even when a limit stops the walk early.
func readLocalTarGz(ctx context.Context, f *os.File, size int64, blobs core.BlobStore, lim core.Limits) (*core.Tree, error) {
	sum, err := hashAll(ctx, f, size)
	if err != nil {
		return nil, err
	}
	tree, err := ReadTarGz(ctx, io.NewSectionReader(f, 0, size), blobs, lim, StripSingle)
	if err != nil {
		return nil, err
	}
	tree.SHA256 = sum
	return tree, nil
}
