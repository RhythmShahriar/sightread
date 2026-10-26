// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package archive

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/RhythmShahriar/sightread/core"
)

// ReadZipDownload indexes a zip the Getter downloaded into blobs. A zip
// needs random access, so it is read from the blob's file when the
// store has one and from memory otherwise (the memory store of tests
// and the demo). Either way the bytes ReadZip hashed must be the bytes
// that were downloaded: a blob changed on disk since is
// core.ErrBlobCorrupt, never a tree.
func ReadZipDownload(ctx context.Context, d core.Download, blobs core.BlobStore, lim core.Limits, strip StripRule) (*core.Tree, error) {
	ra, closeFn, err := openDownload(d, blobs)
	if err != nil {
		return nil, err
	}
	defer closeFn()
	tree, err := ReadZip(ctx, ra, d.Size, blobs, lim, strip)
	if err != nil {
		return nil, err
	}
	if tree.SHA256 != d.SHA256 {
		return nil, fmt.Errorf("read the downloaded zip: %w", core.ErrBlobCorrupt)
	}
	return tree, nil
}

// openDownload gives random access to a downloaded blob. A blob on disk
// is first read through the store's self-checking Open, which deletes
// it when its bytes don't match its name, so a torn or changed blob
// fails this run only and the next download stores it fresh.
func openDownload(d core.Download, blobs core.BlobStore) (io.ReaderAt, func(), error) {
	path := d.Path
	if path == "" {
		path, _ = blobs.Path(d.SHA256)
	}
	if path != "" {
		if err := verify(d, blobs); err != nil {
			return nil, nil, err
		}
		f, err := os.Open(path) //nolint:gosec // a path the blob store gave for a hash
		if err != nil {
			return nil, nil, fmt.Errorf("open the downloaded archive: %w", err)
		}
		return f, func() { _ = f.Close() }, nil
	}
	rc, err := blobs.Open(d.SHA256)
	if err != nil {
		return nil, nil, fmt.Errorf("open the downloaded archive: %w", err)
	}
	defer func() { _ = rc.Close() }()
	// One byte past the size reaches EOF, where the store checks its hash.
	data, err := io.ReadAll(io.LimitReader(rc, d.Size+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read the downloaded archive: %w", err)
	}
	if int64(len(data)) != d.Size {
		return nil, nil, fmt.Errorf("read the downloaded archive: %w", core.ErrBlobCorrupt)
	}
	return bytes.NewReader(data), func() {}, nil
}

// verify reads the whole blob through the store, which re-hashes it.
func verify(d core.Download, blobs core.BlobStore) error {
	rc, err := blobs.Open(d.SHA256)
	if err != nil {
		return fmt.Errorf("open the downloaded archive: %w", err)
	}
	defer func() { _ = rc.Close() }()
	n, err := io.Copy(io.Discard, rc)
	if err != nil {
		return fmt.Errorf("read the downloaded archive: %w", err)
	}
	if n != d.Size {
		return fmt.Errorf("read the downloaded archive: %w", core.ErrBlobCorrupt)
	}
	return nil
}
