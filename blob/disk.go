// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package blob

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/RhythmShahriar/sightread/core"
)

func init() {
	core.SetBlobStore(func(dir string) (core.BlobStore, error) { return OpenDisk(dir) })
}

// Disk is the blob store on disk: <root>/blobs/<first two hex>/<sha256
// hex>, folders 0700 and files 0600 on Unix. A blob is written once and
// never renamed over, has no extension and never an exec bit.
type Disk struct {
	dir string // <root>/blobs
}

// tmpPrefix starts every temp file name, so Prune can tell them from
// blobs.
const tmpPrefix = ".tmp-"

// OpenDisk opens (creating it) the blob store under root, the Sightread
// cache folder.
func OpenDisk(root string) (*Disk, error) {
	dir := filepath.Join(root, "blobs")
	if err := os.MkdirAll(dir, 0o700); err != nil { //nolint:gosec // root is the user's cache folder
		return nil, fmt.Errorf("blob store: %w", err)
	}
	// MkdirAll keeps the mode of a folder that already exists; the store
	// holds package code, so it is the user's alone.
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // a folder needs its x bit; 0700 is the user's alone
			return nil, fmt.Errorf("blob store: %w", err)
		}
	}
	return &Disk{dir: dir}, nil
}

// Dir is the folder holding the blobs.
func (d *Disk) Dir() string { return d.dir }

// path is where sum lives.
func (d *Disk) path(sum [32]byte) string {
	h := hex.EncodeToString(sum[:])
	return filepath.Join(d.dir, h[:2], h)
}

// Put streams r into a temp file next to the blobs, hashing and counting
// as it goes. More than limit bytes is core.ErrTooLarge and stores
// nothing; so does a canceled ctx. The temp file is then linked under
// its hash only if no blob has that name yet, so two
// writers of the same content both succeed and a blob another process
// has open is never replaced (Windows can't rename over an open file).
func (d *Disk) Put(ctx context.Context, r io.Reader, limit int64) (sum [32]byte, n int64, err error) {
	if err := ctx.Err(); err != nil {
		return sum, 0, err
	}
	tmp, err := os.CreateTemp(d.dir, tmpPrefix+"*")
	if err != nil {
		return sum, 0, fmt.Errorf("blob store: %w", err)
	}
	name := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(name)
	}()
	h := sha256.New()
	n, err = io.Copy(io.MultiWriter(tmp, h), io.LimitReader(ctxReader{ctx: ctx, r: r}, limit+1))
	if err != nil {
		return sum, 0, err
	}
	if n > limit {
		return sum, 0, core.ErrTooLarge
	}
	// No fsync: a blob a crash tears is caught by the re-hash in Open and
	// fetched again, while a flush per file costs about 7 ms, 14 s for a
	// 2,000-file plugin.
	if err := tmp.Close(); err != nil {
		return sum, 0, fmt.Errorf("blob store: %w", err)
	}
	copy(sum[:], h.Sum(nil))
	if err := ctx.Err(); err != nil {
		return [32]byte{}, 0, err
	}
	final := d.path(sum)
	if err := os.MkdirAll(filepath.Dir(final), 0o700); err != nil {
		return [32]byte{}, 0, fmt.Errorf("blob store: %w", err)
	}
	if err := place(name, final); err != nil {
		return [32]byte{}, 0, fmt.Errorf("blob store: %w", err)
	}
	return sum, n, nil
}

// place puts the temp file tmp at final unless a blob is already there.
// A hard link fails when final exists, so nothing is ever replaced; a
// file system without hard links gets a rename after a check, which can
// only race with a writer of the same bytes.
func place(tmp, final string) error {
	err := os.Link(tmp, final)
	if err == nil {
		return nil
	}
	if errors.Is(err, fs.ErrExist) {
		// The blob is in use again: Prune goes by this time.
		now := time.Now()
		_ = os.Chtimes(final, now, now)
		return nil
	}
	if _, serr := os.Lstat(final); serr == nil {
		return nil
	}
	if rerr := os.Rename(tmp, final); rerr != nil {
		if _, serr := os.Lstat(final); serr == nil {
			return nil
		}
		return rerr
	}
	return nil
}

// ctxReader stops a copy once ctx is done.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, err
	}
	return c.r.Read(p)
}

// Open reads a blob back. The reader re-hashes what it hands out and
// fails with core.ErrBlobCorrupt at the end when the bytes don't match
// the name; the bad blob is then deleted so the next run fetches it
// again.
func (d *Disk) Open(sum [32]byte) (io.ReadCloser, error) {
	p := d.path(sum)
	f, err := os.Open(p) //nolint:gosec // a path built from a hash under the store
	if err != nil {
		return nil, fmt.Errorf("blob %x: %w", sum[:4], err)
	}
	return &checked{f: f, h: sha256.New(), want: sum, path: p}, nil
}

// checked is an open blob that verifies itself.
type checked struct {
	f    *os.File
	h    hash.Hash
	want [32]byte
	path string
	bad  bool
}

func (c *checked) Read(p []byte) (int, error) {
	if c.bad {
		return 0, core.ErrBlobCorrupt
	}
	n, err := c.f.Read(p)
	c.h.Write(p[:n])
	if errors.Is(err, io.EOF) {
		var got [32]byte
		copy(got[:], c.h.Sum(nil))
		if got != c.want {
			c.bad = true
			_ = c.f.Close()
			_ = os.Remove(c.path)
			return n, core.ErrBlobCorrupt
		}
	}
	return n, err
}

func (c *checked) Close() error {
	if c.bad {
		return nil
	}
	return c.f.Close()
}

// Has reports whether sum is stored.
func (d *Disk) Has(sum [32]byte) bool {
	fi, err := os.Lstat(d.path(sum))
	return err == nil && fi.Mode().IsRegular()
}

// Path returns sum's file on disk and whether it is there.
func (d *Disk) Path(sum [32]byte) (string, bool) {
	p := d.path(sum)
	return p, d.Has(sum)
}

// Prune removes every blob not in referenced that was last stored more
// than olderThan ago. Temp files a crashed run left behind go too once
// they are as old. It returns how many files and bytes it removed. The
// walk runs inside an os.Root, so a link planted in the folder can't
// make it remove anything outside.
func (d *Disk) Prune(referenced map[[32]byte]bool, olderThan time.Duration) (files int, bytes int64, err error) {
	root, err := os.OpenRoot(d.dir)
	if err != nil {
		return 0, 0, fmt.Errorf("blob store: %w", err)
	}
	defer func() { _ = root.Close() }()
	cutoff := time.Now().Add(-olderThan)
	err = fs.WalkDir(root.FS(), ".", func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			return nil
		}
		fi, err := e.Info()
		if err != nil || !fi.ModTime().Before(cutoff) {
			return nil //nolint:nilerr // a file that vanished mid-walk is no longer ours to prune
		}
		name := e.Name()
		if !strings.HasPrefix(name, tmpPrefix) {
			sum, ok := parseSum(name)
			if !ok || referenced[sum] {
				return nil
			}
		}
		if err := root.Remove(p); err != nil {
			return err
		}
		files++
		bytes += fi.Size()
		return nil
	})
	return files, bytes, err
}

// parseSum reads a blob file name.
func parseSum(name string) ([32]byte, bool) {
	var sum [32]byte
	if len(name) != 64 {
		return sum, false
	}
	if _, err := hex.Decode(sum[:], []byte(name)); err != nil {
		return sum, false
	}
	return sum, true
}
