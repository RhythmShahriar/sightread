// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package archive

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"reflect"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
)

// ReadZip indexes the zip in ra (size bytes) into blobs. archive/zip is
// used for the central directory only: every name goes through
// ValidateName, every entry is read through a counter of bytes actually
// read and nothing is written under an entry's name. What it finds wrong
// with an entry becomes a Tree.Issues entry; a limit hit is IssueLimit,
// which the analyzer reports as unanalysed. Only a total past
// lim.Uncompressed is an error: E11, which run reports as Not checked
// too-large.
func ReadZip(ctx context.Context, ra io.ReaderAt, size int64, blobs core.BlobStore, lim core.Limits, strip StripRule) (*core.Tree, error) {
	zr, err := zip.NewReader(ra, size)
	// With GODEBUG=zipinsecurepath=0 the reader also reports unsafe names;
	// ValidateName judges every name here either way.
	if err != nil && !errors.Is(err, zip.ErrInsecurePath) {
		return nil, fmt.Errorf("not a readable zip archive: %w", err)
	}
	b := newBuilder(ctx, blobs, lim)
	for i, f := range zr.File {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if i >= b.lim.Entries {
			b.limitIssue("", fmt.Sprintf("more than %d entries; the rest were not read", b.lim.Entries))
			break
		}
		if err := zipEntry(b, ra, f); err != nil {
			if errors.Is(err, errStop) {
				break
			}
			return nil, err
		}
	}
	tree := b.finish(strip)
	sum, err := hashAll(ctx, ra, size)
	if err != nil {
		return nil, err
	}
	tree.SHA256 = sum
	return tree, nil
}

// zipEntry indexes one entry.
func zipEntry(b *builder, ra io.ReaderAt, f *zip.File) error {
	raw := f.Name
	mode := f.Mode()
	isDir := mode.IsDir() || strings.HasSuffix(raw, "/") || strings.HasSuffix(raw, `\`)
	name, ok := b.name(raw, isDir)
	if !ok || isDir {
		return nil
	}
	if local, ok := localName(ra, f); ok && local != raw {
		b.issue(core.IssueMalformed, raw, local, "the local header names another file than the central directory")
	}
	if f.Flags&0x1 != 0 {
		b.issue(core.IssueEncrypted, raw, "", "encrypted; not read")
		return nil
	}
	if !mode.IsRegular() {
		target := ""
		if mode&fs.ModeSymlink != 0 {
			var err error
			if target, err = linkTarget(b, f); err != nil {
				return err
			}
		}
		b.link(raw, name, mode, target)
		return nil
	}
	rc, err := f.Open()
	if err != nil {
		b.issue(core.IssueMalformed, raw, "", "unreadable: "+shortErr(err))
		return nil
	}
	defer func() { _ = rc.Close() }()
	return b.file(raw, name, mode, rc, int64(min(f.CompressedSize64, uint64(1)<<62)))
}

// linkTarget reads a zip symlink's target, which the entry holds as its
// contents. It counts toward the total like any entry.
func linkTarget(b *builder, f *zip.File) (string, error) {
	rc, err := f.Open()
	if err != nil {
		return "", nil //nolint:nilerr // an unreadable target is recorded as empty
	}
	defer func() { _ = rc.Close() }()
	cr := &countingReader{b: b, r: io.LimitReader(rc, maxLink), compressed: -1}
	data, err := io.ReadAll(cr)
	if cr.err != nil {
		return "", cr.err
	}
	if err != nil {
		return "", nil //nolint:nilerr // as above
	}
	return string(data), nil
}

// localName reads the name in f's local file header. archive/zip keeps
// the header's offset unexported, so it is read by reflection; ok is
// false when that fails and the check is then skipped.
func localName(ra io.ReaderAt, f *zip.File) (string, bool) {
	v := reflect.ValueOf(f).Elem().FieldByName("headerOffset")
	if !v.IsValid() || v.Kind() != reflect.Int64 {
		return "", false
	}
	off := v.Int()
	var h [30]byte
	if _, err := ra.ReadAt(h[:], off); err != nil {
		return "", false
	}
	if binary.LittleEndian.Uint32(h[0:4]) != 0x04034b50 {
		return "", false
	}
	name := make([]byte, binary.LittleEndian.Uint16(h[26:28]))
	if _, err := ra.ReadAt(name, off+30); err != nil {
		return "", false
	}
	return string(name), true
}

// hashAll is the sha256 of the whole archive.
func hashAll(ctx context.Context, ra io.ReaderAt, size int64) ([32]byte, error) {
	h := sha256.New()
	if _, err := io.Copy(h, ctxReader{ctx: ctx, r: io.NewSectionReader(ra, 0, size)}); err != nil {
		return [32]byte{}, err
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
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
