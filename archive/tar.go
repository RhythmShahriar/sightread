// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package archive

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
)

// maxTrailing caps the bytes read after the end of the tar archive or
// the gzip stream while looking for hidden data. Zero padding is normal
// (tar pads to its record size); anything else, or more than this, is
// reported as malformed.
const maxTrailing = 1 << 20

// ReadTarGz indexes the tar.gz streaming from r into blobs with the
// rules of ReadZip: every name through ValidateName, entries read
// through a counter of bytes actually read, links, devices and pipes
// recorded and never followed, duplicates and collisions kept. PAX and
// GNU long names are judged like any other. A nested archive is stored
// as a file, never opened. A tar entry has no compressed size of its
// own, so its ratio is measured against the gzip bytes its read used.
//
// Tree.SHA256 is the hash of every byte of r and is set only when the
// stream was read to its end; a walk that a limit stopped leaves it zero
// (the caller has the download's hash). Data after the end of the tar
// archive or of the gzip stream, where an extractor would not look, is
// IssueMalformed. A total past lim.Uncompressed is E11, as for ReadZip.
func ReadTarGz(ctx context.Context, r io.Reader, blobs core.BlobStore, lim core.Limits, strip StripRule) (*core.Tree, error) {
	h := sha256.New()
	raw := &rawCounter{r: io.TeeReader(r, h)}
	// gzip reads a ByteReader directly, so it never pulls bytes past its
	// own stream from br and the trailing check below sees them.
	br := bufio.NewReader(raw)
	gz, err := gzip.NewReader(br)
	if err != nil {
		return nil, fmt.Errorf("not a readable gzip stream: %w", err)
	}
	// One gzip member only: a second one is data a tar extractor that
	// stops at the end-of-archive marker would never show.
	gz.Multistream(false)
	b := newBuilder(ctx, blobs, lim)
	b.stream = &raw.n
	complete, err := tarEntries(b, tar.NewReader(gz))
	if err != nil {
		return nil, err
	}
	if complete {
		if complete, err = tarTrailing(b, gz, br); err != nil {
			return nil, err
		}
	}
	tree := b.finish(strip)
	if complete {
		copy(tree.SHA256[:], h.Sum(nil))
	}
	return tree, nil
}

// tarEntries walks the entries. complete is false when the walk stopped
// early (a limit or an unreadable archive).
func tarEntries(b *builder, tr *tar.Reader) (complete bool, err error) {
	for i := 0; ; i++ {
		if err := b.ctx.Err(); err != nil {
			return false, err
		}
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return true, nil
		}
		// With GODEBUG=tarinsecurepath=0 the reader also reports unsafe
		// names; ValidateName judges every name here either way.
		if err != nil && !errors.Is(err, tar.ErrInsecurePath) {
			b.issue(core.IssueMalformed, "", "", "unreadable archive: "+shortErr(err)+"; the rest was not read")
			return false, nil
		}
		if i >= b.lim.Entries {
			b.limitIssue("", fmt.Sprintf("more than %d entries; the rest were not read", b.lim.Entries))
			return false, nil
		}
		if err := tarEntry(b, tr, hdr); err != nil {
			if errors.Is(err, errStop) {
				return false, nil
			}
			return false, err
		}
	}
}

// tarEntry indexes one entry.
func tarEntry(b *builder, tr *tar.Reader, hdr *tar.Header) error {
	raw := hdr.Name
	// A regular entry whose name ends in a slash is a folder to every
	// extractor.
	isDir := hdr.Typeflag == tar.TypeDir || hdr.Typeflag == tar.TypeReg && strings.HasSuffix(raw, "/")
	name, ok := b.name(raw, isDir)
	if !ok || isDir {
		return nil
	}
	perm := fs.FileMode(hdr.Mode).Perm() //nolint:gosec // only the permission bits are kept
	switch hdr.Typeflag {
	case tar.TypeReg, tar.TypeGNUSparse:
		if err := b.file(raw, name, perm, tr, -1); err != nil {
			return err
		}
		return skipRest(b, raw, tr)
	case tar.TypeSymlink:
		b.link(raw, name, fs.ModeSymlink|perm, clip(hdr.Linkname))
	case tar.TypeLink:
		b.hardLink(raw, name, perm, clip(hdr.Linkname))
	case tar.TypeChar:
		b.link(raw, name, fs.ModeDevice|fs.ModeCharDevice|perm, "")
	case tar.TypeBlock:
		b.link(raw, name, fs.ModeDevice|perm, "")
	case tar.TypeFifo:
		b.link(raw, name, fs.ModeNamedPipe|perm, "")
	default:
		b.link(raw, name, fs.ModeIrregular|perm, "")
	}
	return nil
}

// skipRest reads what is left of an entry the store did not take (one
// over lim.EntryStored, or unreadable) through the counter, so the bytes
// tar would otherwise skip uncounted still meet the total and the ratio.
func skipRest(b *builder, raw string, tr io.Reader) error {
	cr := &countingReader{b: b, r: tr, compressed: -1, stream: b.stream, streamAt: *b.stream}
	_, _ = io.Copy(io.Discard, cr)
	switch {
	case errors.Is(cr.err, errRatio):
		b.limitIssue(raw, fmt.Sprintf("expands more than %d:1; the rest of the archive was not read", b.lim.Ratio))
		return errStop
	case cr.err != nil:
		return cr.err
	}
	return nil
}

// clip caps link target text at maxLink bytes.
func clip(s string) string {
	if len(s) > maxLink {
		return s[:maxLink]
	}
	return s
}

// tarTrailing reads what follows the tar end-of-archive marker inside
// the gzip stream, then what follows the gzip stream. Both are counted
// against the uncompressed total. complete is false when the check gave
// up past maxTrailing bytes.
func tarTrailing(b *builder, gz *gzip.Reader, br *bufio.Reader) (complete bool, err error) {
	cr := &countingReader{b: b, r: gz, compressed: -1}
	inner, err := hidden(io.LimitReader(cr, maxTrailing+1))
	switch {
	case cr.err != nil:
		return false, cr.err
	case err != nil:
		b.issue(core.IssueMalformed, "", "", "unreadable gzip stream: "+shortErr(err))
		return false, nil
	case inner:
		b.issue(core.IssueMalformed, "", "", "data after the end of the tar archive; not read")
	}
	if inner {
		// Whatever is left of the stream is part of that hidden data.
		return false, nil
	}
	outer, err := hidden(io.LimitReader(br, maxTrailing+1))
	switch {
	case err != nil:
		return false, err
	case outer:
		b.issue(core.IssueMalformed, "", "", "data after the end of the gzip stream; not read")
		return false, nil
	}
	return true, nil
}

// hidden reads r to its end and reports whether it held a byte other
// than zero, or more than maxTrailing bytes.
func hidden(r io.Reader) (bool, error) {
	var buf [32 << 10]byte
	var total int64
	for {
		n, err := r.Read(buf[:])
		total += int64(n)
		for _, c := range buf[:n] {
			if c != 0 {
				return true, nil
			}
		}
		if total > maxTrailing {
			return true, nil
		}
		if errors.Is(err, io.EOF) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
	}
}

// rawCounter counts the compressed bytes read from the archive.
type rawCounter struct {
	r io.Reader
	n int64
}

func (c *rawCounter) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
