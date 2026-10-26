// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/RhythmShahriar/sightread/archive"
	"github.com/RhythmShahriar/sightread/core"
)

// maxLocalPath is the longest path LocalTree accepts, as archives do.
const maxLocalPath = 1024

// sniffBytes is how much of each file LocalTree keeps to guess its
// kind.
const sniffBytes = 8 << 10

// LocalTree reads an installed plugin, theme or vendor package folder
// into a tree, the shape an archive gives, so run can diff it and check
// drift. It reads with os.Lstat and never follows a link inside dir: a
// link is recorded with Mode symlink, its target text as Link and that
// text as its contents. The archive limits apply; a file over
// lim.EntryStored, an unreadable file, a special file or a path with a
// control character becomes an issue rather than an error. The tree's
// hash is the manifest hash, so it matches a zip of the same files.
// dir itself may be a link, since the user named it.
func LocalTree(ctx context.Context, dir string, blobs core.BlobStore, lim core.Limits) (*core.Tree, error) {
	fi, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a folder", dir)
	}
	w := &localWalk{ctx: ctx, blobs: blobs, lim: lim, tree: &core.Tree{
		Root:     filepath.Base(filepath.Clean(dir)) + "/",
		HashKind: core.HashManifest,
		Blobs:    blobs,
	}}
	if err := w.walk(dir, ""); err != nil && !errors.Is(err, errStopWalk) {
		return nil, err
	}
	w.tree.SortFiles()
	w.tree.SHA256 = core.ManifestHash(w.tree.Files)
	return w.tree, nil
}

// errStopWalk ends a walk that hit the entry or total size limit; the
// issue is already recorded.
var errStopWalk = errors.New("limit reached")

// localWalk is one LocalTree call.
type localWalk struct {
	ctx     context.Context
	blobs   core.BlobStore
	lim     core.Limits
	tree    *core.Tree
	entries int
}

// issue records a problem with one entry.
func (w *localWalk) issue(kind core.ArchiveIssueKind, p, other, detail string) {
	w.tree.Issues = append(w.tree.Issues, core.ArchiveIssue{Kind: kind, Path: p, Other: other, Detail: detail})
}

// walk adds the entries of dir, whose path in the tree is prefix.
func (w *localWalk) walk(dir, prefix string) error {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if prefix == "" {
			return err
		}
		w.issue(core.IssueMalformed, prefix, "", "couldn't read the folder: "+errText(err))
		return nil
	}
	for _, e := range ents {
		if err := w.ctx.Err(); err != nil {
			return err
		}
		rel := e.Name()
		if prefix != "" {
			rel = prefix + "/" + e.Name()
		}
		if bad := localPathProblem(rel); bad != "" {
			w.issue(core.IssueMalformed, rel, "", bad)
			continue
		}
		fi, err := e.Info() // Lstat: a link stays a link
		if err != nil {
			w.issue(core.IssueMalformed, rel, "", "couldn't read: "+errText(err))
			continue
		}
		if fi.IsDir() {
			if err := w.walk(filepath.Join(dir, e.Name()), rel); err != nil {
				return err
			}
			continue
		}
		w.entries++
		if w.lim.Entries > 0 && w.entries > w.lim.Entries {
			w.issue(core.IssueLimit, rel, "", fmt.Sprintf("more than %d entries; the rest were not read", w.lim.Entries))
			return errStopWalk
		}
		if err := w.add(filepath.Join(dir, e.Name()), rel, fi); err != nil {
			return err
		}
	}
	return nil
}

// add stores one non-folder entry.
func (w *localWalk) add(full, rel string, fi fs.FileInfo) error {
	mode := fi.Mode()
	switch {
	case mode&fs.ModeSymlink != 0:
		target, err := os.Readlink(full)
		if err != nil {
			w.issue(core.IssueMalformed, rel, "", "couldn't read the link: "+errText(err))
			return nil
		}
		return w.store(rel, strings.NewReader(target), fs.ModeSymlink|mode.Perm(), target)
	case !mode.IsRegular():
		w.issue(core.IssueMalformed, rel, "", "it is "+fileKind(mode)+", not a regular file; not read")
		return nil
	}
	if w.lim.EntryStored > 0 && fi.Size() > w.lim.EntryStored {
		w.issue(core.IssueLimit, rel, "", fmt.Sprintf("%d bytes, over the %d byte limit for one file", fi.Size(), w.lim.EntryStored))
		return nil
	}
	f, err := openRegular(full)
	if err != nil {
		w.issue(core.IssueMalformed, rel, "", "couldn't read: "+errText(err))
		return nil
	}
	defer func() { _ = f.Close() }()
	return w.store(rel, f, mode.Perm(), "")
}

// store puts r in the blob store and records the file.
func (w *localWalk) store(rel string, r io.Reader, mode fs.FileMode, link string) error {
	limit := w.lim.EntryStored
	if limit <= 0 {
		limit = core.DefaultLimits().EntryStored
	}
	sniff := &headBuffer{max: sniffBytes}
	sum, n, err := w.blobs.Put(w.ctx, io.TeeReader(r, sniff), limit)
	switch {
	case errors.Is(err, core.ErrTooLarge):
		w.issue(core.IssueLimit, rel, "", fmt.Sprintf("over the %d byte limit for one file", limit))
		return nil
	case w.ctx.Err() != nil:
		return w.ctx.Err()
	case err != nil:
		w.issue(core.IssueMalformed, rel, "", "couldn't read: "+errText(err))
		return nil
	}
	if w.lim.Uncompressed > 0 && w.tree.Bytes+n > w.lim.Uncompressed {
		w.issue(core.IssueLimit, rel, "", fmt.Sprintf("the folder holds over %d bytes; the rest were not read", w.lim.Uncompressed))
		return errStopWalk
	}
	kind := FileKindOf(rel, sniff.b)
	if link != "" {
		kind = core.KindText
	}
	w.tree.Files = append(w.tree.Files, core.File{Path: rel, Size: n, SHA256: sum, Mode: mode, Link: link, Kind: kind})
	w.tree.Bytes += n
	return nil
}

// localPathProblem says what is wrong with a local path, or "". Local
// names can't hold "..", "/" or a drive, so only length and control
// characters are checked.
func localPathProblem(p string) string {
	if len(p) > maxLocalPath {
		return fmt.Sprintf("path is over %d bytes", maxLocalPath)
	}
	if strings.ContainsFunc(p, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "path holds a control character"
	}
	return ""
}

// headBuffer keeps the first max bytes written to it.
type headBuffer struct {
	b   []byte
	max int
}

func (h *headBuffer) Write(p []byte) (int, error) {
	if room := h.max - len(h.b); room > 0 {
		h.b = append(h.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

// FileKindOf is a file's kind from its path, by the rule archive entries
// get (archive.KindOf), so an installed copy and the official archive of
// the same package classify every file alike: the analyzer then checks
// the same files for code. A JavaScript file whose head is one long line
// is minified, which the analyzer would conclude from the contents too.
func FileKindOf(p string, head []byte) core.FileKind {
	k := archive.KindOf(p)
	if k == core.KindJS && minified(head) {
		return core.KindMinified
	}
	return k
}

// minified reports whether a JavaScript head looks minified: over 1,000
// bytes with no line break in the first 1,000.
func minified(head []byte) bool {
	return len(head) > 1000 && bytes.IndexByte(head[:1000], '\n') < 0
}
