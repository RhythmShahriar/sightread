// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package archive

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/fetch"
)

// StripRule says which top folder ReadZip removes from every path. The
// stripped folder is recorded as Tree.Root.
type StripRule struct {
	// Top strips the one folder every entry sits in: "akismet/" of a
	// WordPress.org zip, "<owner>-<repo>-<sha>/" of a GitHub zipball,
	// "package/" of an npm tarball. An archive with several top folders,
	// or a file at the top, keeps its paths.
	Top bool
	// Only, when set, strips that folder only when it has this name.
	Only string
}

// StripSingle strips whatever single top folder there is.
var StripSingle = StripRule{Top: true}

// StripFolder strips the single top folder when it is named name.
func StripFolder(name string) StripRule { return StripRule{Top: true, Only: strings.Trim(name, "/")} }

// ratioFloor is the size an entry must reach before its compression
// ratio counts (PRD 11: 200:1 on entries over 1 MiB).
const ratioFloor = 1 << 20

// maxLink caps the link target text read from an archive.
const maxLink = 4096

// errRatio stops a read whose compression ratio is past the limit.
var errRatio = errors.New("compression ratio over the limit")

// builder collects one archive's entries into a tree. It is shared by
// the zip and tar readers, which only differ in how they walk entries.
type builder struct {
	ctx   context.Context
	blobs core.BlobStore
	lim   core.Limits
	tree  *core.Tree
	total int64          // bytes read from every entry
	paths map[string]int // path to the copies seen, for name#2
	cases map[string]string
	tops  map[string]bool // first segment of every accepted name
	flat  bool            // a file sits at the top
	// stream counts the compressed bytes a tar.gz reader consumed, so a
	// tar entry's ratio can be measured; nil for zip.
	stream *int64
}

func newBuilder(ctx context.Context, blobs core.BlobStore, lim core.Limits) *builder {
	return &builder{
		ctx: ctx, blobs: blobs, lim: withDefaults(lim),
		tree:  &core.Tree{Blobs: blobs, HashKind: core.HashArchive},
		paths: map[string]int{}, cases: map[string]string{}, tops: map[string]bool{},
	}
}

// withDefaults fills limits left at zero from core.DefaultLimits, so a
// caller that forgets one never runs without it.
func withDefaults(l core.Limits) core.Limits {
	d := core.DefaultLimits()
	if l.Uncompressed <= 0 {
		l.Uncompressed = d.Uncompressed
	}
	if l.EntryStored <= 0 {
		l.EntryStored = d.EntryStored
	}
	if l.Entries <= 0 {
		l.Entries = d.Entries
	}
	if l.Ratio <= 0 {
		l.Ratio = d.Ratio
	}
	if l.Download <= 0 {
		l.Download = d.Download
	}
	return l
}

func (b *builder) issue(kind core.ArchiveIssueKind, raw, other, detail string) {
	b.tree.Issues = append(b.tree.Issues, core.ArchiveIssue{Kind: kind, Path: raw, Other: other, Detail: detail})
}

// limitIssue records a limit hit; the analyzer reports the package as
// unanalysed, never clean.
func (b *builder) limitIssue(raw, detail string) { b.issue(core.IssueLimit, raw, "", detail) }

// name validates raw and notes where it sits. dir is true for a folder
// entry, whose one trailing slash is dropped first. ok false means the
// entry was refused and recorded.
func (b *builder) name(raw string, dir bool) (string, bool) {
	n := raw
	if dir {
		n = strings.TrimSuffix(n, "/")
		n = strings.TrimSuffix(n, `\`)
	}
	clean, kind, ok := ValidateName(n)
	if !ok {
		detail := escapeDetail(n)
		if kind == core.IssueMalformed {
			detail = "empty, too long, not UTF-8 or with a control character"
		}
		b.issue(kind, raw, "", detail)
		return "", false
	}
	top, _, nested := strings.Cut(clean, "/")
	b.tops[top] = true
	if !nested && !dir {
		b.flat = true
	}
	return clean, true
}

// unique returns the path a file is kept under: its own, or name#2,
// name#3 for later copies of a duplicate. Duplicates and names that
// differ only in case or Unicode form are recorded as collisions.
func (b *builder) unique(raw, name string) string {
	key := CaseKey(name)
	if first, ok := b.cases[key]; ok && first != name {
		b.issue(core.IssueCollision, raw, first, "differs only in case")
	}
	if _, ok := b.cases[key]; !ok {
		b.cases[key] = name
	}
	n := b.paths[name]
	b.paths[name] = n + 1
	if n == 0 {
		return name
	}
	kept := name
	for i := n + 1; ; i++ {
		kept = fmt.Sprintf("%s#%d", name, i)
		if _, taken := b.paths[kept]; !taken {
			break
		}
	}
	b.paths[kept] = 1
	detail := "duplicate entry"
	if raw != name {
		detail = "duplicate entry (same name in another Unicode form or with backslashes)"
	}
	b.issue(core.IssueCollision, raw, name, detail+"; this copy is kept as "+kept)
	return kept
}

// countingReader counts the bytes actually read from one entry against
// the entry's compressed size and the archive total.
type countingReader struct {
	b          *builder
	r          io.Reader
	read       int64
	compressed int64 // the entry's compressed size, or -1 for none
	// stream, when set, counts the compressed bytes of a gzip stream; the
	// entry's compressed size is then what it advanced past streamAt.
	stream   *int64
	streamAt int64
	err      error // errRatio or the total cap, once passed
}

// packed is the entry's compressed size so far, or -1 when it has none.
func (c *countingReader) packed() int64 {
	if c.stream != nil {
		return *c.stream - c.streamAt
	}
	return c.compressed
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	n, err := c.r.Read(p)
	c.read += int64(n)
	c.b.total += int64(n)
	switch {
	case c.b.total > c.b.lim.Uncompressed:
		c.err = fetch.TooLarge(c.b.lim.Uncompressed)
	case c.read > ratioFloor && c.packed() >= 0 && c.read > int64(c.b.lim.Ratio)*max(c.packed(), 1):
		c.err = errRatio
	}
	if c.err != nil {
		return n, c.err
	}
	return n, err
}

// errStop ends the walk early with what the tree has so far.
var errStop = errors.New("stop reading the archive")

// file stores one regular entry. compressed is its compressed size, or
// -1 when it has none; a tar entry counts what the gzip stream advanced
// instead (builder.stream). It returns errStop or an E11 error when the
// walk must end.
func (b *builder) file(raw, name string, mode fs.FileMode, r io.Reader, compressed int64) error {
	cr := &countingReader{b: b, r: r, compressed: compressed}
	if b.stream != nil {
		cr.stream, cr.streamAt = b.stream, *b.stream
	}
	sum, n, err := b.blobs.Put(b.ctx, cr, b.lim.EntryStored)
	switch {
	case cr.err != nil && errors.Is(cr.err, errRatio):
		b.limitIssue(raw, fmt.Sprintf("expands more than %d:1; the rest of the archive was not read", b.lim.Ratio))
		return errStop
	case cr.err != nil:
		return cr.err
	case b.ctx.Err() != nil:
		return b.ctx.Err()
	case errors.Is(err, core.ErrTooLarge):
		b.limitIssue(raw, "entry over "+fetch.Size(b.lim.EntryStored)+"; not stored")
		return nil
	case err != nil:
		b.issue(core.IssueMalformed, raw, "", "unreadable: "+shortErr(err))
		return nil
	}
	path := b.unique(raw, name)
	b.tree.Files = append(b.tree.Files, core.File{Path: path, Size: n, SHA256: sum, Mode: mode.Perm(), Kind: KindOf(name)})
	b.tree.Bytes += n
	return nil
}

// link records a link or other non-regular entry with its target text.
// Its bytes are never stored or followed.
func (b *builder) link(raw, name string, mode fs.FileMode, target string) {
	path := b.unique(raw, name)
	b.tree.Files = append(b.tree.Files, core.File{Path: path, Mode: mode, Link: target, Kind: core.KindBinary})
	switch {
	case mode&fs.ModeSymlink != 0 && escapes(name, target):
		b.issue(core.IssueLinkEscape, raw, target, "symlink to outside the package")
	case mode&fs.ModeSymlink != 0:
		b.issue(core.IssueLink, raw, target, "symlink")
	default:
		b.issue(core.IssueLink, raw, target, nonRegular(mode))
	}
}

// hardLink records a tar hard link. Its Mode is fs.ModeIrregular, so
// like every entry that is not a regular file it has no blob; the target
// is another entry's name, resolved from the archive root.
func (b *builder) hardLink(raw, name string, perm fs.FileMode, target string) {
	path := b.unique(raw, name)
	b.tree.Files = append(b.tree.Files, core.File{Path: path, Mode: fs.ModeIrregular | perm, Link: target, Kind: core.KindBinary})
	if hardEscapes(target) {
		b.issue(core.IssueLinkEscape, raw, target, "hard link to outside the package")
		return
	}
	b.issue(core.IssueLink, raw, target, "hard link")
}

// nonRegular names a non-regular mode.
func nonRegular(mode fs.FileMode) string {
	switch {
	case mode&fs.ModeNamedPipe != 0:
		return "named pipe"
	case mode&fs.ModeCharDevice != 0:
		return "character device"
	case mode&fs.ModeDevice != 0:
		return "block device"
	case mode&fs.ModeSocket != 0:
		return "socket"
	}
	return "irregular file"
}

// escapes reports whether a symlink at name pointing to target leaves
// the package: an absolute or drive target, one that climbs above the
// archive root, or one that leaves the top folder name sits in (the
// package root once that folder is stripped). Backslashes count as
// separators, as they would for the Windows user who unpacks it.
func escapes(name, target string) bool {
	t := strings.ReplaceAll(target, `\`, "/")
	if t == "" {
		return false
	}
	if strings.HasPrefix(t, "/") || hasDrive(t) {
		return true
	}
	j := path.Join(path.Dir(name), t)
	if j == ".." || strings.HasPrefix(j, "../") {
		return true
	}
	top, _, nested := strings.Cut(name, "/")
	return nested && j != top && !strings.HasPrefix(j, top+"/")
}

// hardEscapes reports whether a hard link's target, a name inside the
// archive that an extractor resolves from the archive root, would leave
// it: anything ValidateName refuses.
func hardEscapes(target string) bool {
	_, _, ok := ValidateName(strings.TrimSuffix(target, "/"))
	return !ok
}

// finish strips the top folder by rule and sorts the files.
func (b *builder) finish(strip StripRule) *core.Tree {
	if strip.Top && !b.flat && len(b.tops) == 1 {
		var top string
		for t := range b.tops {
			top = t
		}
		if strip.Only == "" || strip.Only == top {
			b.tree.Root = top + "/"
			for i := range b.tree.Files {
				b.tree.Files[i].Path = strings.TrimPrefix(b.tree.Files[i].Path, b.tree.Root)
			}
		}
	}
	b.tree.SortFiles()
	return b.tree
}

// shortErr is an error's text without the wrapping a reader adds.
func shortErr(err error) string {
	s := err.Error()
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}
