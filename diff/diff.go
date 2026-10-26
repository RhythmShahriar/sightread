// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package diff

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"slices"
	"strings"

	"github.com/RhythmShahriar/sightread/core"
)

func init() { core.SetDiffer(Differ{}) }

// Differ implements core.Differ. The zero value is ready to use.
type Differ struct{}

// maxRead is the most of one blob the differ reads. Blob stores keep at
// most 64 MiB per entry, so this only guards against a store that
// doesn't.
const maxRead = 64 << 20

// Similarity renames: a removed and an added text file of the same kind
// pair as a rename when their line sets overlap by at least
// minSimilarity (Jaccard). The search is skipped when either side has
// more than maxRenameFiles unpaired files; files over maxRenameSize
// are not read for it, so a release that rewrites everything stays fast.
const (
	minSimilarity  = 0.6
	maxRenameFiles = 2000
	maxRenameSize  = 4 << 20
	renameWork     = 1 << 28
	renameKeep     = 8 // best candidates kept per added file
)

// maxCountSize is the largest modified file whose lines are counted by
// content; a bigger one counts the change in its number of lines.
const maxCountSize = 16 << 20

// Diff compares old and new file by file. Files are paired by path. A
// file whose hash is unchanged but whose mode is not is ModeChanged. An
// unpaired removed file and an unpaired added file with the same SHA-256
// are a rename with similarity 1; text files left over pair as renames
// by line similarity. A modified text file whose bytes differ only in
// CRLF against LF is marked EOLOnly. Either tree may be nil (empty).
//
// Changes are sorted by new path (old path for a removed file), then
// old path. Line counts come from the blobs: an added or removed file
// counts its lines, a modified one the lines added and removed as a
// multiset, which equals the line diff when no lines moved.
func (Differ) Diff(ctx context.Context, old, new *core.Tree) (*core.Diff, error) {
	d := &core.Diff{Old: old, New: new}
	oldFiles, newFiles := files(old), files(new)
	if old != nil {
		d.Stats.BytesFrom = old.Bytes
	}
	if new != nil {
		d.Stats.BytesTo = new.Bytes
	}
	newByPath := make(map[string]*core.File, len(newFiles))
	for _, f := range newFiles {
		newByPath[f.Path] = f
	}
	var removed, added []*core.File
	paired := make(map[string]bool, len(oldFiles))
	for _, o := range oldFiles {
		n, ok := newByPath[o.Path]
		if !ok {
			removed = append(removed, o)
			continue
		}
		paired[o.Path] = true
		switch {
		case identity(o) != identity(n):
			d.Changes = append(d.Changes, core.FileChange{Kind: core.Modified, Old: o, New: n})
		case o.Mode != n.Mode:
			d.Changes = append(d.Changes, core.FileChange{Kind: core.ModeChanged, Old: o, New: n})
		}
	}
	for _, n := range newFiles {
		if !paired[n.Path] {
			added = append(added, n)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	removed, added = renamesByHash(d, removed, added)
	removed, added, err := renamesBySimilarity(ctx, d, removed, added)
	if err != nil {
		return nil, err
	}
	for _, f := range removed {
		d.Changes = append(d.Changes, core.FileChange{Kind: core.Removed, Old: f})
	}
	for _, f := range added {
		d.Changes = append(d.Changes, core.FileChange{Kind: core.Added, New: f})
	}
	slices.SortFunc(d.Changes, compareChanges)
	if err := stats(ctx, d); err != nil {
		return nil, err
	}
	return d, nil
}

// files lists the files of t, which may be nil.
func files(t *core.Tree) []*core.File {
	if t == nil {
		return nil
	}
	out := make([]*core.File, len(t.Files))
	for i := range t.Files {
		out[i] = &t.Files[i]
	}
	return out
}

// changeKey is the path a change sorts under: new, else old.
func changeKey(c core.FileChange) string {
	if c.New != nil {
		return c.New.Path
	}
	return c.Old.Path
}

// compareChanges orders changes by changeKey, then old path.
func compareChanges(x, y core.FileChange) int {
	if c := strings.Compare(changeKey(x), changeKey(y)); c != 0 {
		return c
	}
	var xo, yo string
	if x.Old != nil {
		xo = x.Old.Path
	}
	if y.Old != nil {
		yo = y.Old.Path
	}
	return strings.Compare(xo, yo)
}

// identity is what tells two versions of a file apart: its SHA-256, or
// for a link its target text. An archive records a link's target with no
// blob (a zero hash) while an installed folder stores the target text as
// the link's contents; both give the hash of the target here, so a link
// pointing at the same place is unchanged and one moved elsewhere is
// modified, whichever side read it.
func identity(f *core.File) [32]byte {
	if f.Link != "" {
		return sha256.Sum256([]byte(f.Link))
	}
	return f.SHA256
}

// renamesByHash pairs removed and added files with the same hash, in
// path order on both sides. It returns the files left.
func renamesByHash(d *core.Diff, removed, added []*core.File) (restRemoved, restAdded []*core.File) {
	bySum := map[[32]byte][]*core.File{}
	for _, f := range removed {
		k := identity(f)
		bySum[k] = append(bySum[k], f)
	}
	for _, n := range added {
		if k := identity(n); len(bySum[k]) > 0 {
			q := bySum[k]
			bySum[k] = q[1:]
			d.Changes = append(d.Changes, core.FileChange{Kind: core.Renamed, Old: q[0], New: n, Similarity: 1})
			continue
		}
		restAdded = append(restAdded, n)
	}
	for _, f := range removed {
		if k := identity(f); len(bySum[k]) > 0 && bySum[k][0] == f {
			bySum[k] = bySum[k][1:]
			restRemoved = append(restRemoved, f)
		}
	}
	return restRemoved, restAdded
}

// textKind reports whether files of kind k are compared as text.
func textKind(k core.FileKind) bool {
	switch k {
	case core.KindPHP, core.KindJS, core.KindJSON, core.KindText, core.KindMinified:
		return true
	}
	return false
}

// lineSet is the sorted distinct hashes of a file's non-blank lines.
type lineSet []uint64

// candidate is a possible similarity rename.
type candidate struct {
	old, new int // indexes into removed and added
	sim      float64
}

// renamesBySimilarity pairs left-over text files of the same kind whose
// line sets overlap by at least minSimilarity, best pairs first. It
// returns the files left.
func renamesBySimilarity(ctx context.Context, d *core.Diff, removed, added []*core.File) (restRemoved, restAdded []*core.File, err error) {
	if len(removed) == 0 || len(added) == 0 || len(removed) > maxRenameFiles || len(added) > maxRenameFiles {
		return removed, added, nil
	}
	seed := maphash.MakeSeed()
	sets := func(t *core.Tree, fs []*core.File) ([]lineSet, error) {
		out := make([]lineSet, len(fs))
		for i, f := range fs {
			if !textKind(f.Kind) || f.Size > maxRenameSize || f.Size == 0 {
				continue
			}
			b, err := readBlob(t, f)
			if errors.Is(err, errNoBlobs) {
				return nil, nil
			}
			if err != nil {
				return nil, err
			}
			if !hasNUL(b) {
				out[i] = lines(seed, b)
			}
		}
		return out, nil
	}
	rs, err := sets(d.Old, removed)
	if err != nil || rs == nil {
		return removed, added, err
	}
	as, err := sets(d.New, added)
	if err != nil || as == nil {
		return removed, added, err
	}
	var cands []candidate
	work := renameWork
	for j, n := range added {
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		var best []candidate
		for i, o := range removed {
			if o.Kind != n.Kind || len(rs[i]) == 0 || len(as[j]) == 0 {
				continue
			}
			lo, hi := min(len(rs[i]), len(as[j])), max(len(rs[i]), len(as[j]))
			if float64(lo) < minSimilarity*float64(hi) {
				continue // the union is too big for the overlap to reach it
			}
			work -= lo + hi
			if work < 0 {
				break
			}
			if s := jaccard(rs[i], as[j]); s >= minSimilarity {
				best = append(best, candidate{i, j, s})
				slices.SortStableFunc(best, func(x, y candidate) int { return cmpSim(y.sim, x.sim) })
				best = best[:min(len(best), renameKeep)]
			}
		}
		cands = append(cands, best...)
	}
	slices.SortStableFunc(cands, func(x, y candidate) int {
		if c := cmpSim(y.sim, x.sim); c != 0 {
			return c
		}
		if c := strings.Compare(added[x.new].Path, added[y.new].Path); c != 0 {
			return c
		}
		return strings.Compare(removed[x.old].Path, removed[y.old].Path)
	})
	usedOld, usedNew := make([]bool, len(removed)), make([]bool, len(added))
	for _, c := range cands {
		if usedOld[c.old] || usedNew[c.new] {
			continue
		}
		usedOld[c.old], usedNew[c.new] = true, true
		d.Changes = append(d.Changes, core.FileChange{Kind: core.Renamed, Old: removed[c.old], New: added[c.new], Similarity: float32(c.sim)})
	}
	for i, f := range removed {
		if !usedOld[i] {
			restRemoved = append(restRemoved, f)
		}
	}
	for j, f := range added {
		if !usedNew[j] {
			restAdded = append(restAdded, f)
		}
	}
	return restRemoved, restAdded, nil
}

// cmpSim compares two similarities.
func cmpSim(x, y float64) int {
	switch {
	case x < y:
		return -1
	case x > y:
		return 1
	}
	return 0
}

// lines hashes the non-blank lines of b, trailing spaces and CR
// trimmed, into a sorted set.
func lines(seed maphash.Seed, b []byte) lineSet {
	var out lineSet
	for len(b) > 0 {
		end := bytes.IndexByte(b, '\n')
		if end < 0 {
			end = len(b)
		}
		line := bytes.TrimRight(b[:end], " \t\r")
		b = b[min(end+1, len(b)):]
		if len(line) > 0 {
			out = append(out, maphash.Bytes(seed, line))
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// jaccard is |a ∩ b| / |a ∪ b| of two sorted sets.
func jaccard(a, b lineSet) float64 {
	i, j, both := 0, 0, 0
	for i < len(a) && j < len(b) {
		switch {
		case a[i] == b[j]:
			both++
			i++
			j++
		case a[i] < b[j]:
			i++
		default:
			j++
		}
	}
	return float64(both) / float64(len(a)+len(b)-both)
}

// errNoBlobs is a tree without a blob store: its contents can't be read,
// so the differ works on hashes alone.
var errNoBlobs = errors.New("the tree has no blob store")

// readBlob reads f's bytes from t's blob store.
func readBlob(t *core.Tree, f *core.File) ([]byte, error) {
	if f.Link != "" {
		// A link's contents are its target text: an archive stores no
		// blob for it and an installed folder stores that same text.
		return []byte(f.Link), nil
	}
	if t == nil || t.Blobs == nil {
		return nil, errNoBlobs
	}
	rc, err := t.Blobs.Open(f.SHA256)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", f.Path, err)
	}
	defer func() { _ = rc.Close() }()
	b, err := io.ReadAll(io.LimitReader(rc, maxRead+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", f.Path, err)
	}
	if len(b) > maxRead {
		return nil, fmt.Errorf("%s: %w", f.Path, core.ErrTooLarge)
	}
	return b, nil
}

// stats fills d.Stats and marks line-ending-only changes. Trees without
// a blob store count files only.
func stats(ctx context.Context, d *core.Diff) error {
	seed := maphash.MakeSeed()
	for i := range d.Changes {
		if err := ctx.Err(); err != nil {
			return err
		}
		c := &d.Changes[i]
		switch c.Kind {
		case core.Added:
			d.Stats.FilesAdded++
		case core.Removed:
			d.Stats.FilesRemoved++
		default:
			d.Stats.FilesChanged++
		}
		if c.Kind == core.ModeChanged || c.Kind == core.Renamed && c.Old.SHA256 == c.New.SHA256 {
			continue
		}
		if c.Old != nil && !textKind(c.Old.Kind) || c.New != nil && !textKind(c.New.Kind) {
			continue
		}
		old, err := readSide(d.Old, c.Old)
		if err == nil {
			var new []byte
			new, err = readSide(d.New, c.New)
			if err == nil {
				count(seed, d, c, old, new)
				continue
			}
		}
		if !errors.Is(err, errNoBlobs) {
			return err
		}
	}
	return nil
}

// count adds the lines of one text change to d.Stats.
func count(seed maphash.Seed, d *core.Diff, c *core.FileChange, old, new []byte) {
	if hasNUL(old) || hasNUL(new) {
		return
	}
	if c.Old != nil && c.New != nil && eolOnly(old, new) {
		c.EOLOnly = true
		return
	}
	if len(old) > maxCountSize || len(new) > maxCountSize {
		if o, n := lineCount(old), lineCount(new); n > o {
			d.Stats.LinesAdded += n - o
		} else {
			d.Stats.LinesRemoved += o - n
		}
		return
	}
	seen := map[uint64]int{}
	eachLine(old, func(l []byte) { seen[maphash.Bytes(seed, l)]++ })
	eachLine(new, func(l []byte) {
		h := maphash.Bytes(seed, l)
		if seen[h] > 0 {
			seen[h]--
			return
		}
		d.Stats.LinesAdded++
	})
	for _, n := range seen {
		d.Stats.LinesRemoved += n
	}
}

// eolOnly reports whether a and b differ but are equal once every CRLF
// is read as LF.
func eolOnly(a, b []byte) bool {
	crlf, lf := []byte("\r\n"), []byte("\n")
	return !bytes.Equal(a, b) && bytes.Equal(bytes.ReplaceAll(a, crlf, lf), bytes.ReplaceAll(b, crlf, lf))
}

// lineCount counts the lines of b: its newlines, plus one for a last
// line without one.
func lineCount(b []byte) int {
	n := bytes.Count(b, []byte("\n"))
	if len(b) > 0 && b[len(b)-1] != '\n' {
		n++
	}
	return n
}

// eachLine calls fn with each line of b, without its newline.
func eachLine(b []byte, fn func([]byte)) {
	for len(b) > 0 {
		end := bytes.IndexByte(b, '\n')
		if end < 0 {
			fn(b)
			return
		}
		fn(b[:end])
		b = b[end+1:]
	}
}
