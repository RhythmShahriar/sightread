// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package fsnap records a folder tree (every path with its type, mode,
// size and content hash) and compares two records. The benchmark walks
// HOME and the project fixtures before and after each run to count files
// Sightread wrote outside its work folders; the --soundcheck cases
// prove the host project stays byte-identical while the update lands in
// the container.
package fsnap

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Entry is one path of a snapshot.
type Entry struct {
	// Kind is "file", "dir" or "link".
	Kind string
	// Mode is the permission bits.
	Mode fs.FileMode
	// Size is the file size; zero for folders.
	Size int64
	// Digest is the SHA-256 of a file's content or a link's target.
	Digest string
}

// Snapshot maps slash-separated paths, relative to the root, to entries.
type Snapshot map[string]Entry

// Take records every path under root. A missing root is an empty
// snapshot, so a folder that appears during a run shows up as added.
// Paths whose relative form starts with one of skip (slash-separated
// prefixes) are left out, for the work folders that are meant to change.
func Take(root string, skip ...string) (Snapshot, error) {
	s := Snapshot{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && path == root {
				return fs.SkipAll
			}
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		for _, p := range skip {
			if rel == p || strings.HasPrefix(rel, p+"/") {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		e := Entry{Mode: info.Mode().Perm()}
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			e.Kind, e.Digest = "link", digest(strings.NewReader(target))
		case d.IsDir():
			e.Kind = "dir"
		default:
			f, err := os.Open(path) //nolint:gosec // walking a tree the caller chose
			if err != nil {
				return err
			}
			e.Kind, e.Size, e.Digest = "file", info.Size(), digest(f)
			_ = f.Close()
		}
		s[rel] = e
		return nil
	})
	return s, err
}

// digest hashes r, or returns "unreadable" when it cannot be read.
func digest(r io.Reader) string {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "unreadable"
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Change is one difference between two snapshots.
type Change struct {
	// Path is the slash-separated path relative to the root.
	Path string
	// What is "added", "removed" or "changed".
	What string
}

// String renders "added: path".
func (c Change) String() string { return c.What + ": " + c.Path }

// Diff lists what changed from before to after, sorted by path.
func Diff(before, after Snapshot) []Change {
	var out []Change
	for p, a := range after {
		b, ok := before[p]
		switch {
		case !ok:
			out = append(out, Change{p, "added"})
		case a != b:
			out = append(out, Change{p, "changed"})
		}
	}
	for p := range before {
		if _, ok := after[p]; !ok {
			out = append(out, Change{p, "removed"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// Digest is one hash over the whole snapshot, for a byte-identical check
// that prints short.
func (s Snapshot) Digest() string {
	paths := make([]string, 0, len(s))
	for p := range s {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		e := s[p]
		fmt.Fprintf(h, "%s\x00%s\x00%o\x00%d\x00%s\n", p, e.Kind, e.Mode, e.Size, e.Digest)
	}
	return hex.EncodeToString(h.Sum(nil))
}
