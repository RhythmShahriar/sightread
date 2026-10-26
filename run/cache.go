// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/config"
	"github.com/RhythmShahriar/sightread/core"
)

// CacheDir returns the Sightread cache folder: dir when set, else
// config.CacheDir("sightread").
func CacheDir(dir string) (string, error) {
	if dir != "" {
		return dir, nil
	}
	return config.CacheDir("sightread")
}

// CachedTree returns the verified tree of ref from the archive index
// under cache, with every blob it names still in blobs. explain reads
// the hunks of a saved report through it.
func CachedTree(cache string, ref core.Ref, blobs core.BlobStore) (*core.Tree, bool) {
	t, _, ok := loadIndex(cache, ref, blobs)
	return t, ok
}

// PruneIndexes removes the archive indexes under cache saved more than
// olderThan before now and returns how many it removed and the blobs
// the indexes it kept still name, so the blob store can drop the rest.
// A file that isn't an index of this version is left alone and names
// nothing.
func PruneIndexes(cache string, olderThan time.Duration, now time.Time) (removed int, referenced map[[32]byte]bool, err error) {
	referenced = map[[32]byte]bool{}
	// The walk runs inside an os.Root, so a link planted in the cache
	// can't make it read or remove anything outside archives/.
	root, err := os.OpenRoot(filepath.Join(cache, "archives"))
	if errors.Is(err, fs.ErrNotExist) {
		return 0, referenced, nil
	}
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = root.Close() }()
	cutoff := now.Add(-olderThan)
	err = fs.WalkDir(root.FS(), ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.Type().IsRegular() || !strings.HasSuffix(d.Name(), ".json") {
			return nil
		}
		idx, ok := readIndex(root, path)
		if !ok {
			return nil
		}
		if idx.Saved.Before(cutoff) {
			if err := root.Remove(path); err != nil {
				return err
			}
			removed++
			return nil
		}
		var sum [32]byte
		for _, e := range idx.Tree.Files {
			if decodeSum(e.SHA256, &sum) {
				referenced[sum] = true
			}
		}
		return nil
	})
	return removed, referenced, err
}

// readIndex decodes one index file inside root.
func readIndex(root *os.Root, path string) (*indexFile, bool) {
	f, err := root.Open(path)
	if err != nil {
		return nil, false
	}
	defer func() { _ = f.Close() }()
	var idx indexFile
	if err := json.NewDecoder(io.LimitReader(f, maxIndex)).Decode(&idx); err != nil || idx.Schema != indexSchema {
		return nil, false
	}
	return &idx, true
}

// Verify fetches and verifies one published version the way a review
// does (through the archive cache) and returns the report's view of it.
// allow uses it to bind an entry to the hash of the bytes it checked.
// The Side's Verified is core.ByNone when nothing could check it and
// core.ByFailed when a published hash doesn't match.
func Verify(ctx context.Context, req Request, ref core.Ref) (core.Side, error) {
	r := &reviewer{req: req}
	if err := r.setup(); err != nil {
		return core.Side{}, err
	}
	src := core.SourceFor(ref.Eco, r.env)
	if src == nil {
		return core.Side{}, fmt.Errorf("%s source %w", ref.Eco, core.ErrNotLinked)
	}
	m, err := src.Meta(ctx, ref)
	if err != nil {
		return core.Side{}, withCommand(err, req.Command)
	}
	tree, in, _, err := r.fetch(ctx, src, m)
	if err != nil {
		return core.Side{}, err
	}
	if len(in.Mismatch) > 0 && in.By != core.ByFailed {
		// A mismatch is a failed check whatever the source called it.
		in.By = core.ByFailed
	}
	return r.sideInfo(ref, m, tree, in, ""), nil
}
