// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/update"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/run"
)

// blobGrace keeps blobs stored this recently even when no index names
// them yet: a review running at the same time stores an archive's blobs
// before it writes the index.
const blobGrace = time.Hour

// pruner is the blob store's prune (blob.Disk).
type pruner interface {
	Prune(referenced map[[32]byte]bool, olderThan time.Duration) (files int, bytes int64, err error)
}

// cacheCommand is `cache prune` (PRD 6.9).
var cacheCommand = &simpleCommand{
	name: "cache", args: "prune [--older <d>]", brief: "prune", summary: "remove cached archives nothing uses",
	long: "prune removes the archive indexes saved more than --older ago and then every cached blob no remaining " +
		"index names. Reviews of those versions download them again. The signal data and metadata caches are left alone.",
	examples: []string{"cache prune", "cache prune --older 7d"},
	flags: func(fs *flag.FlagSet, _ *simpleFlags) runFunc {
		older := fs.String("older", "30d", "remove archives cached longer ago than this `duration`")
		return func(_ context.Context, pos []string, stdout, _ io.Writer) error {
			if len(pos) != 1 || pos[0] != "prune" {
				return cli.Usagef("cache takes one action: %s cache prune [--older <d>]", cli.Name())
			}
			age, err := parseDuration("older", *older)
			if err != nil {
				return err
			}
			return prune(age, time.Now(), stdout)
		}
	},
}

func prune(age time.Duration, now time.Time, stdout io.Writer) error {
	cache, err := run.CacheDir("")
	if err != nil {
		return err
	}
	indexes, referenced, err := run.PruneIndexes(cache, age, now)
	if err != nil {
		return fmt.Errorf("cache prune: %w", err)
	}
	blobs, err := core.OpenBlobs(cache)
	if err != nil {
		return err
	}
	p, ok := blobs.(pruner)
	if !ok {
		return fmt.Errorf("blob prune %w", core.ErrNotLinked)
	}
	files, size, err := p.Prune(referenced, blobGrace)
	if err != nil {
		return fmt.Errorf("cache prune: %w", err)
	}
	fmt.Fprintf(stdout, "removed %s %s and %s nothing uses (%s)\n",
		plural(indexes, "archive index", "archive indexes"), olderText(age), plural(files, "cached file"), byteSize(size))
	return nil
}

// olderText says which indexes --older took: "older than 30 days",
// "older than 45 minutes", or "(all of them)" for --older 0.
func olderText(age time.Duration) string {
	switch {
	case age <= 0:
		return "(all of them)"
	case age < time.Minute:
		return "older than " + plural(int(age/time.Second), "second")
	case age < time.Hour:
		return "older than " + plural(int(age/time.Minute), "minute")
	}
	return "older than " + update.FormatAge(age)
}

// byteSize writes n in the largest binary unit that keeps it at or above
// 1, with one decimal: 4.2 MiB.
func byteSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit && exp < 4; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}
