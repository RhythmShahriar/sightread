// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

// runStamp names a saved report: UTC with milliseconds, so names sort by
// time and two runs in one second don't collide.
const runStamp = "20060102T150405.000Z"

// RunsDir is the folder under the cache that keeps the last reports.
func RunsDir(cache string) string { return filepath.Join(cache, "runs") }

// saveRun writes r as JSON to <cache>/runs/<UTC time>.json, mode 0600,
// and keeps the newest RunsKept. explain and watch read them back. It
// returns the path written.
func saveRun(cache string, r *core.Report, version string, now time.Time) (string, error) {
	w := core.WriterFor(core.FormatJSON)
	if w == nil {
		return "", fmt.Errorf("json writer %w", core.ErrNotLinked)
	}
	var b bytes.Buffer
	if err := w.Write(&b, r, core.WriteOptions{Program: cli.Name(), Version: version}); err != nil {
		return "", err
	}
	dir := RunsDir(cache)
	path := filepath.Join(dir, now.UTC().Format(runStamp)+".json")
	for i := 2; ; i++ {
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			break
		}
		path = filepath.Join(dir, fmt.Sprintf("%s-%d.json", now.UTC().Format(runStamp), i))
	}
	if err := WriteFile(path, b.Bytes()); err != nil {
		return "", err
	}
	return path, pruneRuns(dir, RunsKept)
}

// pruneRuns removes all but the newest keep reports in dir.
func pruneRuns(dir string, keep int) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range entries {
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".json") {
			names = append(names, e.Name())
		}
	}
	slices.Sort(names)
	var errs []error
	for len(names) > keep {
		if err := os.Remove(filepath.Join(dir, names[0])); err != nil {
			errs = append(errs, err)
		}
		names = names[1:]
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}
