// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/run"
)

// explainContext is how many lines of context explain shows around a
// finding's hunk (PRD 6.5).
const explainContext = 6

// explainCommand is `explain`: a signal's explain text, or one finding
// of a saved report with its diff hunk from the archive cache.
var explainCommand = &simpleCommand{
	name: "explain", args: "<signal-id> | <report.json> <n|fingerprint>",
	brief:   "<signal-id>",
	summary: "what a signal means and how to review it",
	long: "With a signal ID, prints what the signal means, why it matters, how to review it, its usual false alarms and " +
		"the incidents it is built on. It needs no network. With a saved JSON report and a finding's number (as the " +
		"report counts them, from 1) or fingerprint, prints that finding, its evidence and the diff hunk with 6 lines of " +
		"context, read from the archives the review cached. A review of a local file (--from-file, --to-file) or one " +
		"whose archives are no longer cached shows the hunk the report saved.",
	examples: []string{"explain remote-fetch-exec", "explain review.json 3", "explain review.json 9f2c41aa07d3b6e1"},
	flags: func(fs *flag.FlagSet, _ *simpleFlags) runFunc {
		asJSON := fs.Bool("json", false, "print the kind explain JSON document")
		return func(ctx context.Context, pos []string, stdout, _ io.Writer) error {
			r := core.GetExplainRenderer()
			if r == nil {
				return fmt.Errorf("explain renderer %w", core.ErrNotLinked)
			}
			o := core.WriteOptions{Program: cli.Name(), Version: version, Plain: !cli.IsTerminal(stdout), Color: colorOn(stdout)}
			switch len(pos) {
			case 1:
				if _, ok := core.Signal(pos[0]); !ok {
					e := unknownSignal(pos[0]).(*core.Error) //nolint:errorlint,forcetypeassert // unknownSignal always builds a bare *core.Error
					e.Command = "explain"
					return e
				}
				return r.RenderSignal(stdout, pos[0], o, *asJSON)
			case 2:
				return explainFinding(ctx, r, pos[0], pos[1], stdout, o, *asJSON)
			}
			return cli.Usagef("explain takes a signal ID, or a report and a finding: %s explain <report.json> <n|fingerprint>", cli.Name())
		}
	},
}

// explainFinding shows finding sel of the saved report at path.
func explainFinding(ctx context.Context, r core.ExplainRenderer, path, sel string, w io.Writer, o core.WriteOptions, asJSON bool) error {
	rep, err := readReport("explain", path)
	if err != nil {
		return err
	}
	u, f, err := pickFinding(rep, path, sel)
	if err != nil {
		return err
	}
	return r.RenderFinding(w, rep, sel, findingHunks(ctx, u, f), o, asJSON)
}

// readReport opens and parses a saved kind review report. A file that
// isn't there is E12 for command.
func readReport(command, path string) (*core.Report, error) {
	f, err := os.Open(path) //nolint:gosec // the report the user named
	if err != nil {
		what := fmt.Sprintf("can't read %s (%v)", shown(path), errors.Unwrap(err))
		if errors.Is(err, fs.ErrNotExist) {
			what = shown(path) + ": no such file"
		}
		return nil, &core.Error{Code: core.EBadConfig, Exit: cli.ExitUsage, Command: command, What: what, Err: err}
	}
	defer func() { _ = f.Close() }()
	return core.ReadReport(f)
}

// pickFinding finds a finding by its 1-based number across the report's
// updates, in report order, or by its fingerprint.
func pickFinding(rep *core.Report, path, sel string) (*core.Update, *core.Finding, error) {
	n, isNumber := strconv.Atoi(sel)
	count := 0
	for i := range rep.Updates {
		u := &rep.Updates[i]
		for j := range u.Findings {
			count++
			if f := &u.Findings[j]; isNumber == nil && count == n || f.Fingerprint == sel {
				return u, f, nil
			}
		}
	}
	what := fmt.Sprintf("%s has no finding with fingerprint %s", shown(path), sel)
	if isNumber == nil {
		what = fmt.Sprintf("%s has no finding %d (it has %d)", shown(path), n, count)
	}
	return nil, nil, &core.Error{Code: core.EBadFlag, Exit: cli.ExitUsage, Command: "explain", What: what}
}

// findingHunks returns the hunks of the finding's file: diffed again
// between the cached archives of both sides with explainContext lines
// of context, else the flagged hunks the report holds. A side read from
// a local file is never cached; a cached tree whose sha256 is not the
// one the report names is not the same release. Both fall back to the
// report. It returns nil when neither has the file; the renderer
// then says why.
func findingHunks(ctx context.Context, u *core.Update, f *core.Finding) []core.Hunk {
	if f.File == "" || f.InLockfile() {
		return nil
	}
	if hunks := cachedHunks(ctx, u, f); hunks != nil {
		return hunks
	}
	var hunks []core.Hunk
	for _, h := range u.Hunks {
		if h.Path == f.File {
			hunks = append(hunks, h)
		}
	}
	return hunks
}

// cachedHunks diffs the finding's file between the cached archives of
// both sides; nil when either side is local or no longer cached.
func cachedHunks(ctx context.Context, u *core.Update, f *core.Finding) []core.Hunk {
	differ := core.GetDiffer()
	if differ == nil || u.To.Local() || u.From.Local() {
		return nil
	}
	cache, err := run.CacheDir("")
	if err != nil {
		return nil
	}
	blobs, err := core.OpenBlobs(cache)
	if err != nil {
		return nil
	}
	cur, ok := cachedSide(cache, u, u.To, blobs)
	if !ok {
		return nil
	}
	var old *core.Tree
	if u.From.Version != "" {
		if old, ok = cachedSide(cache, u, u.From, blobs); !ok {
			return nil
		}
	}
	d, err := differ.Diff(ctx, old, cur)
	if err != nil {
		return nil
	}
	hunks, err := differ.Hunks(ctx, d, f.File, explainContext)
	if err != nil {
		return nil
	}
	return hunks
}

// cachedSide is the cached tree of one side, when its sha256 is the
// one the report names (or the report names none).
func cachedSide(cache string, u *core.Update, s core.Side, blobs core.BlobStore) (*core.Tree, bool) {
	t, ok := run.CachedTree(cache, core.Ref{Eco: u.Eco, Name: u.Name, Version: s.Version}, blobs)
	if !ok || s.SHA256 != "" && !strings.EqualFold(hex.EncodeToString(t.SHA256[:]), s.SHA256) {
		return nil, false
	}
	return t, true
}

// colorOn reports whether terminal output to w may use colour.
func colorOn(w io.Writer) bool {
	return cli.IsTerminal(w) && os.Getenv("NO_COLOR") == ""
}
