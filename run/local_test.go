// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
	"github.com/RhythmShahriar/sightread/run/runtest"
	"github.com/RhythmShahriar/sightread/source/changelog"
)

// readmeSource is the fake WordPress.org source that, like the real
// one, reads the changelog from a release's own readme.txt.
type readmeSource struct{ *runtest.Source }

func (s readmeSource) MetaFromTree(m *core.Meta, t *core.Tree) { m.Changelog = changelog.FromTree(t) }

// localPair reviews a plugin from two local zips whose readme.txt hold
// oldLog and newLog.
func localPair(t *testing.T, oldLog, newLog string) *core.Update {
	t.Helper()
	w := runtest.Install(t)
	src := readmeSource{w.Sources[core.WPPlugin]}
	t.Cleanup(core.SwapSource(core.WPPlugin, func(*core.Env) core.Source { return src }))
	dir := t.TempDir()
	logs := map[string]string{"old.zip": oldLog, "new.zip": newLog}
	for name := range logs {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(core.SwapLocalArchive(func(_ context.Context, path string, _ core.BlobStore, _ core.Limits) (*core.Tree, error) {
		tr := coretest.Tree(map[string]string{"p.php": "<?php\n", "readme.txt": "=== P ===\n\n== Changelog ==\n" + logs[filepath.Base(path)]})
		tr.HashKind = core.HashArchive
		return tr, nil
	}))
	req := request(t, "plugin")
	req.Eco, req.Names = core.WPPlugin, []string{"p"}
	req.FromFile, req.ToFile = filepath.Join(dir, "old.zip"), filepath.Join(dir, "new.zip")
	req.AllowUnverified = true
	rep := review(t, req)
	if len(rep.Updates) != 1 {
		t.Fatalf("updates %+v", rep.Updates)
	}
	return &rep.Updates[0]
}

// Positive: two local files, which have no version, review the entries
// the new readme adds over the old one's newest.
func TestLocalChangelog(t *testing.T) {
	u := localPair(t, "= 1.0.0 =\n* First.\n", "= 1.1.0 =\n* Adds a cleanup task.\n\n= 1.0.0 =\n* First.\n")
	var got []string
	for _, e := range u.Changelog {
		got = append(got, e.Version)
	}
	if !reflect.DeepEqual(got, []string{"1.1.0"}) {
		t.Errorf("changelog versions %q, want 1.1.0", got)
	}
}

// Negative: a new file whose readme adds no entry gives no changelog,
// so changelog-mismatch still sees the update as unexplained.
func TestLocalChangelogNoEntry(t *testing.T) {
	u := localPair(t, "= 1.0.0 =\n* First.\n", "= 1.0.0 =\n* First.\n")
	if len(u.Changelog) != 0 {
		t.Errorf("changelog %+v", u.Changelog)
	}
}
