// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run_test

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
	"github.com/RhythmShahriar/sightread/run"
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

// versionInventory is the fake inventory that reads a local copy's
// declared version from its VERSION file, as the real one reads a
// plugin header.
type versionInventory struct{ *coretest.FakeInventory }

func (versionInventory) TreeVersion(_ core.Ecosystem, _ string, t *core.Tree) string {
	for _, f := range t.Files {
		if f.Path == "VERSION" {
			rc, err := t.Blobs.Open(f.SHA256)
			if err != nil {
				return ""
			}
			defer func() { _ = rc.Close() }()
			b, _ := io.ReadAll(rc)
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

// TestLocalDeclaredVersion: a --from-file or --to-file side with no
// --from or --to is named by the version its files declare; one that
// declares none stays "local". An explicit --to still wins.
func TestLocalDeclaredVersion(t *testing.T) {
	cases := []struct {
		name, oldV, newV, to, wantFrom, wantTo string
	}{
		{"both declare", "2.8.0", "2.8.1", "", "2.8.0", "2.8.1"},
		{"new declares none", "2.8.0", "", "", "2.8.0", core.LocalVersion},
		{"--to wins", "2.8.0", "2.8.1", "2.9.0", "2.8.0", "2.9.0"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := runtest.Install(t)
			t.Cleanup(core.SwapInventory(versionInventory{w.Inventory}))
			dir := t.TempDir()
			versions := map[string]string{"old.zip": c.oldV, "new.zip": c.newV}
			for name := range versions {
				if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			t.Cleanup(core.SwapLocalArchive(func(_ context.Context, path string, _ core.BlobStore, _ core.Limits) (*core.Tree, error) {
				files := map[string]string{"p.php": "<?php\n" + filepath.Base(path)}
				if v := versions[filepath.Base(path)]; v != "" {
					files["VERSION"] = v
				}
				return coretest.Tree(files), nil
			}))
			req := request(t, "plugin")
			req.Eco, req.Names, req.To = core.WPPlugin, []string{"p"}, c.to
			req.FromFile, req.ToFile = filepath.Join(dir, "old.zip"), filepath.Join(dir, "new.zip")
			req.AllowUnverified = true
			rep := review(t, req)
			if len(rep.Updates) != 1 {
				t.Fatalf("updates %+v", rep.Updates)
			}
			if u := rep.Updates[0]; u.From.Version != c.wantFrom || u.To.Version != c.wantTo {
				t.Errorf("%s → %s, want %s → %s", u.From.Version, u.To.Version, c.wantFrom, c.wantTo)
			}
		})
	}
}

// TestLocalUnverifiedHint: without --allow-unverified a local file is
// not diffed; its E5 hint says why running again won't help.
func TestLocalUnverifiedHint(t *testing.T) {
	w := runtest.Install(t)
	src := readmeSource{w.Sources[core.WPPlugin]}
	t.Cleanup(core.SwapSource(core.WPPlugin, func(*core.Env) core.Source { return src }))
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "new.zip"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(core.SwapLocalArchive(func(context.Context, string, core.BlobStore, core.Limits) (*core.Tree, error) {
		tr := coretest.Tree(map[string]string{"p.php": "<?php\n"})
		tr.HashKind = core.HashArchive
		return tr, nil
	}))
	w.Publish(core.WPPlugin, "p", "1.0.0")
	w.Install(core.WPPlugin, "p", "1.0.0")
	req := request(t, "plugin")
	req.Eco, req.Names = core.WPPlugin, []string{"p"}
	req.ToFile = filepath.Join(dir, "new.zip")
	var hints []string
	req.OnProblem = func(e *core.Error) {
		if e.Code == core.EUnverifiable {
			hints = append(hints, e.Hint...)
		}
	}
	review(t, req)
	if len(hints) != 1 || hints[0] != run.LocalUnverifiedHint {
		t.Errorf("E5 hints %q, want the local file one", hints)
	}
	if strings.Contains(run.LocalUnverifiedHint, "later") {
		t.Error("the local hint still says to run again later")
	}
}

// unknownSource is a WordPress.org source that knows no plugin, with the
// real source's E2 text and hint.
type unknownSource struct{ *runtest.Source }

func (unknownSource) Meta(_ context.Context, ref core.Ref) (*core.Meta, error) {
	return nil, &core.Error{Code: core.EUnknownPackage, Exit: 2, Command: "plugin",
		What: "wordpress.org has no plugin \"" + ref.Name + "\"",
		Hint: []string{"A premium plugin has no official source: use --to-file <zip>"}}
}

func (s unknownSource) Versions(ctx context.Context, name string) ([]string, error) {
	_, err := s.Meta(ctx, core.Ref{Name: name})
	return nil, err
}

// TestLocalToFileUnknownFrom: with --to-file given, a --from that
// WordPress.org doesn't know points at the installed side, not at the
// --to-file the run already has.
func TestLocalToFileUnknownFrom(t *testing.T) {
	w := runtest.Install(t)
	src := unknownSource{w.Sources[core.WPPlugin]}
	t.Cleanup(core.SwapSource(core.WPPlugin, func(*core.Env) core.Source { return src }))
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "new.zip"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(core.SwapLocalArchive(func(context.Context, string, core.BlobStore, core.Limits) (*core.Tree, error) {
		return coretest.Tree(map[string]string{"p.php": "<?php\n"}), nil
	}))
	req := request(t, "plugin")
	req.Eco, req.Names, req.From = core.WPPlugin, []string{"myplug"}, "1.0.0"
	req.ToFile = filepath.Join(dir, "new.zip")
	var problems []*core.Error
	req.OnProblem = func(e *core.Error) { problems = append(problems, e) }
	rep := review(t, req)
	if len(problems) != 1 || len(problems[0].Hint) != 1 || problems[0].Hint[0] != run.InstalledSideHint {
		t.Errorf("E2 problems %+v", problems)
	}
	if len(rep.NotChecked) != 1 || rep.NotChecked[0].Hint != run.InstalledSideHint {
		t.Errorf("not checked %+v", rep.NotChecked)
	}
	// The source's own error keeps its --to-file hint for other runs.
	if _, err := src.Meta(context.Background(), core.Ref{Name: "myplug"}); !strings.Contains(err.Error(), "use --to-file <zip>") {
		t.Errorf("source error changed: %v", err)
	}
	// Without --to-file the named package fails with the --to-file hint.
	req.ToFile = ""
	if _, err := run.Review(context.Background(), req); err == nil || !strings.Contains(err.Error(), "use --to-file <zip>") {
		t.Errorf("without --to-file: %v", err)
	}
}
