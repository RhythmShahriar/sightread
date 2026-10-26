// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package testbed_test

// The same blank imports as cmd/rhythm-sightread/imports.go, so this
// test sees the stages the binary links. Package main can't be
// imported, so the list is copied and TestLinkListMatchesBinary keeps
// the two equal.
import (
	"context"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"

	_ "github.com/RhythmShahriar/sightread/analyze"
	_ "github.com/RhythmShahriar/sightread/archive"
	_ "github.com/RhythmShahriar/sightread/blob"
	_ "github.com/RhythmShahriar/sightread/data"
	_ "github.com/RhythmShahriar/sightread/detect"
	_ "github.com/RhythmShahriar/sightread/detect/code"
	_ "github.com/RhythmShahriar/sightread/detect/meta"
	_ "github.com/RhythmShahriar/sightread/diff"
	_ "github.com/RhythmShahriar/sightread/fetch"
	_ "github.com/RhythmShahriar/sightread/inventory"
	_ "github.com/RhythmShahriar/sightread/inventory/gitref"
	_ "github.com/RhythmShahriar/sightread/policy"
	_ "github.com/RhythmShahriar/sightread/report"
	_ "github.com/RhythmShahriar/sightread/score"
	_ "github.com/RhythmShahriar/sightread/source/github"
	_ "github.com/RhythmShahriar/sightread/source/npm"
	_ "github.com/RhythmShahriar/sightread/source/osv"
	_ "github.com/RhythmShahriar/sightread/source/packagist"
	_ "github.com/RhythmShahriar/sightread/source/wporg"
	_ "github.com/RhythmShahriar/sightread/version"
)

// blankImports returns the paths a Go file imports as _, sorted.
func blankImports(t *testing.T, file string) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), file, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, imp := range f.Imports {
		if imp.Name == nil || imp.Name.Name != "_" {
			continue
		}
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	slices.Sort(out)
	return out
}

// TestLinkListMatchesBinary fails when this file's blank imports and
// the binary's drift apart, so a package added to imports.go is checked
// here too. It runs always: it needs no stage.
func TestLinkListMatchesBinary(t *testing.T) {
	bin := blankImports(t, filepath.Join("..", "cmd", "rhythm-sightread", "imports.go"))
	here := blankImports(t, "linkcheck_test.go")
	if len(bin) == 0 {
		t.Fatal("cmd/rhythm-sightread/imports.go has no blank imports")
	}
	for _, p := range bin {
		if !slices.Contains(here, p) {
			t.Errorf("imports.go links %s; add it to testbed/linkcheck_test.go", p)
		}
	}
	for _, p := range here {
		if !slices.Contains(bin, p) {
			t.Errorf("testbed/linkcheck_test.go imports %s, which imports.go doesn't link", p)
		}
	}
}

// linkProblems lists every stage the pipeline looks up that isn't
// registered, every detector signal that isn't a detect ID of the
// catalogue, every detect ID no detector lists and every signal without
// explain text. Empty means the binary is whole.
func linkProblems() []string {
	var out []string
	for _, c := range []struct {
		name string
		ok   bool
	}{
		{"inventory", core.GetInventory() != nil},
		{"git show", core.GetGitShow() != nil},
		{"differ", core.GetDiffer() != nil},
		{"analyzer", core.GetAnalyzer() != nil},
		{"data packs", core.GetDataPacks() != nil},
		{"scorer", core.GetScorer() != nil},
		{"policy", core.GetPolicy() != nil},
		{"explain renderer", core.GetExplainRenderer() != nil},
		{"signer", core.GetSigner() != nil},
		{"detectors", len(core.Detectors()) > 0},
	} {
		if !c.ok {
			out = append(out, c.name+" not linked")
		}
	}
	for _, eco := range core.Ecosystems() {
		if core.Versions(eco) == nil {
			out = append(out, "version scheme of "+string(eco)+" not linked")
		}
	}
	for _, f := range allFormats {
		if core.WriterFor(f) == nil {
			out = append(out, f+" writer not linked")
		}
	}
	// Sources, OSV, the tag check, the getter, the blob store and the
	// readers are constructors that need a run's Env or folder, so they
	// are checked by name through core.Linked instead of built.
	linked := core.Linked()
	want := []string{"advisories", "tag-checker", "getter", "blobs", "report-reader", "local-archive"}
	for _, eco := range core.Ecosystems() {
		want = append(want, "source:"+string(eco))
	}
	for _, w := range want {
		if !slices.Contains(linked, w) {
			out = append(out, w+" not linked")
		}
	}

	catalog := map[string]core.SignalInfo{}
	for _, s := range core.Catalog {
		catalog[s.ID] = s
	}
	covered := map[string]bool{}
	for _, d := range core.Detectors() {
		info := d.Info()
		if len(info.Signals) == 0 {
			out = append(out, "detector "+info.Name+" lists no signals")
		}
		for _, id := range info.Signals {
			s, ok := catalog[id]
			switch {
			case !ok:
				out = append(out, "detector "+info.Name+" lists "+id+", which is not in the catalogue")
			case s.Emitter != core.EmitDetect:
				out = append(out, "detector "+info.Name+" lists "+id+", which "+s.Emitter+" emits")
			}
			covered[id] = true
		}
	}
	for _, s := range core.Catalog {
		if s.Emitter == core.EmitDetect && !covered[s.ID] {
			out = append(out, "no detector emits "+s.ID)
		}
		if _, ok := core.ExplainFor(s.ID); !ok {
			out = append(out, s.ID+" has no explain text")
		}
	}
	return out
}

// allFormats are the writers PRD 9 names.
var allFormats = []string{core.FormatTerminal, core.FormatJSON, core.FormatJSONL, core.FormatSARIF, core.FormatMarkdown, core.FormatHTML}

// TestAllStagesLinked is the integration check: every stage the
// pipeline looks up is registered, every detector emits only catalogue
// IDs, the detectors together cover every signal detect emits and every
// signal has explain text. Before integration the stages are stubs, so
// it skips unless SIGHTREAD_REQUIRE_LINKED=1 (make test-integrated, the
// nightly and the release checklist).
func TestAllStagesLinked(t *testing.T) {
	if os.Getenv(coretest.RequireLinkedEnv) != "1" {
		t.Skipf("the integration check; set %s=1 to run it", coretest.RequireLinkedEnv)
	}
	for _, p := range linkProblems() {
		t.Error(p)
	}
}

// stubWriter is a writer that only names its format.
type stubWriter struct{ format string }

func (w stubWriter) Format() string { return w.format }

func (stubWriter) Write(io.Writer, *core.Report, core.WriteOptions) error { return nil }

// linkStubs registers a placeholder for every stage, one detector that
// lists every detect ID and explain text for every signal, all restored
// when t ends. The placeholders are never called: linkProblems only
// asks whether each one is there.
func linkStubs(t *testing.T) {
	t.Helper()
	var ids []core.Finding
	restore := []func(){
		core.SwapInventory(struct{ core.Inventory }{}),
		core.SwapGitShow(func(context.Context, string, string, string) ([]byte, error) { return nil, nil }),
		core.SwapDiffer(struct{ core.Differ }{}),
		core.SwapAnalyzer(struct{ core.Analyzer }{}),
		core.SwapDataPacks(struct{ core.DataPacks }{}),
		core.SwapScorer(struct{ core.Scorer }{}),
		core.SwapPolicy(struct{ core.Policy }{}),
		core.SwapExplainRenderer(struct{ core.ExplainRenderer }{}),
		core.SwapSigner(struct{ core.Signer }{}),
		core.SwapAdvisories(func(*core.Env) core.Advisories { return nil }),
		core.SwapTagChecker(func(*core.Env) core.TagChecker { return nil }),
		core.SwapGetter(func(core.GetterConfig) (core.Getter, error) { return nil, nil }),
		core.SwapBlobStore(func(string) (core.BlobStore, error) { return nil, nil }),
		core.SwapReportReader(func(io.Reader) (*core.Report, error) { return nil, nil }),
		core.SwapLocalArchive(func(context.Context, string, core.BlobStore, core.Limits) (*core.Tree, error) { return nil, nil }),
	}
	for _, eco := range core.Ecosystems() {
		restore = append(restore,
			core.SwapSource(eco, func(*core.Env) core.Source { return nil }),
			core.SwapVersionScheme(eco, struct{ core.VersionScheme }{}))
	}
	for _, f := range allFormats {
		restore = append(restore, core.SwapWriter(stubWriter{f}))
	}
	for _, s := range core.Catalog {
		restore = append(restore, core.SwapExplain(s.ID, core.Explain{Why: "stub"}))
		if s.Emitter == core.EmitDetect {
			ids = append(ids, core.Finding{ID: s.ID})
		}
	}
	restore = append(restore, core.SwapDetectors(&coretest.FakeDetector{Name: "every-signal", Findings: ids}))
	t.Cleanup(func() {
		for _, r := range slices.Backward(restore) {
			r()
		}
	})
}

// TestLinkProblems runs the check on stand-ins, so it proves itself
// before integration: whole with every stage there; each kind of gap
// named.
func TestLinkProblems(t *testing.T) {
	t.Run("whole", func(t *testing.T) {
		linkStubs(t)
		if p := linkProblems(); len(p) != 0 {
			t.Errorf("problems with every stage registered: %q", p)
		}
	})
	for _, c := range []struct {
		name    string
		breakIt func() func()
		want    []string
	}{
		{"a stage missing", func() func() { return core.SwapDiffer(nil) }, []string{"differ not linked"}},
		{"a version scheme missing", func() func() { return core.SwapVersionScheme(core.NPM, nil) }, []string{"version scheme of npm not linked"}},
		{"a signal outside the catalogue and one uncovered", func() func() {
			return core.SwapDetectors(&coretest.FakeDetector{Name: "odd", Findings: []core.Finding{{ID: "no-such-signal"}, {ID: "approved-version-changed"}}})
		}, []string{
			"detector odd lists no-such-signal, which is not in the catalogue",
			"detector odd lists approved-version-changed, which policy emits",
			"no detector emits remote-fetch-exec",
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			linkStubs(t)
			t.Cleanup(c.breakIt())
			got := linkProblems()
			for _, w := range c.want {
				if !slices.Contains(got, w) {
					t.Errorf("missing %q in %q", w, got)
				}
			}
		})
	}
}
