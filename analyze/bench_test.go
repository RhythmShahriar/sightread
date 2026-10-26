// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// genTree builds a WordPress plugin tree of at least n bytes from the
// templates in testdata/gen: the plugin's own PHP (heredocs, ?> HTML
// mixes, REST routes, settings), its admin script and vendored code
// shaped like an HTTP client and a framework (legit unserialize of
// cache and queue data, no eval). Each copy is numbered so no two files
// are equal. The templates are written for these tests, not copied from
// any package.
func genTree(tb testing.TB, n int) *core.Tree {
	tb.Helper()
	type tmpl struct{ rel, text string }
	var tmpls []tmpl
	root := filepath.Join("testdata", "gen")
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".tmpl") {
			return err
		}
		b, err := os.ReadFile(p) // #nosec G304 -- test templates
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		tmpls = append(tmpls, tmpl{filepath.ToSlash(strings.TrimSuffix(rel, ".tmpl")), string(b)})
		return nil
	})
	if err != nil || len(tmpls) == 0 {
		tb.Fatalf("no templates: %v", err)
	}
	files := map[string]string{}
	size := 0
	for i := 0; size < n; i++ {
		t := tmpls[i%len(tmpls)]
		dir, base := filepath.Split(t.rel)
		ext := filepath.Ext(base)
		p := "sample-forms/" + dir + strings.TrimSuffix(base, ext) + "-" + strconv.Itoa(i) + ext
		if strings.HasPrefix(t.rel, "vendor/") {
			p = "sample-forms/vendor/lib" + strconv.Itoa(i%7) + "/src/" + strings.TrimSuffix(base, ext) + strconv.Itoa(i) + ext
		}
		text := strings.ReplaceAll(t.text, "__N__", strconv.Itoa(i))
		files[p] = text
		size += len(text)
	}
	return coretest.Tree(files)
}

// BenchmarkAnalyzeWordPressPlugin analyses a generated 5 MB plugin tree,
// one side of a review. The target is under 2 s per side on the CI
// Linux runner (TestAnalyzePluginTime holds it).
func BenchmarkAnalyzeWordPressPlugin(b *testing.B) {
	tree := genTree(b, 5<<20)
	b.SetBytes(tree.Bytes)
	b.ResetTimer()
	for b.Loop() {
		_ = analyzeAll(b, tree, core.DefaultLimits())
	}
}

// TestAnalyzePluginTime guards the 2 s per side target on the 5 MB
// tree. Shared runners vary, so by default it fails only past twice the
// target; SIGHTREAD_PERF=1 (make bench, the release checklist) holds
// it to the target. It takes the best of three runs and skips under
// -short and -race.
func TestAnalyzePluginTime(t *testing.T) {
	if testing.Short() || raceSlowdown > 1 {
		t.Skip("speed is measured without -short and -race")
	}
	tree := genTree(t, 5<<20)
	best := time.Duration(1 << 62)
	for range 3 {
		start := time.Now()
		set := analyzeAll(t, tree, core.DefaultLimits())
		best = min(best, time.Since(start))
		if len(set.Unanalysed) > 0 {
			t.Fatalf("unanalysed: %q", set.Unanalysed)
		}
	}
	t.Logf("%d files, %.1f MB in %v", len(tree.Files), float64(tree.Bytes)/1e6, best)
	target := 2 * time.Second
	if os.Getenv("SIGHTREAD_PERF") != "1" {
		target *= 2
	}
	if best > target {
		t.Errorf("analysed in %v, want under %v", best, target)
	}
}

// TestBenignCorpus analyses the generated plugin and vendor shapes and
// asserts that nothing in them reads as remote or request data reaching
// eval or unserialize, that every file was analysed and that no hidden
// code, Unicode trick or secret is reported.
func TestBenignCorpus(t *testing.T) {
	n := 1 << 20
	if raceSlowdown > 1 || testing.Short() {
		n = 256 << 10
	}
	set := analyzeAll(t, genTree(t, n), core.DefaultLimits())
	if len(set.Unanalysed) > 0 {
		t.Errorf("unanalysed: %q", set.Unanalysed)
	}
	if len(set.ByKey) == 0 {
		t.Fatal("the corpus gave no features at all")
	}
	for k, fs := range set.ByKey {
		f := fs[0]
		switch f.Kind {
		case core.FFlow:
			src, sink, _ := strings.Cut(f.Key, "->")
			if (src == "remote" || src == "request") && (sink == sinkEval || sink == sinkUnserialize) {
				t.Errorf("benign code gave %s at %s:%d", k, f.Ev.Path, f.Ev.Line)
			}
		case core.FCodeInAsset, core.FUnicode, core.FSecret, core.FBlob:
			t.Errorf("benign code gave %s at %s:%d", k, f.Ev.Path, f.Ev.Line)
		}
	}
	// The corpus holds the shapes the assertion is about.
	for _, want := range []string{"call:unserialize", "call:maybe_unserialize", "send:wp_remote_get", "send:curl_exec", "route:sample-forms/v1/entries"} {
		if len(set.ByKey[want]) == 0 {
			t.Errorf("corpus lacks %s", want)
		}
	}
	if set.Has(core.FRoute, "sample-forms/v1/entries") {
		if p := set.ByKey["route:sample-forms/v1/entries"][0].Attrs["permission"]; p == "open" {
			t.Errorf("a route with a capability check reads as open")
		}
	}
}
