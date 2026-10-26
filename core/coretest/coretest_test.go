// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package coretest

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/secrets"
	"github.com/RhythmShahriar/sightread/core"
)

// Every fake key is one kit secrets finds on its own, with no "token ="
// around it, so masking tests prove the rule and not the context.
func TestFakeKeysAreSecrets(t *testing.T) {
	seen := map[string]bool{}
	for _, kind := range FakeKeyKinds() {
		k := FakeKey(kind)
		if seen[k] {
			t.Errorf("%s: same key as another kind", kind)
		}
		seen[k] = true
		if out := secrets.Redact("x " + k + " y"); strings.Contains(out, k) {
			t.Errorf("%s: Redact left %q", kind, out)
		}
		if len(secrets.FindSecrets([]byte(k))) == 0 {
			t.Errorf("%s: FindSecrets misses it", kind)
		}
	}
}

func TestFakeKeyUnknown(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("FakeKey(nope) didn't panic")
		}
	}()
	FakeKey("nope")
}

func TestTreeRefusesBadPaths(t *testing.T) {
	for _, p := range []string{"../x", "/etc/passwd", `a\b`, "C:/x", "a//b", "a/./b", "a\x00b", ""} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("Tree accepted %q", p)
				}
			}()
			Tree(map[string]string{p: "x"})
		}()
	}
}

func TestTree(t *testing.T) {
	tr := Tree(map[string]string{"b.php": "<?php", "a.min.js": "x", "img/logo.png": "\x89PNG", "README.txt": "hi"})
	var paths []string
	for _, f := range tr.Files {
		paths = append(paths, f.Path+"="+string(f.Kind))
	}
	want := []string{"README.txt=text", "a.min.js=minified", "b.php=php", "img/logo.png=asset"}
	if !slices.Equal(paths, want) {
		t.Errorf("files %v, want %v", paths, want)
	}
	if Read(tr, "b.php") != "<?php" || tr.Bytes != 5+1+4+2 || tr.SHA256 != core.ManifestHash(tr.Files) {
		t.Errorf("tree contents, size or hash wrong: %+v", tr)
	}
}

func TestMemBlobs(t *testing.T) {
	b := MemBlobs()
	ctx := context.Background()
	sum, n, err := b.Put(ctx, strings.NewReader("hello"), 5)
	if err != nil || n != 5 || !b.Has(sum) {
		t.Fatalf("Put = %x, %d, %v", sum[:4], n, err)
	}
	if _, _, err := b.Put(ctx, strings.NewReader("toolong"), 3); !errors.Is(err, core.ErrTooLarge) {
		t.Errorf("Put over the limit: %v, want ErrTooLarge", err)
	}
	if _, ok := b.Path(sum); ok {
		t.Error("a memory store has a path")
	}
	if _, err := b.Open([32]byte{1}); err == nil {
		t.Error("Open of a missing blob succeeded")
	}
}

func TestSampleReport(t *testing.T) {
	r := SampleReport()
	ids := map[string]bool{}
	verdicts := map[core.Verdict]bool{}
	fleet := false
	for _, u := range r.Updates {
		verdicts[u.Verdict] = true
		fleet = fleet || len(u.Sites) > 1
		for _, f := range u.Findings {
			ids[f.ID] = true
			if f.Fingerprint == "" {
				t.Errorf("%s %s: no fingerprint", u.Name, f.ID)
			}
			for _, k := range FakeKeyKinds() {
				if strings.Contains(f.Evidence.String(), FakeKey(k)) {
					t.Errorf("%s: raw %s key in evidence", f.ID, k)
				}
			}
		}
	}
	for _, id := range core.SignalIDs() {
		if !ids[id] {
			t.Errorf("signal %s is missing", id)
		}
	}
	for _, v := range []core.Verdict{core.Hold, core.Review, core.Routine, core.Allowed, core.Unverified} {
		if !verdicts[v] {
			t.Errorf("no %s update", v)
		}
	}
	if !fleet || len(r.NotChecked) == 0 || len(r.Errors) == 0 || r.Complete {
		t.Error("want a fleet update, a Not checked entry, an error and complete false")
	}
	s := r.Summary
	if s.Updates != 6 || s.AllowedFindings != 1 || s.Baselined != 1 || s.Ignored != 1 || s.Demoted != 1 || s.FromCache != 1 {
		t.Errorf("summary %+v", s)
	}
	if SampleReport() == r || SampleReport().Updates[0].Findings[0].ID != r.Updates[0].Findings[0].ID {
		t.Error("SampleReport isn't a fresh, stable copy")
	}
}

func TestFakeScorer(t *testing.T) {
	sc := FakeScorer{}
	u := &core.Update{Eco: core.NPM, Name: "x", From: core.Side{Verified: core.BySignature},
		To:       core.Side{Version: "2.0.0", SHA256: "aa", Verified: core.BySignature},
		Findings: []core.Finding{{ID: "eval-dynamic", File: "a.js"}}}
	sc.Score(context.Background(), u, nil, nil, nil)
	f := u.Findings[0]
	if u.Verdict != core.Review || f.Severity != cli.SeverityHigh || f.Title == "" || f.Fingerprint == "" {
		t.Errorf("verdict %s, finding %+v", u.Verdict, f)
	}
	allow := AllowList{{Package: "npm:x", Version: "2.0.0", SHA256: "aa", Reason: "ok", By: "me"}}
	u.Findings[0].Allowed = nil
	sc.Score(context.Background(), u, nil, allow, nil)
	if u.Verdict != core.Allowed {
		t.Errorf("allowed update got %s", u.Verdict)
	}
	r := &core.Report{Updates: []core.Update{*u}}
	sc.Summarise(r)
	if code, _ := sc.Gate(r, core.GateOptions{FailOn: cli.SeverityHigh}); code != cli.ExitOK {
		t.Errorf("allowed finding gates with %d", code)
	}
	r.Updates[0].Findings[0].Allowed = nil
	if code, _ := sc.Gate(r, core.GateOptions{FailOn: cli.SeverityHigh}); code != cli.ExitFindings {
		t.Errorf("high finding under --fail-on high gives %d", code)
	}
	if code, _ := sc.Gate(r, core.GateOptions{}); code != cli.ExitOK {
		t.Errorf("no --fail-on gives %d", code)
	}
	partial := &core.Report{NotChecked: []core.NotChecked{{Name: "y"}}}
	sc.Summarise(partial)
	if code, _ := sc.Gate(partial, core.GateOptions{FailOn: cli.SeverityHigh}); code != cli.ExitUnavailable {
		t.Errorf("partial run gives %d, want 3", code)
	}
	if code, _ := sc.Gate(partial, core.GateOptions{FailOn: cli.SeverityHigh, AllowPartial: true}); code != cli.ExitOK {
		t.Errorf("--allow-partial gives %d", code)
	}
}

func TestAllowListConflict(t *testing.T) {
	l := AllowList{{Package: "npm:x", Version: "1.0.0", SHA256: "aa"}}
	if m, ok, c := l.Match(core.NPM, "x", "1.0.0", "bb"); m != nil || ok || c == nil {
		t.Errorf("other hash: match %v counted %v conflict %v", m, ok, c)
	}
	if m, ok, c := l.Match(core.NPM, "x", "1.0.0", "aa"); m == nil || !ok || c != nil {
		t.Errorf("same hash: match %v counted %v conflict %v", m, ok, c)
	}
}

func TestFakeDiffer(t *testing.T) {
	old := Tree(map[string]string{"a.php": "1", "b.php": "2", "gone.php": "3"})
	cur := Tree(map[string]string{"a.php": "1", "b.php": "changed", "new.php": "4"})
	d, err := FakeDiffer{}.Diff(context.Background(), old, cur)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range d.Changes {
		p := ""
		if c.New != nil {
			p = c.New.Path
		} else {
			p = c.Old.Path
		}
		got = append(got, c.Kind.String()+":"+p)
	}
	if want := []string{"modified:b.php", "removed:gone.php", "added:new.php"}; !slices.Equal(got, want) {
		t.Errorf("changes %v, want %v", got, want)
	}
	dr := FakeDiffer{}.Drift(context.Background(), cur, old)
	if !slices.Equal(dr.Matched, []string{"a.php"}) || !slices.Equal(dr.Differ, []string{"b.php"}) ||
		!slices.Equal(dr.Missing, []string{"gone.php"}) || !slices.Equal(dr.Extra, []string{"new.php"}) || dr.Official {
		t.Errorf("drift %+v (1 of 3 match: not official)", dr)
	}
}

func TestFakeAnalyzer(t *testing.T) {
	old := Tree(map[string]string{"a.php": "<?php"})
	cur := Tree(map[string]string{"a.php": "<?php eval($x);", "big.php": "x"})
	a := &FakeAnalyzer{
		ByPath:     map[string][]core.Feature{"a.php": {Feat(core.FDomain, "example.com", "", 1)}},
		ByTree:     map[*core.Tree]map[string][]core.Feature{cur: {"a.php": {Feat(core.FEval, "eval", "", 1, "source", "request")}}},
		Unanalysed: map[string]string{"big.php": "over 4 MiB"},
	}
	ctx := context.Background()
	o, _ := a.Analyze(ctx, old, []string{"a.php"}, core.DefaultLimits())
	n, _ := a.Analyze(ctx, cur, []string{"a.php", "big.php", "missing.php"}, core.DefaultLimits())
	if !o.Has(core.FDomain, "example.com") || !n.Has(core.FEval, "eval") || n.Has(core.FDomain, "example.com") {
		t.Error("ByTree doesn't win over ByPath")
	}
	if len(n.Unanalysed) != 1 || n.ByKey["eval:eval"][0].Ev.Path != "a.php" || n.ByKey["eval:eval"][0].Attrs["source"] != "request" {
		t.Errorf("feature set %+v", n)
	}
}

func TestInstallRestores(t *testing.T) {
	if core.GetScorer() != nil {
		t.Skip("a scorer is linked into this test binary")
	}
	t.Run("installed", func(t *testing.T) {
		FakeScorer{}.Install(t)
		NeedScorer(t)
	})
	if core.GetScorer() != nil {
		t.Error("Install didn't restore the empty slot")
	}
}

// recorder is a testing.TB that records Errorf instead of failing.
type recorder struct {
	testing.TB
	errs []string
}

func (r *recorder) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}

func TestLoopbackOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	rec := &recorder{TB: t}
	c := &http.Client{Transport: LoopbackOnly(rec)}
	resp, err := c.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(rec.errs) != 0 {
		t.Errorf("loopback request was refused: %v", rec.errs)
	}
	// .invalid never resolves; the transport refuses before dialling.
	resp, err = c.Get("https://registry.npmjs.invalid/left-pad")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("request to another host went through")
	}
	if len(rec.errs) != 1 {
		t.Errorf("want the test failed once, got %v", rec.errs)
	}
}

func TestNormalise(t *testing.T) {
	tmp := filepath.Join(os.TempDir(), "TestX123", "001", "review.json")
	in := `{"tool": "rhythm-sightread", "version": "1.0.3", "started": "2026-10-26T09:12:03Z", "duration_ms": 8120,` +
		` "path": "` + strings.ReplaceAll(tmp, `\`, `\\`) + `", "to": {"version": "2.6.8"}}` + "\n♪ rhythm sightread 1.0.0 · 1.4s\n"
	got := string(Normalise([]byte(in)))
	want := `{"tool": "rhythm-sightread", "version": "<version>", "started": "<time>", "duration_ms": 0,` +
		` "path": "<tmp>/TestX123/001/review.json", "to": {"version": "2.6.8"}}` + "\n♪ rhythm sightread <version> · <dur>\n"
	if got != want {
		t.Errorf("Normalise =\n%s\nwant\n%s", got, want)
	}
}

func TestGolden(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	*update = true
	Golden(t, "x/out.txt", []byte("at 2026-10-26T09:12:03Z\n"))
	*update = false
	b, err := os.ReadFile(filepath.Join(dir, "testdata", "golden", "x", "out.txt"))
	if err != nil || string(b) != "at <time>\n" {
		t.Fatalf("golden file %q, %v", b, err)
	}
	Golden(t, "x/out.txt", []byte("at 2027-01-01T00:00:00Z\n"))
	rec := &recorder{TB: t}
	Golden(rec, "x/out.txt", []byte("other\n"))
	if len(rec.errs) != 1 || !strings.Contains(rec.errs[0], "line 1") {
		t.Errorf("a different output: %v", rec.errs)
	}
}

func TestNeedSkips(t *testing.T) {
	if os.Getenv(RequireLinkedEnv) == "1" {
		t.Skip("integrated run: Need fails instead")
	}
	ok := t.Run("skips", func(t *testing.T) {
		need(t, false, "nothing")
		t.Error("need didn't skip")
	})
	if !ok {
		t.Error("the subtest failed instead of skipping")
	}
}
