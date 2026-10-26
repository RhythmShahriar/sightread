// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package code

import (
	"context"
	"math"
	"strings"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"

	// The real analyzer once it lands; the explain text for Advice.
	_ "github.com/RhythmShahriar/sightread/analyze"
	_ "github.com/RhythmShahriar/sightread/detect"
)

func detectAll(t *testing.T, d core.Detector, s *core.Subject) []core.Finding {
	t.Helper()
	var out []core.Finding
	d.Detect(context.Background(), s, func(f core.Finding) { out = append(out, f) })
	return out
}

func ids(fs []core.Finding) string {
	var out []string
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return strings.Join(out, ",")
}

func TestHasDecode(t *testing.T) {
	for arg, want := range map[string]bool{
		"base64_decode($x)":               true,
		"GZINFLATE(str_rot13($d))":        true,
		"atob(x)":                         true,
		"Buffer.from(s, 'base64')":        true,
		"String.fromCharCode(101,118)":    true,
		"$x":                              false,
		"'base64_decode'":                 false, // the name as text, not a call
		"json_decode($body)":              false,
		"":                                false,
		"strrev_helper_name_without_call": false,
	} {
		if got := hasDecode(arg); got != want {
			t.Errorf("hasDecode(%q) = %v, want %v", arg, got, want)
		}
	}
}

func TestBundlerHelper(t *testing.T) {
	yes := []core.Feature{
		coretest.Feat(core.FDynCall, "__webpack_require__", "a.js", 1, AttrCallee, "__webpack_require__"),
		coretest.Feat(core.FEval, "function", "a.js", 1, AttrArg, `"return this"`),
		coretest.Feat(core.FEval, "function", "a.js", 1, AttrArg, `'return this;'`),
	}
	no := []core.Feature{
		coretest.Feat(core.FEval, "function", "a.js", 1, AttrArg, `"return this.x"`),
		coretest.Feat(core.FEval, "eval", "a.js", 1, AttrArg, `"return this"`),
		coretest.Feat(core.FDynCall, "f", "a.js", 1, AttrCallee, "webpack_require"),
	}
	for _, f := range yes {
		if !bundlerHelper(f) {
			t.Errorf("not a helper: %+v", f.Attrs)
		}
	}
	for _, f := range no {
		if bundlerHelper(f) {
			t.Errorf("helper: %+v", f.Attrs)
		}
	}
}

func TestEntropy(t *testing.T) {
	if h := entropy([]byte("aaaa")); h != 0 {
		t.Errorf("entropy(aaaa) = %v", h)
	}
	if h := entropy([]byte("abcd")); math.Abs(h-2) > 1e-9 {
		t.Errorf("entropy(abcd) = %v", h)
	}
	all := make([]byte, 256)
	for i := range all {
		all[i] = byte(i)
	}
	if h := entropy(all); math.Abs(h-8) > 1e-9 {
		t.Errorf("entropy(0..255) = %v", h)
	}
}

func subject(eco core.Ecosystem, old, new *core.FeatureSet) *core.Subject {
	return &core.Subject{Update: core.Ref{Eco: eco, Name: "x", Version: "2"},
		OldFeatures: old, NewFeatures: new, NewTree: coretest.Tree(nil)}
}

// A finding carries the catalogue's title, severity and confidence, the
// feature's place and evidence plus the explain advice.
func TestExecFindingFields(t *testing.T) {
	f := coretest.Feat(core.FFlow, "remote->eval", "a.php", 3)
	f.Ev.EndLine = 5
	got := detectAll(t, execDetector{}, subject(core.WPPlugin, nil, coretest.Features(f)))
	if len(got) != 1 {
		t.Fatalf("findings %v", ids(got))
	}
	fd := got[0]
	ex, _ := core.ExplainFor(SigRemoteFetchExec)
	if fd.ID != SigRemoteFetchExec || fd.Title != "Fetches remote code and runs it" || fd.Severity != cli.SeverityCritical ||
		fd.Confidence != core.Confirmed || fd.File != "a.php" || fd.Line != 3 || fd.EndLine != 5 ||
		fd.Evidence.String() != "flow remote->eval" || fd.Advice == "" || fd.Advice != ex.Advice {
		t.Errorf("finding %+v", fd)
	}
}

// One eval(base64_decode($x)) is a decode-exec, not also an
// eval-dynamic; a separate eval elsewhere still is.
func TestDecodeExecSuppressesEvalDynamicOnSameLine(t *testing.T) {
	fs := coretest.Features(
		coretest.Feat(core.FEval, "eval", "a.php", 3, AttrSource, SrcVariable, AttrArg, "base64_decode($x)"),
		coretest.Feat(core.FEval, "assert", "a.php", 3, AttrSource, SrcRequest),
		coretest.Feat(core.FEval, "assert", "b.php", 9, AttrSource, SrcRequest),
	)
	if got := ids(detectAll(t, execDetector{}, subject(core.WPPlugin, nil, fs))); got != "decode-exec,eval-dynamic" {
		t.Errorf("findings %s", got)
	}
}

// eval-dynamic in a minified file fires: minifying never hides a
// payload. Only blobs are exempt in minified files.
func TestMinifiedStillFires(t *testing.T) {
	fs := coretest.Features(
		coretest.Feat(core.FEval, "eval", "app.min.js", 1, AttrSource, SrcVariable, AttrArg, "atob(x)"),
		coretest.Feat(core.FBlob, "b64:1", "app.min.js", 1, AttrSize, "4000", AttrEntropy, "5.9", AttrDecoded, "data"),
	)
	fs.Minified = []string{"app.min.js"}
	if got := ids(detectAll(t, execDetector{}, subject(core.NPM, nil, fs))); got != "decode-exec" {
		t.Errorf("findings %s", got)
	}
}

// Every evasion of qa.md E2 fires decode-exec or eval-dynamic once the
// real analyzer runs on the source.
func TestE2Evasions(t *testing.T) {
	coretest.NeedAnalyzer(t)
	for name, src := range map[string]string{
		"plain":            `eval(base64_decode($x));`,
		"built decoder":    `$f = 'base' . '64_decode'; eval($f($x));`,
		"comment before (": `eval /* c */ (base64_decode($x));`,
		"hash comment":     "eval # c\n(base64_decode($x));",
		"built assert":     `$a = "as" . "sert"; $a(base64_decode($x));`,
		"call_user_func":   `call_user_func('ev' . 'al', base64_decode($x));`,
		"escaped name":     `$e = "\x65\x76\x61\x6c"; $e(gzinflate($x));`,
		"layers":           `eval(gzinflate(str_rot13(base64_decode($x))));`,
	} {
		t.Run(name, func(t *testing.T) {
			tr := coretest.Tree(map[string]string{"a.php": "<?php\nfunction f($x) {\n" + src + "\n}\n"})
			fs, err := core.GetAnalyzer().Analyze(context.Background(), tr, []string{"a.php"}, core.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			s := subject(core.WPPlugin, core.NewFeatureSet(), fs)
			s.NewTree = tr
			got := ids(detectAll(t, execDetector{}, s))
			if !strings.Contains(got, SigDecodeExec) && !strings.Contains(got, SigEvalDynamic) {
				t.Errorf("%s: findings %q", src, got)
			}
		})
	}
}

// A minified file that gains eval(atob(x)) still fires through the
// real analyzer.
func TestMinifiedEvalAtobAnalyzed(t *testing.T) {
	coretest.NeedAnalyzer(t)
	body := strings.Repeat("var a=1;", 300)
	old := coretest.Tree(map[string]string{"dist/app.min.js": body})
	tr := coretest.Tree(map[string]string{"dist/app.min.js": body + "eval(atob(x));"})
	a := core.GetAnalyzer()
	ofs, err := a.Analyze(context.Background(), old, []string{"dist/app.min.js"}, core.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	nfs, err := a.Analyze(context.Background(), tr, []string{"dist/app.min.js"}, core.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	s := subject(core.NPM, ofs, nfs)
	s.NewTree = tr
	if got := ids(detectAll(t, execDetector{}, s)); !strings.Contains(got, SigDecodeExec) {
		t.Errorf("findings %q", got)
	}
}

// The entropy outlier needs enough peers to compare with.
func TestEntropyNeedsPeers(t *testing.T) {
	noise := strings.Repeat("Zq8+xW3/kL0aR7yT", 64)
	files := map[string]string{"a.php": "<?php $k='" + noise + "';"}
	for _, p := range []string{"b.php", "c.php"} {
		files[p] = "<?php\n" + strings.Repeat("echo esc_html( $value );\n", 30)
	}
	tr := coretest.Tree(files)
	d, _ := coretest.FakeDiffer{}.Diff(context.Background(), coretest.Tree(nil), tr)
	s := &core.Subject{Update: core.Ref{Eco: core.WPPlugin}, NewTree: tr, Diff: d, NewFeatures: core.NewFeatureSet()}
	if got := entropyFindings(context.Background(), s); len(got) != 0 {
		t.Errorf("fired with 2 peers: %v", ids(got))
	}
}
