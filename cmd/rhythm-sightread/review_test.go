// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
	"github.com/RhythmShahriar/sightread/run/runtest"
)

// world installs the fakes and a cache and config folder of the test's
// own.
func world(t *testing.T) *runtest.World {
	t.Helper()
	t.Setenv("RHYTHM_CACHE_DIR", t.TempDir())
	t.Setenv("RHYTHM_CONFIG_DIR", t.TempDir())
	t.Setenv("CI", "")
	t.Setenv("GITHUB_BASE_REF", "")
	return runtest.Install(t)
}

// routineAndHold publishes one routine update and one with a critical
// finding.
func routineAndHold(w *runtest.World) {
	w.Publish(core.WPPlugin, "akismet", "5.3.3", "5.3.5")
	w.Publish(core.WPPlugin, "countdown", "2.6.7", "2.6.8")
	w.Install(core.WPPlugin, "akismet", "5.3.3")
	w.Install(core.WPPlugin, "countdown", "2.6.7")
	w.Detector.Set("countdown", "remote-fetch-exec")
}

// TestReviewExitCodes is PRD section 10 through the commands.
func TestReviewExitCodes(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(w *runtest.World)
		args   []string
		code   int
		stderr string
	}{
		{"routine, no gate", func(w *runtest.World) {
			w.Publish(core.WPPlugin, "akismet", "5.3.3", "5.3.5")
			w.Install(core.WPPlugin, "akismet", "5.3.3")
		},
			[]string{"all"}, cli.ExitOK, ""},
		{"hold without --fail-on", routineAndHold, []string{"all"}, cli.ExitOK, ""},
		{"hold with --fail-on high", routineAndHold, []string{"all", "--fail-on", "high"}, cli.ExitFindings, ""},
		{"hold with config fail_on", func(w *runtest.World) { routineAndHold(w); w.Policy.Config = &core.Config{FailOn: "high"} },
			[]string{"all"}, cli.ExitFindings, ""},
		{"flag beats config", func(w *runtest.World) { routineAndHold(w); w.Policy.Config = &core.Config{FailOn: "high"} },
			[]string{"all", "--fail-on", "none"}, cli.ExitOK, ""},
		{"partial with --fail-on", unverifiedTheme, []string{"all", "--fail-on", "high"}, cli.ExitUnavailable,
			"rhythm-sightread all: couldn't verify astra 4.8.1: nothing to check it against\n" +
				"  not diffed; run again later, or --allow-unverified to review it anyway (the report marks it unverified)\n" +
				"rhythm-sightread: the run is partial, so --fail-on high can't pass it\n"},
		{"partial accepted", unverifiedTheme, []string{"all", "--fail-on", "high", "--allow-unverified"}, cli.ExitOK, ""},
		{"partial without --fail-on", unverifiedTheme, []string{"all"}, cli.ExitOK, ""},
		{"findings and gaps exit 1", func(w *runtest.World) { routineAndHold(w); unverifiedTheme(w) },
			[]string{"all", "--fail-on", "high"}, cli.ExitFindings, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w := world(t)
			c.setup(w)
			code, out, errOut := execute(t, c.args...)
			if code != c.code || errOut != c.stderr {
				t.Errorf("exit %d, stderr %q; want %d, %q", code, errOut, c.code, c.stderr)
			}
			if out != "fake terminal: "+fmt.Sprint(len(w.Writers[core.FormatTerminal].Got()[0].Updates))+" updates\n" {
				t.Errorf("stdout %q", out)
			}
		})
	}
}

func unverifiedTheme(w *runtest.World) {
	w.Publish(core.WPTheme, "astra", "4.8.0", "4.8.1")
	w.Install(core.WPTheme, "astra", "4.8.0")
	w.Sources[core.WPTheme].Integrity[core.Ref{Eco: core.WPTheme, Name: "astra", Version: "4.8.1"}] = core.Integrity{By: core.ByNone}
}

// TestOutputs: one run writes several -o formats, each a whole file of
// mode 0600; the terminal view still prints; --json moves stdout to
// JSON.
func TestOutputs(t *testing.T) {
	w := world(t)
	routineAndHold(w)
	dir := t.TempDir()
	var args []string
	for _, ext := range []string{"json", "md", "html", "sarif"} {
		args = append(args, "-o", filepath.Join(dir, "review."+ext))
	}
	code, out, errOut := execute(t, append([]string{"all"}, args...)...)
	if code != cli.ExitOK || out != "fake terminal: 2 updates\n" || errOut != "" {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errOut)
	}
	for _, ext := range []string{"json", "md", "html", "sarif"} {
		path := filepath.Join(dir, "review."+ext)
		b, err := os.ReadFile(path) //nolint:gosec // the test's own file
		if err != nil {
			t.Fatal(err)
		}
		if want := "fake " + map[string]string{"json": "json", "md": "md", "html": "html", "sarif": "sarif"}[ext] + ": 2 updates\n"; string(b) != want {
			t.Errorf("%s: %q, want %q", ext, b, want)
		}
		if fi, err := os.Stat(path); err == nil && runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v, want 0600 (SR-13)", ext, fi.Mode().Perm())
		}
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 4 {
		t.Errorf("left %d files, want only the 4 reports", len(entries))
	}
	code, out, _ = execute(t, "all", "--json")
	if code != cli.ExitOK || out != "fake json: 2 updates\n" {
		t.Errorf("--json: exit %d stdout %q", code, out)
	}
}

// TestChangesBeforeAfter: changes reviews the bumps of two lockfiles.
func TestChangesBeforeAfter(t *testing.T) {
	w := world(t)
	w.Publish(core.NPM, "axios", "1.14.0", "1.14.1")
	from := core.Installed{Ref: core.Ref{Eco: core.NPM, Name: "axios", Version: "1.14.0"}}
	w.Inventory.Bumps = []core.Bump{{From: &from, To: core.Installed{Ref: core.Ref{Eco: core.NPM, Name: "axios", Version: "1.14.1"}}}}
	code, out, errOut := execute(t, "changes", "--before", "old.json", "--after", "package-lock.json", "--json")
	if code != cli.ExitOK || out != "fake json: 1 updates\n" {
		t.Fatalf("exit %d stdout %q stderr %q", code, out, errOut)
	}
	if rep := w.Writers[core.FormatJSON].Got(); rep[0].Target.Kind != "changes" || rep[0].Updates[0].To.Version != "1.14.1" {
		t.Errorf("report %+v", rep[0])
	}
}

// TestAllSitesDedupes: all --sites reviews a plugin shared by two sites
// once and lists both.
func TestAllSitesDedupes(t *testing.T) {
	w := world(t)
	w.Publish(core.WPPlugin, "wpforms-lite", "1.9.1", "1.9.2")
	w.Install(core.WPPlugin, "wpforms-lite", "1.9.1")
	sites := filepath.Join(t.TempDir(), "sites.yaml")
	if err := os.WriteFile(sites, []byte("sites:\n  - name: shop\n    path: shop\n  - name: brochure\n    wp: \"wp --path=/srv/www\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := execute(t, "all", "--sites", sites); code != cli.ExitOK {
		t.Fatalf("exit %d %q", code, errOut)
	}
	rep := w.Writers[core.FormatTerminal].Got()[0]
	if len(rep.Updates) != 1 || !slices.Equal(rep.Updates[0].Sites, []string{"shop", "brochure"}) {
		t.Errorf("updates %+v", rep.Updates)
	}
	if n := w.Sources[core.WPPlugin].Fetches(); n != 2 {
		t.Errorf("%d fetches", n)
	}
	bad := filepath.Join(t.TempDir(), "sites.yaml")
	_ = os.WriteFile(bad, []byte("sites:\n  - name: shop\n    pth: x\n"), 0o600)
	code, _, errOut := execute(t, "all", "--sites", bad)
	if code != cli.ExitUsage || !strings.HasSuffix(errOut, "sites.yaml: line 3: unknown key pth (want name, path, wp, tuner_report or allow_file)\n") {
		t.Errorf("bad sites file: exit %d %q", code, errOut)
	}
}

// TestWritesOnlyCacheAndOutputs walks HOME before and after a run: the
// only new files are in the cache and the requested reports.
func TestWritesOnlyCacheAndOutputs(t *testing.T) {
	w := world(t)
	routineAndHold(w)
	home := t.TempDir()
	cache := filepath.Join(home, ".cache", "rhythm")
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("RHYTHM_CACHE_DIR", cache)
	report := filepath.Join(home, "review.json")
	before := walk(t, home)
	if code, _, errOut := execute(t, "all", "-o", report); code != cli.ExitOK {
		t.Fatalf("exit %d %q", code, errOut)
	}
	for _, p := range walk(t, home) {
		inCache := p == cache || strings.HasPrefix(p, cache+string(filepath.Separator)) || strings.HasPrefix(cache, p+string(filepath.Separator))
		if slices.Contains(before, p) || p == report || inCache {
			continue
		}
		t.Errorf("wrote %s outside the cache and the outputs", p)
	}
}

func walk(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		out = append(out, p)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestJSONLStreams: --jsonl prints each update as it finishes, before
// the run ends, then the closing envelope; a .jsonl -o file gets the
// same lines once complete.
func TestJSONLStreams(t *testing.T) {
	w := world(t)
	for _, n := range []string{"a", "b", "c"} {
		w.Publish(core.WPPlugin, n, "1.0.0", "1.1.0")
		w.Install(core.WPPlugin, n, "1.0.0")
	}
	w.Sources[core.WPPlugin].Delay = func() time.Duration { return 15 * time.Millisecond }
	sw := &streamWriter{}
	t.Cleanup(core.SwapWriter(sw))
	file := filepath.Join(t.TempDir(), "r.jsonl")
	code, out, errOut := execute(t, "all", "--jsonl", "--jobs", "1", "-o", file)
	if code != cli.ExitOK {
		t.Fatalf("exit %d %q", code, errOut)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 4 || lines[3] != "end 3" {
		t.Fatalf("stdout %q", out)
	}
	times := sw.times()
	if len(times) < 4 || times[len(times)-1].Sub(times[0]) < 20*time.Millisecond {
		t.Errorf("the first line wasn't written before the run ended: %v", times)
	}
	b, _ := os.ReadFile(file) //nolint:gosec // the test's own file
	if got := strings.Split(strings.TrimSpace(string(b)), "\n"); len(got) != 4 || got[3] != "end 3" {
		t.Errorf("%s: %q", file, b)
	}
}

// TestJSONLTarget: each --jsonl line is written knowing the report's
// target, so --redact-paths makes its paths relative as the envelope's.
func TestJSONLTarget(t *testing.T) {
	w := world(t)
	w.Publish(core.WPPlugin, "a", "1.0.0", "1.1.0")
	w.Install(core.WPPlugin, "a", "1.0.0")
	tw := &targetStream{}
	t.Cleanup(core.SwapWriter(tw))
	if code, _, errOut := execute(t, "all", "--jsonl", "--redact-paths"); code != cli.ExitOK {
		t.Fatalf("exit %d %q", code, errOut)
	}
	if len(tw.targets) != 1 || tw.targets[0] == "" || tw.targets[0] != tw.report {
		t.Errorf("update targets %q, report target %q", tw.targets, tw.report)
	}
}

// targetStream is a jsonl writer that records the target of each line.
type targetStream struct {
	streamWriter
	targets []string
	report  string
}

func (s *targetStream) WriteUpdateIn(w io.Writer, u *core.Update, target string, o core.WriteOptions) error {
	s.targets = append(s.targets, target)
	return s.WriteUpdate(w, u, o)
}

func (s *targetStream) Write(w io.Writer, r *core.Report, o core.WriteOptions) error {
	s.report = r.Target.Path
	return s.streamWriter.Write(w, r, o)
}

// streamWriter is a jsonl writer that records when it wrote.
type streamWriter struct {
	mu sync.Mutex
	at []time.Time
}

func (s *streamWriter) Format() string { return core.FormatJSONL }

func (s *streamWriter) WriteUpdate(w io.Writer, u *core.Update, _ core.WriteOptions) error {
	s.mu.Lock()
	s.at = append(s.at, time.Now())
	s.mu.Unlock()
	_, err := fmt.Fprintf(w, "update %s\n", u.Name)
	return err
}

func (s *streamWriter) Write(w io.Writer, r *core.Report, _ core.WriteOptions) error {
	s.mu.Lock()
	s.at = append(s.at, time.Now())
	s.mu.Unlock()
	_, err := fmt.Fprintf(w, "end %d\n", len(r.Updates))
	return err
}

func (s *streamWriter) times() []time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.at)
}

// TestVerboseMasksSecrets is the -v part of SR-10: a registry answer
// carrying a credential shows up in the log masked.
func TestVerboseMasksSecrets(t *testing.T) {
	w := world(t)
	w.Publish(core.NPM, "left-pad", "1.0.0", "1.1.0")
	w.Install(core.NPM, "left-pad", "1.0.0")
	key := coretest.FakeKey(coretest.KeyNPM)
	t.Cleanup(core.SwapSource(core.NPM, func(*core.Env) core.Source { return leaky{w.Sources[core.NPM], key} }))
	_, out, errOut := execute(t, "npm", "-v", "--json")
	if !strings.Contains(errOut, "sightread: npm:left-pad") {
		t.Fatalf("no -v log:\n%s", errOut)
	}
	if strings.Contains(errOut, key) || strings.Contains(out, key) {
		t.Errorf("the raw key reached the output:\n%s", errOut)
	}
	rep := w.Writers[core.FormatJSON].Got()[0]
	for _, n := range rep.NotChecked {
		if strings.Contains(n.Text, key) {
			t.Errorf("the raw key reached the report: %q", n.Text)
		}
	}
}

type leaky struct {
	*runtest.Source
	key string
}

func (l leaky) Fetch(_ context.Context, m *core.Meta) (*core.Tree, core.Integrity, error) {
	return nil, core.Integrity{}, errors.New("registry said: bad token " + l.key + " for " + m.Ref.Name)
}

// TestNothingToCompare: a named package already at its candidate prints
// the PRD 6.1 line and exits 0.
func TestNothingToCompare(t *testing.T) {
	w := world(t)
	w.Publish(core.WPPlugin, "akismet", "5.3.3", "5.3.5")
	w.Install(core.WPPlugin, "akismet", "5.3.5")
	code, out, _ := execute(t, "plugin", "akismet")
	if code != cli.ExitOK || out != "akismet 5.3.5 is already the latest: nothing to compare\n" {
		t.Errorf("exit %d stdout %q", code, out)
	}
	// The -o files are still written, so a CI job finds its report.
	path := filepath.Join(t.TempDir(), "r.json")
	code, out, _ = execute(t, "plugin", "akismet", "-o", path)
	if code != cli.ExitOK || out != "akismet 5.3.5 is already the latest: nothing to compare\n" {
		t.Errorf("-o: exit %d stdout %q", code, out)
	}
	if b, err := os.ReadFile(path); err != nil || string(b) != "fake json: 0 updates\n" { //nolint:gosec // the test's own file
		t.Errorf("-o file %q, %v", b, err)
	}
	code, out, _ = execute(t, "plugin", "akismet", "--json")
	if code != cli.ExitOK || out != "fake json: 0 updates\n" {
		t.Errorf("--json: exit %d stdout %q", code, out)
	}
}

// TestExcludeIDKeepsIntegrity: --exclude-id can't hide
// integrity-mismatch.
func TestExcludeIDKeepsIntegrity(t *testing.T) {
	w := world(t)
	w.Publish(core.WPPlugin, "a", "1.0.0", "1.1.0")
	w.Install(core.WPPlugin, "a", "1.0.0")
	w.Detector.Set("a", "integrity-mismatch", "outbound-new-domain")
	code, _, _ := execute(t, "all", "--exclude-id", "integrity-mismatch,outbound-new-domain", "--fail-on", "critical")
	if code != cli.ExitFindings {
		t.Errorf("exit %d", code)
	}
	f := w.Writers[core.FormatTerminal].Got()[0].Updates[0].Findings
	if len(f) != 1 || f[0].ID != "integrity-mismatch" {
		t.Errorf("findings %+v", f)
	}
}

// TestOpenWithoutOpener: --open with no OS opener says where the report
// is.
func TestOpenWithoutOpener(t *testing.T) {
	w := world(t)
	routineAndHold(w)
	t.Setenv("PATH", t.TempDir())
	report := filepath.Join(t.TempDir(), "review.html")
	code, _, errOut := execute(t, "all", "-o", report, "--open")
	if code != cli.ExitOK || errOut != "open "+report+" in a browser\n" {
		t.Errorf("exit %d stderr %q", code, errOut)
	}
	if got := opener("linux", "/r.html"); !slices.Equal(got, []string{"xdg-open", "/r.html"}) {
		t.Errorf("linux opener %q", got)
	}
	if got := opener("darwin", "/r.html"); !slices.Equal(got, []string{"open", "/r.html"}) {
		t.Errorf("macOS opener %q", got)
	}
	if got := opener("windows", `C:\r.html`); !slices.Equal(got, []string{"rundll32", "url.dll,FileProtocolHandler", `C:\r.html`}) {
		t.Errorf("Windows opener %q", got)
	}
}

// TestSign: --sign signs the JSON file.
func TestSign(t *testing.T) {
	w := world(t)
	routineAndHold(w)
	coretest.FakeSigner{}.Install(t)
	dir := t.TempDir()
	code, _, errOut := execute(t, "all", "--sign", "-o", filepath.Join(dir, "r.md"), "-o", filepath.Join(dir, "r.json"))
	if code != cli.ExitOK {
		t.Fatalf("exit %d %q", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(dir, "r.json.sig")); err != nil {
		t.Errorf("no signature: %v", err)
	}
}

// TestToList prints the published versions newest first.
func TestToList(t *testing.T) {
	w := world(t)
	w.Publish(core.WPPlugin, "akismet", "5.3.3", "5.3.5", "5.10.0")
	code, out, _ := execute(t, "plugin", "akismet", "--to", "list")
	if code != cli.ExitOK || out != "5.10.0\n5.3.5\n5.3.3\n" {
		t.Errorf("exit %d stdout %q", code, out)
	}
}

// TestNamedErrors: E1 and E3 come out of a review command in PRD text
// and exit 2.
func TestNamedErrors(t *testing.T) {
	w := world(t)
	w.Publish(core.WPPlugin, "akismet", "5.3.3", "5.3.5")
	code, _, errOut := execute(t, "plugin", "akismet", "--from", "5.3.3", "--to", "9.9.9")
	want := "rhythm-sightread plugin: akismet has no version 9.9.9 on wordpress.org\n  newest: 5.3.5 · see them all: rhythm-sightread plugin akismet --to list\n"
	if code != cli.ExitUsage || errOut != want {
		t.Errorf("E3: exit %d %q", code, errOut)
	}
	code, _, errOut = execute(t, "plugin", "countdown-timer-ultimate")
	if code != cli.ExitUsage || !strings.HasPrefix(errOut, "rhythm-sightread plugin: no installed countdown-timer-ultimate under ") {
		t.Errorf("E1: exit %d %q", code, errOut)
	}
}

// TestSoundcheckProductionUnderPath: the production list of the site's
// .soundcheck/config.yaml applies when the run starts outside the site
// and names it with --path.
func TestSoundcheckProductionUnderPath(t *testing.T) {
	w := world(t)
	site := t.TempDir()
	if err := os.MkdirAll(filepath.Join(site, ".soundcheck"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(site, ".soundcheck", "config.yaml"), []byte("production:\n  - shop.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	chdir(t, t.TempDir())
	args := append(soundcheckUpdate(w, "https://shop.example.com", "wp --path=/srv/staging"), "--path", site)
	code, _, errOut := execute(t, args...)
	if code != cli.ExitUsage || !strings.Contains(errOut, "shop.example.com is listed as production in ") ||
		!strings.Contains(errOut, ".soundcheck/config.yaml") {
		t.Errorf("exit %d stderr %q", code, errOut)
	}
}
