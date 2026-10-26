// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package stage

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// stubDir holds the stub binaries TestMain builds from testdata/stub.
var stubDir string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sightread-stage-stubs-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	code := 1
	if err := buildStubs(dir); err != nil {
		fmt.Fprintln(os.Stderr, "building the stub binaries:", err)
	} else {
		stubDir = dir
		code = m.Run()
	}
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// exe is name with the platform's program suffix.
func exe(name string) string {
	if runtime.GOOS == "windows" {
		return name + ".exe"
	}
	return name
}

// buildStubs builds testdata/stub once and copies it under every name a
// test runs: rhythm-roadie, rhythm-soundcheck, wp and install-cmd.
func buildStubs(dir string) error {
	gobin, err := exec.LookPath("go")
	if err != nil {
		return fmt.Errorf("the stage tests build their stub programs and need go on PATH: %w", err)
	}
	stub := filepath.Join(dir, exe("stub"))
	cmd := exec.Command(gobin, "build", "-o", stub, "./testdata/stub") //nolint:gosec // the test's own stub source
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	b, err := os.ReadFile(stub)
	if err != nil {
		return err
	}
	for _, n := range []string{"rhythm-roadie", "rhythm-soundcheck", "wp", "install-cmd"} {
		if err := os.WriteFile(filepath.Join(dir, exe(n)), b, 0o755); err != nil { //nolint:gosec // a test program
			return err
		}
	}
	return nil
}

// stubCall is one recorded stub run.
type stubCall struct {
	Name      string   `json:"name"`
	Args      []string `json:"args"`
	ZipSHA256 string   `json:"zip_sha256"`
}

// world is one --soundcheck test: a reviewed update, its cached trees,
// a fixture site folder and the stubs' answers.
type world struct {
	t     *testing.T
	log   string
	site  string // the --path site, which nothing may touch
	rep   *core.Report
	plan  Plan
	trees map[core.Ref]*core.Tree
}

const (
	stagingURL = "https://staging.shop.test"
	prodURL    = "https://shop.example.com"
)

func newWorld(t *testing.T) *world {
	t.Helper()
	dir := t.TempDir()
	w := &world{t: t, log: filepath.Join(dir, "stub.jsonl"), site: filepath.Join(dir, "site"), trees: map[core.Ref]*core.Tree{}}
	t.Setenv("STUB_LOG", w.log)
	for _, k := range []string{"ROADIE", "SOUNDCHECK_SNAPSHOT", "SOUNDCHECK_COMPARE", "WP", "INSTALL_CMD"} {
		t.Setenv("STUB_"+k+"_EXIT", "0")
		t.Setenv("STUB_"+k+"_OUT", "")
	}
	// The --path site the review read: byte-identical after every run.
	if err := os.MkdirAll(filepath.Join(w.site, "wp-content", "plugins", "akismet"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(w.site, "wp-content", "plugins", "akismet", "akismet.php"), []byte("<?php // 5.3.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	oldTree := coretest.Tree(map[string]string{"akismet.php": "<?php // 5.3.3\n"})
	newTree := coretest.Tree(map[string]string{"akismet.php": "<?php // 5.3.5\n", "readme.txt": "=== Akismet ===\n"})
	oldTree.Root, newTree.Root = "akismet/", "akismet/"
	oldRef := core.Ref{Eco: core.WPPlugin, Name: "akismet", Version: "5.3.3"}
	newRef := core.Ref{Eco: core.WPPlugin, Name: "akismet", Version: "5.3.5"}
	w.trees[oldRef], w.trees[newRef] = oldTree, newTree
	w.rep = &core.Report{Updates: []core.Update{{Eco: core.WPPlugin, Name: "akismet", Verdict: core.Routine,
		From: core.Side{Version: "5.3.3", SHA256: hex.EncodeToString(oldTree.SHA256[:])},
		To:   core.Side{Version: "5.3.5", SHA256: hex.EncodeToString(newTree.SHA256[:])}}}}
	w.plan = Plan{Command: "plugin", Staging: stagingURL, WP: []string{filepath.Join(stubDir, exe("wp")), "--path=/srv/staging"},
		FailOn: ClassBroke, Dir: dir, Blobs: coretest.MemBlobs(),
		Tree:       func(r core.Ref) (*core.Tree, bool) { tr, ok := w.trees[r]; return tr, ok },
		Soundcheck: filepath.Join(stubDir, exe("rhythm-soundcheck")), Roadie: filepath.Join(stubDir, exe("rhythm-roadie")),
		Lookup: fakeDNS(map[string]string{"staging.shop.test": "10.0.0.2", "shop.example.com": "203.0.113.5"})}
	w.roadie(t, `{"verdict":"ok","data":{"target":"`+stagingURL+`","production_url":"`+prodURL+
		`","signed":true,"sealed":true,"copy_created":"2026-10-25T22:10:00Z","verified_at":"2026-10-26T08:55:12Z","problems":[]}}`)
	w.compare(t, 0, 0, 0)
	return w
}

// fakeDNS answers from a table: tests never resolve a real name.
func fakeDNS(table map[string]string) Resolver {
	return func(_ context.Context, host string) ([]net.IP, error) {
		if ip, ok := table[host]; ok {
			return []net.IP{net.ParseIP(ip)}, nil
		}
		return nil, errors.New("no such host")
	}
}

// roadie sets what rhythm-roadie verify prints: data merged into the
// schema envelope.
func (w *world) roadie(t *testing.T, body string) {
	t.Helper()
	doc := strings.Replace(body, "{", `{"schema":"rhythm-roadie/v1","kind":"verify","tool":"rhythm-roadie","version":"1.0.0",`, 1)
	p := filepath.Join(t.TempDir(), "roadie.json")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STUB_ROADIE_OUT", p)
}

// compare sets what rhythm-soundcheck compare --json prints.
func (w *world) compare(t *testing.T, broke, added, changed int) {
	t.Helper()
	doc := fmt.Sprintf(`{"schema":"rhythm-soundcheck/v1","kind":"comparison","summary":{"broke":%d,"new":%d,"changed":%d,"verdict":"x"},`+
		`"after":{"dir":"/srv/.soundcheck/runs/after"}}`, broke, added, changed)
	p := filepath.Join(t.TempDir(), "compare.json")
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STUB_SOUNDCHECK_COMPARE_OUT", p)
}

func (w *world) calls() []stubCall {
	w.t.Helper()
	f, err := os.Open(w.log)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		w.t.Fatal(err)
	}
	defer f.Close()
	var out []stubCall
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var c stubCall
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			w.t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

// names lists the calls as "name arg0".
func (w *world) names() []string {
	var out []string
	for _, c := range w.calls() {
		n := c.Name
		if len(c.Args) > 0 {
			n += " " + c.Args[0]
		}
		out = append(out, n)
	}
	return out
}

// siteHash fingerprints every file of the --path site.
func (w *world) siteHash() string {
	w.t.Helper()
	h := sha256.New()
	_ = filepath.WalkDir(w.site, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, _ := os.ReadFile(p)
		fmt.Fprintf(h, "%s %x\n", p, sha256.Sum256(b))
		return nil
	})
	return hex.EncodeToString(h.Sum(nil))
}

func (w *world) run() (bool, error) {
	w.t.Helper()
	return Run(context.Background(), w.plan, w.rep)
}

// zipSum is the sha256 of the zip verifiedZip makes for ref.
func (w *world) zipSum(ref core.Ref) string {
	w.t.Helper()
	s := &stager{p: w.plan, host: "staging.shop.test"}
	p, done, err := s.verifiedZip(ref, hex.EncodeToString(w.trees[ref].SHA256[:]))
	if err != nil {
		w.t.Fatal(err)
	}
	defer done()
	b, _ := os.ReadFile(p)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestHappyPath: verify, snapshot, install the verified zip on staging
// through wp, compare; the --path site is untouched.
func TestHappyPath(t *testing.T) {
	w := newWorld(t)
	before := w.siteHash()
	tripped, err := w.run()
	if err != nil || tripped {
		t.Fatalf("tripped %v err %v", tripped, err)
	}
	want := []string{"rhythm-roadie verify", "rhythm-soundcheck snapshot", "wp --path=/srv/staging", "rhythm-soundcheck compare"}
	if got := w.names(); !slices.Equal(got, want) {
		t.Fatalf("calls %q, want %q", got, want)
	}
	calls := w.calls()
	if got := calls[0].Args; !slices.Equal(got, []string{"verify", "--target", stagingURL, "--wp", w.plan.WP[0] + " --path=/srv/staging", "--json"}) {
		t.Errorf("roadie argv %q", got)
	}
	if got := calls[1].Args; !slices.Equal(got, []string{"snapshot", stagingURL, "--name", "sightread-akismet-5.3.3"}) {
		t.Errorf("snapshot argv %q", got)
	}
	inst := calls[2].Args
	if len(inst) != 5 || inst[1] != "plugin" || inst[2] != "install" || filepath.Base(inst[3]) != "akismet.5.3.5.zip" || inst[4] != "--force" {
		t.Errorf("wp argv %q", inst)
	}
	newRef := core.Ref{Eco: core.WPPlugin, Name: "akismet", Version: "5.3.5"}
	if calls[2].ZipSHA256 != w.zipSum(newRef) {
		t.Errorf("wp got another zip than the verified one")
	}
	if got := calls[3].Args; !slices.Equal(got, []string{"compare", stagingURL, "--snapshot", "sightread-akismet-5.3.3", "--json"}) {
		t.Errorf("compare argv %q", got)
	}
	sc := w.rep.Updates[0].Soundcheck
	if sc == nil || sc.RoadieVerify != "ok" || sc.Snapshot != "sightread-akismet-5.3.3" || sc.Report != "/srv/.soundcheck/runs/after" ||
		!strings.HasPrefix(sc.Applied, "verified archive ") || sc.RolledBack {
		t.Errorf("soundcheck %+v", sc)
	}
	if !slices.Contains(w.rep.Notes, NoteRan) || slices.Contains(w.rep.Notes, NoteApplied) {
		t.Errorf("notes %q", w.rep.Notes)
	}
	if w.siteHash() != before {
		t.Error("the --path site changed")
	}
	// The temp zip is gone.
	if _, err := os.Stat(inst[3]); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("temp zip left behind: %v", err)
	}
}

// TestZipContents: the verified zip holds the tree under its top folder.
func TestZipContents(t *testing.T) {
	w := newWorld(t)
	s := &stager{p: w.plan}
	ref := core.Ref{Eco: core.WPPlugin, Name: "akismet", Version: "5.3.5"}
	p, done, err := s.verifiedZip(ref, hex.EncodeToString(w.trees[ref].SHA256[:]))
	if err != nil {
		t.Fatal(err)
	}
	defer done()
	zr, err := zip.OpenReader(p)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
		rc, _ := f.Open()
		b, _ := io.ReadAll(rc)
		rc.Close()
		if f.Name == "akismet/akismet.php" && string(b) != "<?php // 5.3.5\n" {
			t.Errorf("contents %q", b)
		}
	}
	if !slices.Equal(names, []string{"akismet/akismet.php", "akismet/readme.txt"}) {
		t.Errorf("names %q", names)
	}
}

// TestRefusals is T-70: each refusal exits non-zero before anything is
// installed and the --path site stays byte-identical.
func TestRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, w *world)
		code  core.ErrorCode
		exit  int
		text  string
		calls []string
	}{
		{"hold", func(_ *testing.T, w *world) { w.rep.Updates[0].Verdict = core.Hold }, core.ESoundcheckOnHold, cli.ExitFindings,
			"rhythm sightread plugin: akismet 5.3.5 is on HOLD, so --soundcheck won't install it\n" +
				"  review the findings first; --soundcheck-anyway installs it on the staging copy regardless", nil},
		{"no roadie", func(t *testing.T, w *world) {
			t.Setenv("PATH", t.TempDir())
			w.plan.Roadie = ""
		}, core.ESoundcheckMissing, cli.ExitUnavailable,
			"rhythm sightread: --soundcheck needs rhythm-roadie\n  install it with: rhythm install roadie", nil},
		{"no helpers", func(t *testing.T, w *world) {
			t.Setenv("PATH", t.TempDir())
			w.plan.Roadie, w.plan.Soundcheck = "", ""
		}, core.ESoundcheckMissing, cli.ExitUnavailable,
			"rhythm sightread: --soundcheck needs rhythm-soundcheck and rhythm-roadie\n  install them with: rhythm install soundcheck roadie", nil},
		{"failed verify", func(t *testing.T, w *world) {
			w.roadie(t, `{"verdict":"findings","data":{"signed":true,"sealed":true,"copy_created":"2026-10-25T22:10:00Z",`+
				`"verified_at":"2026-10-26T08:55:12Z","problems":[{"kind":"real-email","count":2,"text":"2 real-looking emails"},`+
				`{"kind":"live-key","count":1,"text":"1 live payment key"}]}}`)
			t.Setenv("STUB_ROADIE_EXIT", "1")
		}, core.ESoundcheckMissing, cli.ExitUnavailable,
			"rhythm sightread: staging.shop.test failed rhythm roadie verify (2 real-looking emails, 1 live payment key)\n" +
				"  fix it with rhythm roadie prepare, or --skip-roadie-verify (the report says it was skipped)", []string{"rhythm-roadie verify"}},
		{"stale verify", func(t *testing.T, w *world) {
			w.roadie(t, `{"verdict":"ok","data":{"signed":true,"sealed":true,"copy_created":"2026-10-26T09:00:00Z","verified_at":"2026-10-26T08:55:12Z"}}`)
		}, core.ESoundcheckMissing, cli.ExitUnavailable,
			"rhythm sightread: staging.shop.test failed rhythm roadie verify (the check is older than the copy)\n" +
				"  fix it with rhythm roadie prepare, or --skip-roadie-verify (the report says it was skipped)", []string{"rhythm-roadie verify"}},
		{"unsealed", func(t *testing.T, w *world) {
			w.roadie(t, `{"verdict":"ok","data":{"signed":true,"sealed":false,"copy_created":"2026-10-25T22:10:00Z","verified_at":"2026-10-26T08:55:12Z"}}`)
		}, core.ESoundcheckMissing, cli.ExitUnavailable,
			"rhythm sightread: staging.shop.test failed rhythm roadie verify (outbound mail is not sealed)\n" +
				"  fix it with rhythm roadie prepare, or --skip-roadie-verify (the report says it was skipped)", []string{"rhythm-roadie verify"}},
		{"unsigned", func(t *testing.T, w *world) {
			w.roadie(t, `{"verdict":"ok","data":{"signed":false,"sealed":true,"copy_created":"2026-10-25T22:10:00Z","verified_at":"2026-10-26T08:55:12Z"}}`)
		}, core.ESoundcheckMissing, cli.ExitUnavailable,
			"rhythm sightread: staging.shop.test failed rhythm roadie verify (the copy has no signed Roadie marker)\n" +
				"  fix it with rhythm roadie prepare, or --skip-roadie-verify (the report says it was skipped)", []string{"rhythm-roadie verify"}},
		{"roadie broken", func(t *testing.T, w *world) {
			w.roadie(t, `not json`)
			t.Setenv("STUB_ROADIE_EXIT", "3")
		}, core.ESoundcheckMissing, cli.ExitUnavailable,
			"rhythm sightread plugin: rhythm-roadie verify couldn't run (exit 3)\n  -v shows its output; nothing was installed on staging.shop.test",
			[]string{"rhythm-roadie verify"}},
		{"production in .soundcheck", func(t *testing.T, w *world) {
			writeFile(t, filepath.Join(w.plan.Dir, ".soundcheck", "config.yaml"), "pages: [/]\nproduction:\n  - staging.shop.test\n")
		}, core.EProduction, cli.ExitUsage,
			"rhythm sightread plugin: staging.shop.test is listed as production in " +
				filepath.ToSlash(filepath.Join("{dir}", ".soundcheck", "config.yaml")) + "\n" +
				"  --soundcheck applies the update to the site; point it at a staging copy (rhythm roadie copy makes one)", nil},
		{"production wildcard in config", func(_ *testing.T, w *world) { w.plan.Production = []string{"*.shop.test"} }, core.EProduction, cli.ExitUsage,
			"rhythm sightread plugin: staging.shop.test is listed as production in .sightread/config.yaml (soundcheck.production)\n" +
				"  --soundcheck applies the update to the site; point it at a staging copy (rhythm roadie copy makes one)", nil},
		{"production from roadie", func(t *testing.T, w *world) {
			w.roadie(t, `{"verdict":"ok","data":{"production_url":"https://staging.shop.test/","signed":true,"sealed":true,`+
				`"copy_created":"2026-10-25T22:10:00Z","verified_at":"2026-10-26T08:55:12Z"}}`)
		}, core.EProduction, cli.ExitUsage,
			"rhythm sightread plugin: staging.shop.test is listed as production in the Roadie verify report\n" +
				"  --soundcheck applies the update to the site; point it at a staging copy (rhythm roadie copy makes one)", []string{"rhythm-roadie verify"}},
		{"same address", func(_ *testing.T, w *world) {
			w.plan.Lookup = fakeDNS(map[string]string{"staging.shop.test": "203.0.113.5", "shop.example.com": "203.0.113.5"})
		}, core.EProduction, cli.ExitUsage,
			"rhythm sightread plugin: staging.shop.test resolves to 203.0.113.5, the address of production shop.example.com (the Roadie verify report)\n" +
				"  --soundcheck applies the update to the site; point it at a staging copy (rhythm roadie copy makes one)", []string{"rhythm-roadie verify"}},
		{"remote wp", func(_ *testing.T, w *world) {
			w.plan.WP = []string{"ssh", "deploy@staging", "--", "wp", "--path=/srv/www"}
		},
			core.ERemoteWPSoundcheck, cli.ExitUsage,
			"rhythm sightread plugin: --soundcheck can install the verified zip only through a local wp command\n" +
				"  for a remote staging site give --apply \"<command that installs akismet 5.3.5>\"; the report then says the applied bytes were not checked", nil},
		{"no wp", func(_ *testing.T, w *world) { w.plan.WP = nil }, core.EBadFlag, cli.ExitUsage,
			"rhythm sightread plugin: --soundcheck needs the staging site's wp command to install the verified zip\n" +
				"  give it with --wp \"wp --path=/srv/staging\" (or soundcheck.wp in .sightread/config.yaml)", nil},
		{"npm without apply", func(_ *testing.T, w *world) { w.rep.Updates[0].Eco = core.NPM }, core.EBadFlag, cli.ExitUsage,
			"rhythm sightread plugin: --soundcheck needs --apply \"<command that installs the update on staging>\" for Composer and npm packages", nil},
		{"bad url", func(_ *testing.T, w *world) { w.plan.Staging = "staging.shop.test" }, core.EBadFlag, cli.ExitUsage,
			"rhythm sightread: --soundcheck \"staging.shop.test\": want the staging site's URL, such as https://staging.shop.test", nil},
		{"tampered cache", func(_ *testing.T, w *world) {
			ref := core.Ref{Eco: core.WPPlugin, Name: "akismet", Version: "5.3.5"}
			w.trees[ref].Blobs = tamperedBlobs{w.trees[ref].Blobs}
		}, core.EIntegrityMismatch, cli.ExitUnavailable,
			"rhythm sightread plugin: the cached archive of akismet 5.3.5 doesn't match the reviewed sha256, so --soundcheck won't install it\n" +
				"  the cache changed after the review; run the review again and look at why", []string{"rhythm-roadie verify", "rhythm-soundcheck snapshot"}},
		{"not cached", func(_ *testing.T, w *world) {
			delete(w.trees, core.Ref{Eco: core.WPPlugin, Name: "akismet", Version: "5.3.5"})
		},
			core.ESoundcheckMissing, cli.ExitUnavailable,
			"rhythm sightread plugin: akismet 5.3.5 isn't in the archive cache, so --soundcheck can't install the reviewed bytes\n" +
				"  review it again: verified archives stay cached for 30 days (an unverified one is never cached)",
			[]string{"rhythm-roadie verify", "rhythm-soundcheck snapshot"}},
		{"report hash differs", func(_ *testing.T, w *world) { w.rep.Updates[0].To.SHA256 = strings.Repeat("0", 64) },
			core.EIntegrityMismatch, cli.ExitUnavailable,
			"rhythm sightread plugin: the cached archive of akismet 5.3.5 doesn't match the reviewed sha256, so --soundcheck won't install it\n" +
				"  the cache changed after the review; run the review again and look at why", []string{"rhythm-roadie verify", "rhythm-soundcheck snapshot"}},
		{"snapshot fails", func(t *testing.T, _ *world) { t.Setenv("STUB_SOUNDCHECK_SNAPSHOT_EXIT", "3") }, core.ESoundcheckMissing, cli.ExitUnavailable,
			"rhythm sightread plugin: rhythm-soundcheck snapshot couldn't run (exit 3)\n  -v shows its output; nothing was installed on staging.shop.test",
			[]string{"rhythm-roadie verify", "rhythm-soundcheck snapshot"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(cli.InvokedAsEnv, "rhythm sightread")
			w := newWorld(t)
			c.setup(t, w)
			before := w.siteHash()
			_, err := w.run()
			var e *core.Error
			if !errors.As(err, &e) {
				t.Fatalf("err %v", err)
			}
			want := strings.ReplaceAll(c.text, "{dir}", filepath.ToSlash(w.plan.Dir))
			if e.Code != c.code || e.ExitCode() != c.exit || e.Error() != want {
				t.Errorf("%s exit %d\n%s\nwant %s exit %d\n%s", e.Code, e.ExitCode(), e.Error(), c.code, c.exit, want)
			}
			if got := w.names(); !slices.Equal(got, c.calls) {
				t.Errorf("calls %q, want %q", got, c.calls)
			}
			for _, call := range w.calls() {
				if call.Name == "wp" || call.Name == "install-cmd" {
					t.Errorf("installed despite the refusal: %+v", call)
				}
			}
			if w.siteHash() != before {
				t.Error("the --path site changed")
			}
		})
	}
}

// tamperedBlobs hands back other bytes than the ones stored, like a
// cache file someone edited after the review.
type tamperedBlobs struct{ core.BlobStore }

func (tamperedBlobs) Open([32]byte) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("<?php system($_GET['c']);\n")), nil
}

func writeFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestHoldAnyway: --soundcheck-anyway installs an update on HOLD.
func TestHoldAnyway(t *testing.T) {
	w := newWorld(t)
	w.rep.Updates[0].Verdict = core.Hold
	w.plan.Anyway = true
	if _, err := w.run(); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(w.names(), "wp --path=/srv/staging") {
		t.Errorf("calls %q", w.names())
	}
}

// TestSkipRoadie: no Roadie call, the note says so; Roadie need not be
// installed.
func TestSkipRoadie(t *testing.T) {
	w := newWorld(t)
	t.Setenv("PATH", t.TempDir())
	w.plan.Roadie, w.plan.SkipRoadie = "", true
	if _, err := w.run(); err != nil {
		t.Fatal(err)
	}
	if slices.Contains(w.names(), "rhythm-roadie verify") || !slices.Contains(w.rep.Notes, NoteSkipRoadie) ||
		w.rep.Updates[0].Soundcheck.RoadieVerify != "skipped" {
		t.Errorf("calls %q notes %q", w.names(), w.rep.Notes)
	}
}

// TestRollback: changes at --soundcheck-fail-on trip the gate and
// --rollback reinstalls the verified old archive; below it nothing
// trips.
func TestRollback(t *testing.T) {
	w := newWorld(t)
	w.compare(t, 1, 0, 0)
	w.plan.Rollback = true
	tripped, err := w.run()
	if err != nil || !tripped {
		t.Fatalf("tripped %v err %v", tripped, err)
	}
	calls := w.calls()
	last := calls[len(calls)-1]
	oldRef := core.Ref{Eco: core.WPPlugin, Name: "akismet", Version: "5.3.3"}
	if last.Name != "wp" || filepath.Base(last.Args[3]) != "akismet.5.3.3.zip" || last.ZipSHA256 != w.zipSum(oldRef) {
		t.Errorf("rollback call %+v", last)
	}
	if sc := w.rep.Updates[0].Soundcheck; !sc.RolledBack || sc.Broke != 1 {
		t.Errorf("soundcheck %+v", sc)
	}

	// NEW changes under the default class broke: no trip, no rollback.
	w = newWorld(t)
	w.compare(t, 0, 2, 5)
	w.plan.Rollback = true
	if tripped, err := w.run(); err != nil || tripped || w.rep.Updates[0].Soundcheck.RolledBack {
		t.Errorf("tripped %v err %v", tripped, err)
	}
	// The same with --soundcheck-fail-on new trips.
	w = newWorld(t)
	w.compare(t, 0, 2, 0)
	w.plan.FailOn = ClassNew
	if tripped, err := w.run(); err != nil || !tripped {
		t.Errorf("new: tripped %v err %v", tripped, err)
	}
	w = newWorld(t)
	w.compare(t, 0, 0, 1)
	w.plan.FailOn = ClassChanged
	if tripped, err := w.run(); err != nil || !tripped {
		t.Errorf("changed: tripped %v err %v", tripped, err)
	}
}

// TestApplyCommand: composer and npm (or a remote wp) install through
// the user's --apply command, with the unchecked-bytes note.
func TestApplyCommand(t *testing.T) {
	w := newWorld(t)
	w.rep.Updates[0].Eco = core.NPM
	w.plan.Apply = []string{filepath.Join(stubDir, exe("install-cmd")), "npm", "install", "left-pad@1.4.0"}
	w.plan.Rollback = true
	w.compare(t, 1, 0, 0)
	tripped, err := w.run()
	if err != nil || !tripped {
		t.Fatalf("tripped %v err %v", tripped, err)
	}
	want := []string{"rhythm-roadie verify", "rhythm-soundcheck snapshot", "install-cmd npm", "rhythm-soundcheck compare"}
	if got := w.names(); !slices.Equal(got, want) {
		t.Errorf("calls %q, want %q", got, want)
	}
	sc := w.rep.Updates[0].Soundcheck
	if sc.Applied != "your command" || sc.RolledBack || !slices.Contains(w.rep.Notes, NoteApplied) || !slices.Contains(w.rep.Notes, NoteNoRollback) {
		t.Errorf("soundcheck %+v notes %q", sc, w.rep.Notes)
	}
}

// TestSoundcheckFailures: a failed install or compare is exit 3 after
// the update went on the copy; the message says so.
func TestSoundcheckFailures(t *testing.T) {
	t.Setenv(cli.InvokedAsEnv, "rhythm sightread")
	w := newWorld(t)
	t.Setenv("STUB_WP_EXIT", "1")
	_, err := w.run()
	if err == nil || core.CodeOf(err) != core.ESoundcheckMissing || !strings.Contains(err.Error(), "couldn't install akismet 5.3.5 on staging.shop.test: wp") {
		t.Errorf("install: %v", err)
	}
	w = newWorld(t)
	t.Setenv("STUB_WP_EXIT", "0")
	t.Setenv("STUB_SOUNDCHECK_COMPARE_EXIT", "3")
	_, err = w.run()
	var e *core.Error
	if !errors.As(err, &e) || e.ExitCode() != cli.ExitUnavailable ||
		e.Error() != "rhythm sightread plugin: rhythm-soundcheck compare couldn't run (exit 3)\n"+
			"  -v shows its output; akismet 5.3.5 is installed on staging.shop.test, so check the site yourself" {
		t.Errorf("compare: %v", err)
	}
}

// TestSoundcheckFailureRecorded: a compare that prints something else
// than a comparison leaves the report incomplete with the reason in
// the Soundcheck block and the report errors. It has no counts.
func TestSoundcheckFailureRecorded(t *testing.T) {
	w := newWorld(t)
	w.rep.Complete = true
	p := filepath.Join(t.TempDir(), "compare.json")
	if err := os.WriteFile(p, []byte(`{"schema":"rhythm-soundcheck/v1","kind":"snapshot"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STUB_SOUNDCHECK_COMPARE_OUT", p)
	if _, err := w.run(); core.CodeOf(err) != core.ESoundcheckMissing {
		t.Fatalf("err %v", err)
	}
	sc := w.rep.Updates[0].Soundcheck
	if w.rep.Complete || sc == nil || !sc.NotCompared || !strings.Contains(sc.Error, "rhythm-soundcheck compare couldn't run") {
		t.Errorf("complete %v soundcheck %+v", w.rep.Complete, sc)
	}
	if len(w.rep.Errors) != 1 || w.rep.Errors[0].Code != core.ESoundcheckMissing || w.rep.Errors[0].Name != "akismet" ||
		!strings.HasPrefix(w.rep.Errors[0].Message, "--soundcheck: ") {
		t.Errorf("errors %+v", w.rep.Errors)
	}
	// A finished run leaves the report as it was.
	w = newWorld(t)
	w.rep.Complete = true
	if _, err := w.run(); err != nil || !w.rep.Complete || len(w.rep.Errors) != 0 || w.rep.Updates[0].Soundcheck.NotCompared {
		t.Errorf("finished run: %v complete %v errors %v", err, w.rep.Complete, w.rep.Errors)
	}
}

// TestVerboseLog: -v lists every program with its purpose and the
// helpers' stderr after a failure.
func TestVerboseLog(t *testing.T) {
	w := newWorld(t)
	var log bytes.Buffer
	w.plan.Log = &log
	t.Setenv("STUB_SOUNDCHECK_SNAPSHOT_EXIT", "2")
	_, _ = w.run()
	for _, want := range []string{"run roadie: ", "run soundcheck: ", "rhythm-soundcheck snapshot: rhythm-soundcheck stub ran"} {
		if !strings.Contains(log.String(), want) {
			t.Errorf("log lacks %q:\n%s", want, log.String())
		}
	}
}

// TestVerboseLogMasksSecrets: a token in a helper's stderr is masked in
// the -v log.
func TestVerboseLogMasksSecrets(t *testing.T) {
	w := newWorld(t)
	var log bytes.Buffer
	w.plan.Log = &log
	key := "sk_" + "live_" + strings.Repeat("Ab3", 8)
	t.Setenv("STUB_STDERR", "Error: auth failed for "+key)
	t.Setenv("STUB_WP_EXIT", "1")
	_, _ = w.run()
	if strings.Contains(log.String(), key) || !strings.Contains(log.String(), "Error: auth failed for sk_l") {
		t.Errorf("the key reached the log or the line is missing:\n%s", log.String())
	}
}

// TestNothingToInstall: a run with no update (up to date) does nothing.
func TestNothingToInstall(t *testing.T) {
	w := newWorld(t)
	w.rep.Updates = nil
	if tripped, err := w.run(); err != nil || tripped || len(w.calls()) != 0 {
		t.Errorf("tripped %v err %v calls %q", tripped, err, w.names())
	}
}

func TestRemotePrefix(t *testing.T) {
	for _, argv := range [][]string{
		{"ssh", "deploy@host", "--", "wp"}, {"/usr/bin/docker", "exec", "wp", "wp"}, {"ddev", "wp"}, {"lando", "wp"},
		{"wp", "--ssh=deploy@host/srv"}, {"wp", "@staging"}, {`C:\tools\ssh.exe`, "x"},
	} {
		if !remotePrefix(argv) {
			t.Errorf("%q: not remote", argv)
		}
	}
	for _, argv := range [][]string{{"wp", "--path=/srv/staging"}, {"/usr/local/bin/wp"}, {"php", "wp-cli.phar", "--path=/x"}, nil} {
		if remotePrefix(argv) {
			t.Errorf("%q: remote", argv)
		}
	}
}

func TestProductionMatch(t *testing.T) {
	for _, c := range []struct {
		entry, host string
		want        bool
	}{
		{"shop.example.com", "shop.example.com", true},
		{"https://Shop.Example.com/shop/", "shop.example.com", true},
		{"shop.example.com:8443", "shop.example.com", true},
		{"*.example.com", "a.example.com", true},
		{"*.example.com", "example.com", false},
		{"shop.example.com", "staging.shop.example.com", false},
		{"", "shop.example.com", false},
	} {
		if got := (production{entry: c.entry}).matches(c.host); got != c.want {
			t.Errorf("%q vs %q: %v", c.entry, c.host, got)
		}
	}
	if got := snapshotName("@acme/billing", "2.0.0"); got != "sightread-acme-billing-2.0.0" {
		t.Errorf("snapshot name %q", got)
	}
	if got := snapshotName("axois", ""); got != "sightread-axois-new" {
		t.Errorf("snapshot name %q", got)
	}
}

// pathBlobs serves one archive file by its hash, as the disk store does.
type pathBlobs struct {
	core.BlobStore
	sum  [32]byte
	path string
}

func (b pathBlobs) Path(sum [32]byte) (string, bool) { return b.path, sum == b.sum }

// TestArchiveKept: a theme archive kept whole is copied byte for byte
// after its hash checks out; an edited cache file is refused (T-71).
func TestArchiveKept(t *testing.T) {
	w := newWorld(t)
	w.rep.Updates[0].Eco = core.WPTheme
	archive := []byte("PK\x03\x04 pretend theme zip 1.2.0")
	sum := sha256.Sum256(archive)
	file := filepath.Join(t.TempDir(), "blob")
	writeFile(t, file, string(archive))
	ref := core.Ref{Eco: core.WPTheme, Name: "akismet", Version: "5.3.5"}
	w.trees[ref] = &core.Tree{SHA256: sum, HashKind: core.HashArchive}
	w.rep.Updates[0].To.SHA256 = hex.EncodeToString(sum[:])
	w.plan.Blobs = pathBlobs{sum: sum, path: file}
	if _, err := w.run(); err != nil {
		t.Fatal(err)
	}
	inst := w.calls()[2]
	if inst.Args[1] != "theme" || inst.ZipSHA256 != hex.EncodeToString(sum[:]) {
		t.Errorf("install %+v", inst)
	}

	w = newWorld(t)
	w.rep.Updates[0].Eco = core.WPTheme
	w.trees[ref] = &core.Tree{SHA256: sum, HashKind: core.HashArchive}
	w.rep.Updates[0].To.SHA256 = hex.EncodeToString(sum[:])
	writeFile(t, file, string(archive)+"<?php system($_GET['c']);")
	w.plan.Blobs = pathBlobs{sum: sum, path: file}
	if _, err := w.run(); core.CodeOf(err) != core.EIntegrityMismatch {
		t.Errorf("tampered archive: %v", err)
	}
	for _, c := range w.calls() {
		if c.Name == "wp" {
			t.Errorf("installed a tampered archive: %+v", c)
		}
	}
}

// TestPrecheckRemoteWP: a remote --wp prefix is refused before the
// review, which would otherwise run it to read the site (E21); --apply,
// a local wp command and a Composer package with --apply pass.
func TestPrecheckRemoteWP(t *testing.T) {
	remote := []string{"ssh", "-p", "2222", "staging", "wp"}
	err := Precheck("plugin", core.WPPlugin, "countdown", "https://staging.shop.test", false, remote)
	if core.CodeOf(err) != core.ERemoteWPSoundcheck || !strings.Contains(err.Error(), `--apply "<command that installs countdown>"`) {
		t.Errorf("remote --wp: %v", err)
	}
	for _, c := range []struct {
		eco   core.Ecosystem
		apply bool
		wp    []string
	}{
		{core.WPPlugin, true, remote},
		{core.WPTheme, false, []string{"wp", "--path=/srv/staging"}},
		{core.Composer, true, remote},
	} {
		if err := Precheck("plugin", c.eco, "x", "https://staging.shop.test", c.apply, c.wp); err != nil {
			t.Errorf("%s apply %v wp %q: %v", c.eco, c.apply, c.wp, err)
		}
	}
}
