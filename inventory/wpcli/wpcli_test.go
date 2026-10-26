// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package wpcli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/core"
)

// stubWP is the stub wp binary TestMain builds from testdata/stubwp.
var stubWP string

func TestMain(m *testing.M) {
	code, err := buildStub()
	if err != nil {
		fmt.Fprintln(os.Stderr, "wpcli tests:", err)
		os.Exit(1)
	}
	os.Exit(code(m))
}

// buildStub compiles the stub with the go command running the tests.
func buildStub() (func(*testing.M) int, error) {
	gobin := filepath.Join(runtime.GOROOT(), "bin", "go") //nolint:staticcheck // the toolchain that runs the test
	if _, err := os.Stat(gobin); err != nil {
		if gobin, err = exec.LookPath("go"); err != nil {
			return nil, errors.New("no go command to build testdata/stubwp")
		}
	}
	dir, err := os.MkdirTemp("", "stubwp")
	if err != nil {
		return nil, err
	}
	name := "wp"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	stubWP = filepath.Join(dir, name)
	cmd := exec.Command(gobin, "build", "-o", stubWP, "./testdata/stubwp/main.go")
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("build testdata/stubwp: %w\n%s", err, out)
	}
	return func(m *testing.M) int {
		defer os.RemoveAll(dir)
		return m.Run()
	}, nil
}

// fixture copies testdata/site into a temp folder, points the stub at
// it and returns the folder and the argv log.
func fixture(t *testing.T) (dir, log string) {
	t.Helper()
	dir = t.TempDir()
	ents, err := os.ReadDir("testdata/site")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		b, err := os.ReadFile(filepath.Join("testdata/site", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, e.Name()), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	log = filepath.Join(t.TempDir(), "argv.log")
	t.Setenv("STUBWP_DIR", dir)
	t.Setenv("STUBWP_LOG", log)
	t.Setenv("STUBWP_SLEEP", "")
	return dir, log
}

// calls reads the argv log.
func calls(t *testing.T, log string) [][]string {
	t.Helper()
	b, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]string
	for line := range strings.SplitSeq(strings.TrimSpace(string(b)), "\n") {
		out = append(out, strings.Split(line, "\x1f"))
	}
	return out
}

func TestListRunsOnlyTheFixedCalls(t *testing.T) {
	_, log := fixture(t)
	var vlog bytes.Buffer
	l, err := List(context.Background(), []string{stubWP, "--path=/srv/shop"}, Options{Command: "all", Log: &vlog})
	if err != nil {
		t.Fatal(err)
	}
	want := [][]string{
		{"--path=/srv/shop", "plugin", "list", "--format=json", "--fields=name,status,version,update_version,auto_update"},
		{"--path=/srv/shop", "theme", "list", "--format=json", "--fields=name,status,version,update_version,auto_update"},
		{"--path=/srv/shop", "core", "version"},
		{"--path=/srv/shop", "option", "get", "auto_update_plugins", "--format=json"},
	}
	got := calls(t, log)
	if len(got) != len(want) {
		t.Fatalf("ran %d calls, want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if !slices.Equal(got[i], want[i]) {
			t.Errorf("call %d = %q, want %q", i, got[i], want[i])
		}
	}
	// Every call is one of the fixed table: nothing else can be run.
	for _, c := range got {
		if !slices.ContainsFunc(Calls(), func(f []string) bool { return slices.Equal(c[1:], f) }) {
			t.Errorf("ran %q, not in the fixed table", c)
		}
	}
	if n := strings.Count(vlog.String(), "run wp-cli: "); n != 4 {
		t.Errorf("-v log has %d lines, want 4:\n%s", n, vlog.String())
	}
	if l.Core != "6.6.2" || len(l.Plugins) != 5 || len(l.Themes) != 2 {
		t.Fatalf("listing = %+v", l)
	}
	if p := l.Plugins[0]; p.Name != "akismet" || p.Version != "5.3.5" || p.UpdateVersion != "5.3.7" || p.AutoUpdate != "on" {
		t.Errorf("akismet = %+v", p)
	}
	if !slices.Equal(l.AutoUpdatePlugins, []string{"akismet/akismet.php", "hello.php"}) {
		t.Errorf("auto_update_plugins = %q", l.AutoUpdatePlugins)
	}
}

func TestMissingOptionMeansNone(t *testing.T) {
	dir, _ := fixture(t)
	writeFile(t, dir, "option.exit", "1")
	writeFile(t, dir, "option.stderr", "Error: Could not get 'auto_update_plugins' option. Does it exist?\n")
	l, err := List(context.Background(), []string{stubWP}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(l.AutoUpdatePlugins) != 0 {
		t.Errorf("auto_update_plugins = %q, want none", l.AutoUpdatePlugins)
	}
}

func TestOptionAsObject(t *testing.T) {
	dir, _ := fixture(t)
	writeFile(t, dir, "option.json", `{"0":"b/b.php","2":"a/a.php"}`)
	l, err := List(context.Background(), []string{stubWP}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(l.AutoUpdatePlugins, []string{"a/a.php", "b/b.php"}) {
		t.Errorf("auto_update_plugins = %q", l.AutoUpdatePlugins)
	}
}

func TestNoticeBeforeJSONIsAWarning(t *testing.T) {
	dir, _ := fixture(t)
	b, _ := os.ReadFile(filepath.Join(dir, "plugin.json"))
	writeFile(t, dir, "plugin.json", "Deprecated: Creation of dynamic property in x.php on line 3\n"+string(b))
	l, err := List(context.Background(), []string{stubWP}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := "the wp command printed text before its JSON: Deprecated: Creation of dynamic property in x.php on line 3"
	if !slices.Contains(l.Warnings, want) {
		t.Errorf("warnings = %q, want %q", l.Warnings, want)
	}
}

func TestE1OnNonZeroExit(t *testing.T) {
	dir, _ := fixture(t)
	writeFile(t, dir, "plugin.exit", "1")
	writeFile(t, dir, "plugin.stderr", "Error: This does not seem to be a WordPress installation.\n")
	_, err := List(context.Background(), []string{stubWP, "--path=/srv/shop"}, Options{Command: "plugin"})
	var e *core.Error
	if !errors.As(err, &e) || e.Code != core.ENothingInstalled || e.ExitCode() != 2 {
		t.Fatalf("err = %v, want E1 exit 2", err)
	}
	cmd := stubWP + " --path=/srv/shop"
	want := fmt.Sprintf("rhythm-sightread plugin: --wp %q: plugin list failed (exit 1): Error: This does not seem to be a WordPress installation.\n"+
		"  check that %s plugin list works on its own\n"+
		"  or name the site with --path /var/www/site, or give the version: --from <version>", cmd, cmd)
	if got := e.Error(); !strings.HasSuffix(got, strings.TrimPrefix(want, "rhythm-sightread")) {
		t.Errorf("error =\n%s\nwant\n%s", got, want)
	}
}

func TestE1OnBadJSON(t *testing.T) {
	for name, body := range map[string]string{
		"unknown field": `[{"name":"a","status":"active","version":"1","update_version":"","auto_update":"off","file":"a.php"}]`,
		"bad auto":      `[{"name":"a","status":"active","version":"1","update_version":"","auto_update":"yes"}]`,
		"trailing":      `[] []`,
		"no name":       `[{"name":"","status":"active"}]`,
		"not json":      `Success: done`,
	} {
		t.Run(name, func(t *testing.T) {
			dir, _ := fixture(t)
			writeFile(t, dir, "plugin.json", body)
			_, err := List(context.Background(), []string{stubWP}, Options{})
			if core.CodeOf(err) != core.ENothingInstalled || !strings.Contains(err.Error(), "plugin list did not print the JSON Sightread reads") {
				t.Errorf("err = %v", err)
			}
		})
	}
}

func TestE1OnBadCoreVersion(t *testing.T) {
	dir, _ := fixture(t)
	writeFile(t, dir, "core.txt", "Error: not installed")
	_, err := List(context.Background(), []string{stubWP}, Options{})
	if core.CodeOf(err) != core.ENothingInstalled {
		t.Errorf("err = %v", err)
	}
}

func TestE1WhenTheCommandIsMissing(t *testing.T) {
	_, err := List(context.Background(), []string{filepath.Join(t.TempDir(), "no-such-wp")}, Options{})
	if core.CodeOf(err) != core.ENothingInstalled || !strings.Contains(err.Error(), "was not found") {
		t.Errorf("err = %v", err)
	}
	if _, err := List(context.Background(), nil, Options{}); core.CodeOf(err) != core.ENothingInstalled {
		t.Errorf("empty prefix: err = %v", err)
	}
}

func TestTimeout(t *testing.T) {
	_, log := fixture(t)
	t.Setenv("STUBWP_SLEEP", "theme")
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	start := time.Now()
	_, err := List(context.Background(), []string{stubWP}, Options{Timeout: 300 * time.Millisecond})
	if core.CodeOf(err) != core.ENothingInstalled || !strings.Contains(err.Error(), "theme list did not finish within 300ms") {
		t.Fatalf("err = %v", err)
	}
	if d := time.Since(start); d > 20*time.Second {
		t.Errorf("took %s", d)
	}
	if n := len(calls(t, log)); n != 2 {
		t.Errorf("ran %d calls after the timeout, want it to stop at 2", n)
	}
}

func TestCanceledContext(t *testing.T) {
	fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := List(ctx, []string{stubWP}, Options{}); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestSecretsMaskedInErrors(t *testing.T) {
	dir, _ := fixture(t)
	key := "sk_" + "live_" + strings.Repeat("4eC39HqLyjWDarjtT1zdp7dc", 1)
	writeFile(t, dir, "plugin.exit", "1")
	writeFile(t, dir, "plugin.stderr", "Error: STRIPE_KEY="+key+"\n")
	_, err := List(context.Background(), []string{stubWP}, Options{})
	if err == nil || strings.Contains(err.Error(), key) {
		t.Errorf("err = %v, the key must be masked", err)
	}
}

func TestSSHPrefixQuotesArguments(t *testing.T) {
	got := wpArgv([]string{"ssh", "deploy@staging", "--", "wp"}, "plugin", "list", "a b")
	want := []string{"ssh", "deploy@staging", "--", "wp", "plugin", "list", "'a b'"}
	if !slices.Equal(got, want) {
		t.Errorf("argv = %q, want %q", got, want)
	}
	for _, c := range Calls() {
		if !slices.Equal(wpArgv([]string{"ssh", "h", "wp"}, c...)[3:], c) {
			t.Errorf("%q needs quoting through ssh; keep the fixed calls plain words", c)
		}
	}
}

func TestSplitCommand(t *testing.T) {
	for in, want := range map[string][]string{
		`wp --path=/srv/www`:                    {"wp", "--path=/srv/www"},
		`ssh deploy@h -- wp "--path=/a b"`:      {"ssh", "deploy@h", "--", "wp", "--path=/a b"},
		`ddev wp`:                               {"ddev", "wp"},
		`docker compose exec -T wp wp 'x'`:      {"docker", "compose", "exec", "-T", "wp", "wp", "x"},
		`wp\ cli`:                               {"wp cli"},
		"wp --path=\"/a\\$b\"":                  {"wp", "--path=/a$b"},
		`  wp   plugin  `:                       {"wp", "plugin"},
		`C:\\wp\\wp.bat`:                        {`C:\wp\wp.bat`},
		`"" x`:                                  {"", "x"},
		`lando wp --url=https://shop.lndo.site`: {"lando", "wp", "--url=https://shop.lndo.site"},
	} {
		got, err := splitCommand(in, false)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("SplitCommand(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "   ", `wp; rm -rf /`, `wp | tee`, `wp && x`, "wp `id`", `wp $(id)`, `wp > out`, `"open`, `x\`} {
		if got, err := splitCommand(in, false); err == nil {
			t.Errorf("SplitCommand(%q) = %q, want an error", in, got)
		}
	}
}

func FuzzSplitCommand(f *testing.F) {
	for _, s := range []string{`wp --path=/srv`, `ssh h -- wp "a b"`, `a'b'c`, `x\ y`, `wp; x`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		words, err := SplitCommand(s)
		if err == nil && len(words) == 0 {
			t.Errorf("SplitCommand(%q) gave no words and no error", s)
		}
	})
}

func FuzzDecodeItems(f *testing.F) {
	b, _ := os.ReadFile("testdata/site/plugin.json")
	f.Add(b)
	f.Add([]byte("notice\n[]"))
	f.Fuzz(func(t *testing.T, data []byte) {
		items, err := decodeItems(data, &Listing{})
		if err != nil {
			return
		}
		for _, it := range items {
			if it.Name == "" || it.AutoUpdate != "" && it.AutoUpdate != "on" && it.AutoUpdate != "off" {
				t.Errorf("accepted %+v", it)
			}
		}
	})
}

func writeFile(t *testing.T, dir, name, data string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestSplitCommandWindows: on Windows a backslash is a path separator,
// literal unless it escapes a double quote; the shell operators are
// still refused.
func TestSplitCommandWindows(t *testing.T) {
	for in, want := range map[string][]string{
		`C:\tools\wp.bat --path=C:\site`:      {`C:\tools\wp.bat`, `--path=C:\site`},
		`"C:\Program Files\wp\wp.bat" plugin`: {`C:\Program Files\wp\wp.bat`, "plugin"},
		`wp --title=\"x\"`:                    {"wp", `--title="x"`},
		`wp "a\"b"`:                           {"wp", `a"b`},
		`\\server\share\wp.bat`:               {`\\server\share\wp.bat`},
		`wp x\`:                               {"wp", `x\`},
	} {
		got, err := splitCommand(in, true)
		if err != nil || !slices.Equal(got, want) {
			t.Errorf("windows %q = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{`C:\wp.bat; del x`, `wp | x`, `"open`} {
		if got, err := splitCommand(in, true); err == nil {
			t.Errorf("windows %q = %q, want an error", in, got)
		}
	}
}

// TestSplitCommandOnWindows runs SplitCommand itself on a Windows host.
func TestSplitCommandOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows only")
	}
	got, err := SplitCommand(`C:\tools\wp.bat --path=C:\site`)
	if err != nil || !slices.Equal(got, []string{`C:\tools\wp.bat`, `--path=C:\site`}) {
		t.Errorf("got %q, %v", got, err)
	}
}
