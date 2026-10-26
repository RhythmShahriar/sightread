// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// childEnv makes the test binary run main instead of the tests, so a
// test sees the real exit code and output of cli.Main.
const childEnv = "SIGHTREAD_MAIN_CHILD"

func TestMain(m *testing.M) {
	if os.Getenv(childEnv) == "1" {
		main()
	}
	os.Exit(m.Run())
}

// child runs the test binary as rhythm-sightread with args and returns
// its exit code, stdout and stderr. configDir is the kit config folder,
// so first-run markers stay in the test.
func child(t *testing.T, configDir string, args ...string) (int, string, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...) //nolint:gosec // the test binary itself
	cmd.Env = append(os.Environ(), childEnv+"=1", "RHYTHM_NO_UPDATE_CHECK=1", cli.OfflineEnv+"=1",
		"RHYTHM_CONFIG_DIR="+configDir, "RHYTHM_CACHE_DIR="+t.TempDir(), cli.InvokedAsEnv+"=rhythm-sightread")
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		t.Fatal(err)
	}
	return cmd.ProcessState.ExitCode(), out.String(), errb.String()
}

// execute runs one command in-process the way cli.Main does and returns
// the exit code cli.Main would give it, with stdout and stderr.
func execute(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	t.Setenv(cli.InvokedAsEnv, "rhythm-sightread")
	var out, errb bytes.Buffer
	for _, c := range commands() {
		if c.Name == args[0] {
			err := c.Run(context.Background(), args[1:], &out, &errb)
			return exitCode(&errb, c.Name, err), out.String(), errb.String()
		}
	}
	t.Fatalf("no command %s", args[0])
	return 0, "", ""
}

// exitCode is cli.Main's mapping of a command's error to an exit code,
// printing what it prints (kit cli/tool.go exitFor; internal/kitcheck
// holds the kit to it).
func exitCode(stderr io.Writer, cmd string, err error) int {
	var ee *cli.ExitError
	var ue cli.UsageError
	prog := cli.Name()
	switch {
	case err == nil, errors.Is(err, cli.ErrHelp):
		return cli.ExitOK
	case errors.As(err, &ee):
		if ee.Err != nil {
			_, _ = io.WriteString(stderr, prog+": "+ee.Err.Error()+"\n")
		}
		return ee.Code
	case errors.As(err, &ue):
		if !ue.Reported {
			_, _ = io.WriteString(stderr, prog+": "+ue.Msg+"\n  run '"+prog+" help "+cmd+"' for usage\n")
		}
		return cli.ExitUsage
	}
	_, _ = io.WriteString(stderr, prog+": "+err.Error()+"\n")
	return cli.ExitUnavailable
}

// pdrOrder is every command of PRD section 6 in its order.
var prdOrder = []string{"plugin", "theme", "composer", "npm", "all", "changes", "explain", "allow", "watch", "report",
	"verify-report", "init", "doctor", "demo", "signals", "cache", "update"}

// TestCommandsInPRDOrder: every command of PRD 6 is registered, in that
// order, with the hidden picker last.
func TestCommandsInPRDOrder(t *testing.T) {
	var got []string
	for _, c := range commands() {
		if !c.Hidden {
			got = append(got, c.Name)
		}
	}
	if !reflect.DeepEqual(got, prdOrder) {
		t.Errorf("commands %q, want %q", got, prdOrder)
	}
	if cs := commands(); cs[len(cs)-1].Name != "pick" || !cs[len(cs)-1].Hidden {
		t.Errorf("the picker is not the hidden last command")
	}
}

// TestHelpListsEveryCommand: top-level help names every command, with
// the update line of PRD 0; it leaves the picker out.
func TestHelpListsEveryCommand(t *testing.T) {
	code, out, _ := child(t, t.TempDir(), "--help")
	if code != cli.ExitOK {
		t.Fatalf("--help exit %d:\n%s", code, out)
	}
	for _, name := range prdOrder {
		if !strings.Contains(out, "  "+name+" ") {
			t.Errorf("help has no %s line\n%s", name, out)
		}
	}
	if strings.Contains(out, "  pick") {
		t.Errorf("help lists the hidden picker")
	}
	if !strings.Contains(out, updateSummary) || !strings.Contains(out, summary) {
		t.Errorf("help lacks the update line or the summary:\n%s", out)
	}
}

// TestEveryCommandAnswersHelp: each command's --help and help <cmd>
// print its usage line on stdout and exit 0, through cli.Main.
func TestEveryCommandAnswersHelp(t *testing.T) {
	for _, name := range append(prdOrder, "pick") {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			for _, args := range [][]string{{name, "--help"}, {"help", name}} {
				code, out, errOut := child(t, t.TempDir(), args...)
				if code != cli.ExitOK || !strings.Contains(out, "Usage: rhythm-sightread") {
					t.Errorf("%v: exit %d, stdout:\n%s\nstderr:\n%s", args, code, out, errOut)
				}
			}
		})
	}
}

// TestBareRunOffTerminal: with no arguments and no terminal the usage
// prints and the exit is 0 (the picker needs a terminal).
func TestBareRunOffTerminal(t *testing.T) {
	code, out, _ := child(t, t.TempDir())
	if code != cli.ExitOK || !strings.Contains(out, "Usage:") || !strings.Contains(out, "plugin <slug>...") {
		t.Errorf("bare run: exit %d\n%s", code, out)
	}
	if bareTerminal([]string{"plugin"}, func(string) string { return "" }) {
		t.Errorf("a run with arguments opened the picker")
	}
	if bareTerminal(nil, func(k string) string { return map[string]string{"CI": "true"}[k] }) {
		t.Errorf("the picker opened in CI")
	}
}

// TestUnknownCommand is E20, the kit text.
func TestUnknownCommand(t *testing.T) {
	code, _, errOut := child(t, t.TempDir(), "plugn")
	want := "rhythm-sightread: unknown command \"plugn\"\n  did you mean: rhythm-sightread plugin\n  run 'rhythm-sightread help' to see the commands\n"
	if code != cli.ExitUsage || errOut != want {
		t.Errorf("plugn: exit %d, stderr %q, want %q", code, errOut, want)
	}
}

func TestVersion(t *testing.T) {
	for _, args := range [][]string{{"version"}, {"--version"}} {
		if code, out, _ := child(t, t.TempDir(), args...); code != cli.ExitOK || out != "rhythm-sightread dev\n" {
			t.Errorf("%v: exit %d, output %q", args, code, out)
		}
	}
	code, out, _ := child(t, t.TempDir(), "version", "--json")
	var v struct{ Schema, Name, Version string }
	if err := json.Unmarshal([]byte(out), &v); code != cli.ExitOK || err != nil ||
		v.Schema != cli.VersionSchema || v.Name != "rhythm-sightread" || v.Version != "dev" {
		t.Errorf("version --json: exit %d, %q (%v)", code, out, err)
	}
}

// TestFirstRunOnce: the PRD 6.10 note prints on the first command of a
// machine only; a --json or -q run leaves it for later.
func TestFirstRunOnce(t *testing.T) {
	dir := t.TempDir()
	if _, _, errOut := child(t, dir, "signals", "--json"); strings.Contains(errOut, "Note: Sightread") {
		t.Errorf("--json printed the note:\n%s", errOut)
	}
	_, _, errOut := child(t, dir, "signals")
	if !strings.HasPrefix(errOut, firstRunNote) {
		t.Errorf("first run stderr:\n%s", errOut)
	}
	if _, _, errOut := child(t, dir, "signals"); strings.Contains(errOut, "Note: Sightread") {
		t.Errorf("second run printed the note again:\n%s", errOut)
	}
}

// TestUpdate: the data pack command keeps kit's contract.
func TestUpdate(t *testing.T) {
	dp := &coretest.FakeDataPacks{PackList: []cli.DataPack{{Name: "sightread-names", Version: "2026.10.24", SHA256: "ab"},
		{Name: "sightread-signals", Version: "2026.10.24", SHA256: "cd"}}}
	dp.Install(t)
	code, out, _ := execute(t, "update")
	if code != cli.ExitOK || out != "sightread-names 2026.10.24\nsightread-signals 2026.10.24\n" {
		t.Errorf("update: exit %d %q", code, out)
	}
	code, out, _ = execute(t, "update", "--json", "--pin", "sightread-names=2026.10.24")
	if code != cli.ExitOK || !strings.Contains(out, `"schema":"rhythm-data/v1"`) || !strings.Contains(out, `"pinned":true`) {
		t.Errorf("update --json --pin: exit %d %q", code, out)
	}
	code, _, errOut := execute(t, "update", "--pin", "sightread-names=2020.01.01")
	if code != cli.ExitUnavailable || !strings.Contains(errOut, "update failed: sightread-names 2020.01.01 isn't available") {
		t.Errorf("unmet pin: exit %d %q", code, errOut)
	}
	if code, _, _ := execute(t, "update", "--pin", "nonsense"); code != cli.ExitUsage {
		t.Errorf("bad --pin: exit %d", code)
	}
}

// TestPickArgs: each picker choice stands for the command PRD 6.10
// prints beside it.
func TestPickArgs(t *testing.T) {
	cases := []struct {
		choice, kind, slug string
		want               []string
	}{
		{pickAll, "", "", []string{"all"}},
		{pickOne, "plugin", " akismet ", []string{"plugin", "akismet"}},
		{pickOne, "theme", "astra", []string{"theme", "astra"}},
		{pickChanges, "", "", []string{"changes"}},
		{pickDemo, "", "", []string{"demo"}},
		{pickCI, "", "", []string{"init", "ci"}},
	}
	for _, c := range cases {
		if got := pickArgs(c.choice, c.kind, c.slug); !reflect.DeepEqual(got, c.want) {
			t.Errorf("pickArgs(%q, %q, %q) = %q, want %q", c.choice, c.kind, c.slug, got, c.want)
		}
	}
}

// TestFoundHere is the picker's "Found here:" line.
func TestFoundHere(t *testing.T) {
	inv := &coretest.FakeInventory{Site: &core.Site{Kind: "mixed", WordPress: "6.8.3"}}
	for range 23 {
		inv.Site.Installed = append(inv.Site.Installed, core.Installed{Ref: core.Ref{Eco: core.WPPlugin, Name: "p"}})
	}
	inv.Site.Installed = append(inv.Site.Installed,
		core.Installed{Ref: core.Ref{Eco: core.WPTheme, Name: "a"}}, core.Installed{Ref: core.Ref{Eco: core.WPTheme, Name: "b"}},
		core.Installed{Ref: core.Ref{Eco: core.Composer, Name: "a/b"}, Lockfile: "composer.lock"},
		core.Installed{Ref: core.Ref{Eco: core.Composer, Name: "c/d"}, Lockfile: "composer.lock"})
	inv.Install(t)
	want := "Found here: a WordPress site (23 plugins, 2 themes) and composer.lock"
	if got := lookAround(context.Background(), ".").describe(); got != want {
		t.Errorf("%q, want %q", got, want)
	}
	inv.Err = errors.New("nothing here")
	if got := lookAround(context.Background(), ".").describe(); got != "Found here: no WordPress site or lockfile" {
		t.Errorf("nothing found: %q", got)
	}
	if got := (found{lockfiles: []string{"composer.lock", "package-lock.json"}}).describe(); got != "Found here: composer.lock and package-lock.json" {
		t.Errorf("lockfiles only: %q", got)
	}
}
