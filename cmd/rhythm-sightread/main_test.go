// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"
)

// childEnv makes the test binary run main instead of the tests, so a
// test sees the real exit code and output.
const childEnv = "SIGHTREAD_MAIN_CHILD"

func TestMain(m *testing.M) {
	if os.Getenv(childEnv) == "1" {
		main()
	}
	os.Exit(m.Run())
}

func run(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), childEnv+"=1", "RHYTHM_NO_UPDATE_CHECK=1", cli.OfflineEnv+"=1",
		"RHYTHM_CONFIG_DIR="+t.TempDir(), cli.InvokedAsEnv+"=rhythm-sightread")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		t.Fatal(err)
	}
	return cmd.ProcessState.ExitCode(), out.String()
}

// TestHelpListsEveryCommand: top-level help names every command of PRD
// section 6 and leaves the hidden picker out.
func TestHelpListsEveryCommand(t *testing.T) {
	code, out := run(t, "--help")
	if code != cli.ExitOK {
		t.Fatalf("--help exit %d:\n%s", code, out)
	}
	for _, c := range commands {
		listed := strings.Contains(out, "  "+c.name+" ")
		if listed == c.hidden {
			t.Errorf("%s: listed %v, hidden %v\n%s", c.name, listed, c.hidden, out)
		}
	}
}

// TestEveryCommandAnswersHelp: each command's --help and help <cmd>
// print its usage line and exit 0.
func TestEveryCommandAnswersHelp(t *testing.T) {
	for _, c := range commands {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			for _, args := range [][]string{{c.name, "--help"}, {"help", c.name}} {
				code, out := run(t, args...)
				if code != cli.ExitOK || !strings.Contains(out, "Usage: rhythm-sightread "+c.name) {
					t.Errorf("%v: exit %d, output:\n%s", args, code, out)
				}
			}
		})
	}
}

// TestNotBuiltYet: a command run for real exits 3 until its lane lands.
func TestNotBuiltYet(t *testing.T) {
	code, out := run(t, "plugin", "akismet")
	if code != cli.ExitUnavailable || !strings.Contains(out, "rhythm-sightread: plugin: not built yet") {
		t.Errorf("plugin akismet: exit %d, output %q", code, out)
	}
	if code, out := run(t, "plugn"); code != cli.ExitUsage || !strings.Contains(out, "did you mean") {
		t.Errorf("plugn: exit %d, output %q", code, out)
	}
}

func TestVersion(t *testing.T) {
	if code, out := run(t, "version"); code != cli.ExitOK || !strings.Contains(out, "rhythm-sightread dev") {
		t.Errorf("version: exit %d, output %q", code, out)
	}
}
