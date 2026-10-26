// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package kitcheck

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
)

// childEnv makes the test binary run cli.Main with tool() instead of the
// tests, so the exit code is the process's own.
const childEnv = "KITCHECK_MAIN_CHILD"

func TestMain(m *testing.M) {
	if os.Getenv(childEnv) == "1" {
		os.Exit(cli.Main(tool()))
	}
	os.Exit(m.Run())
}

// tool has one command that ends the way its argument says.
func tool() cli.Tool {
	return cli.Tool{Name: "rhythm-kitcheck", Version: "1.0.0", Summary: "kit contract tests",
		Commands: []cli.Command{{Name: "end", Args: "<how>", Summary: "end as asked",
			Run: func(ctx context.Context, args []string, stdout, stderr io.Writer) error {
				fs := cli.NewFlagSet("end", "Usage: rhythm-kitcheck end <how>", stderr)
				pos, err := cli.ParseArgs(fs, args)
				if err != nil {
					return err
				}
				switch strings.Join(pos, " ") {
				case "ok":
					fmt.Fprintln(stdout, "done")
					return nil
				case "findings":
					return cli.ErrFindings
				case "usage":
					return cli.Usagef("end: that isn't a way to end")
				case "fail":
					return errors.New("couldn't reach the registry")
				case "unavailable":
					return &cli.ExitError{Code: cli.ExitUnavailable, Err: errors.New("end: not built yet")}
				case "wait":
					fmt.Fprintln(stdout, "ready")
					<-ctx.Done()
					return nil
				}
				return cli.Usagef("end: want a <how>")
			}}}}
}

// run starts the test binary as the tool and returns its exit code and
// output.
func run(t *testing.T, args ...string) (int, string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], args...)
	cmd.Env = append(os.Environ(), childEnv+"=1", cli.OfflineEnv+"=1", "RHYTHM_CONFIG_DIR="+t.TempDir(), cli.InvokedAsEnv+"=")
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		t.Fatal(err)
	}
	return cmd.ProcessState.ExitCode(), out.String()
}

// TestExitCodes: the codes PRD section 10 promises scripts and CI.
func TestExitCodes(t *testing.T) {
	for _, c := range []struct {
		how  string
		code int
		out  string
	}{
		{"ok", cli.ExitOK, "done"},
		{"findings", cli.ExitFindings, ""},
		{"usage", cli.ExitUsage, "that isn't a way to end"},
		{"fail", cli.ExitUnavailable, "couldn't reach the registry"},
		{"unavailable", cli.ExitUnavailable, ": end: not built yet"},
	} {
		code, out := run(t, "end", c.how)
		if code != c.code || !strings.Contains(out, c.out) {
			t.Errorf("end %s: exit %d, want %d; output %q", c.how, code, c.code, out)
		}
	}
	if code, out := run(t, "edn"); code != cli.ExitUsage || !strings.Contains(out, "did you mean") {
		t.Errorf("unknown command: exit %d, output %q", code, out)
	}
}

// TestHelpRunsHelp: `help <cmd>` runs the command with --help, which
// prints its usage and exits 0 without doing the work.
func TestHelpRunsHelp(t *testing.T) {
	for _, args := range [][]string{{"help", "end"}, {"end", "--help"}, {"end", "-h"}} {
		code, out := run(t, args...)
		if code != cli.ExitOK || !strings.Contains(out, "Usage: rhythm-kitcheck end <how>") || strings.Contains(out, "done") {
			t.Errorf("%v: exit %d, output %q", args, code, out)
		}
	}
	if code, out := run(t, "--help"); code != cli.ExitOK || !strings.Contains(out, "end") {
		t.Errorf("--help: exit %d, output %q", code, out)
	}
}

// TestInterruptExits130: Ctrl-C cancels the command's context and exits
// 130 even when the command returns nil.
func TestInterruptExits130(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows can't send an interrupt to another process")
	}
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	cmd := exec.Command(os.Args[0], "end", "wait")
	cmd.Env = append(os.Environ(), childEnv+"=1", cli.OfflineEnv+"=1", "RHYTHM_CONFIG_DIR="+t.TempDir())
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 6)
	if _, err := io.ReadFull(out, buf); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the child didn't stop on interrupt")
	}
	if code := cmd.ProcessState.ExitCode(); code != cli.ExitInterrupted {
		t.Errorf("exit %d, want 130", code)
	}
}

// TestParseFailOnText is the E13 message of PRD section 10.
func TestParseFailOnText(t *testing.T) {
	_, err := cli.ParseFailOn("severe")
	var ue cli.UsageError
	if !errors.As(err, &ue) || err.Error() != `--fail-on "severe": want none, info, low, medium, high or critical` {
		t.Errorf("ParseFailOn(severe) = %v", err)
	}
	for in, want := range map[string]cli.Severity{"": cli.SeverityNone, "HIGH": cli.SeverityHigh, "critical": cli.SeverityCritical} {
		if got, err := cli.ParseFailOn(in); err != nil || got != want {
			t.Errorf("ParseFailOn(%q) = %v, %v", in, got, err)
		}
	}
	if !cli.SeverityHigh.Fails(cli.SeverityCritical) || cli.SeverityHigh.Fails(cli.SeverityMedium) || cli.SeverityNone.Fails(cli.SeverityCritical) {
		t.Error("Fails is wrong")
	}
}
