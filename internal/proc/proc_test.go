// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Derived from soundcheck/internal/proc/proc_test.go

package proc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestMain makes the test binary stand in for the children: one that
// waits for an interrupt and says it got one, one that echoes, one that
// floods its output and one that sleeps.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		child(os.Args[1], os.Args[2:])
	}
	os.Exit(m.Run())
}

func child(mode string, args []string) {
	switch mode {
	case "proc-echo":
		in, _ := io.ReadAll(os.Stdin)
		wd, _ := os.Getwd()
		fmt.Fprintf(os.Stdout, "args=%s dir=%s env=%s", strings.Join(args, "|"), filepath.Base(wd), os.Getenv("PROC_TEST"))
		fmt.Fprintf(os.Stderr, "stdin=%s", in)
		code, _ := strconv.Atoi(os.Getenv("PROC_EXIT"))
		os.Exit(code)
	case "proc-flood":
		line := []byte(strings.Repeat("x", 1023) + "\n")
		for {
			if _, err := os.Stdout.Write(line); err != nil {
				os.Exit(0)
			}
		}
	case "proc-sleep":
		time.Sleep(30 * time.Second)
		os.Exit(0)
	}
	if mode == "proc-child" {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, os.Interrupt)
		os.Stdout.WriteString("ready\n")
		select {
		case <-ch:
			os.Exit(3)
		case <-time.After(30 * time.Second):
			os.Exit(0)
		}
	}
}

// A canceled child stops at once: interrupted on Unix, killed on Windows.
func TestInterruptStopsTheChild(t *testing.T) {
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	ctx, cancel := context.WithCancel(context.Background())
	cmd := exec.CommandContext(ctx, os.Args[0], "proc-child")
	Interrupt(cmd)
	cmd.WaitDelay = 20 * time.Second
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 6)
	if _, err := out.Read(buf); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	cancel()
	_ = cmd.Wait()
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("took %s to stop", d)
	}
	if runtime.GOOS != "windows" && cmd.ProcessState.ExitCode() != 3 {
		t.Errorf("exit %d, want 3 (the child saw the interrupt)", cmd.ProcessState.ExitCode())
	}
}

// KillTree stops a child that would otherwise run for 30 s.
func TestKillTree(t *testing.T) {
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	KillOnExit()
	KillOnExit() // a second call is harmless
	cmd := exec.Command(os.Args[0], "proc-child")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 6)
	if _, err := out.Read(buf); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := KillTree(cmd.Process); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("took %s to stop", d)
	}
	if cmd.ProcessState.ExitCode() == 0 || cmd.ProcessState.ExitCode() == 3 {
		t.Errorf("exit %d: the child wasn't killed", cmd.ProcessState.ExitCode())
	}
}

// Run passes argv, folder, environment and stdin exactly, never through
// a shell. A non-zero exit is a code, not an error.
func TestRun(t *testing.T) {
	dir := t.TempDir()
	var log bytes.Buffer
	res, err := Run(context.Background(), Spec{
		Argv:    []string{os.Args[0], "proc-echo", "a b", "$(touch pwned)", ";", "*"},
		Dir:     dir,
		Env:     append(os.Environ(), "PROC_TEST=yes", "PROC_EXIT=4"),
		Stdin:   strings.NewReader("hello"),
		Purpose: PurposeGit,
		Log:     &log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := "args=a b|$(touch pwned)|;|* dir=" + filepath.Base(dir) + " env=yes"; string(res.Stdout) != want {
		t.Errorf("stdout %q, want %q", res.Stdout, want)
	}
	if string(res.Stderr) != "stdin=hello" || res.Code != 4 {
		t.Errorf("stderr %q, code %d", res.Stderr, res.Code)
	}
	if _, err := os.Stat(filepath.Join(dir, "pwned")); err == nil {
		t.Error("an argument ran as a shell command")
	}
	if !strings.HasPrefix(log.String(), "run git: ") {
		t.Errorf("log %q", log.String())
	}
}

func TestRunMasksSecretsInLog(t *testing.T) {
	var log bytes.Buffer
	pass := "Zq9" + "AbCdEf123GhIjK"
	_, err := Run(context.Background(), Spec{Argv: []string{os.Args[0], "proc-echo", "https://deploy:" + pass + "@staging.test"},
		Purpose: PurposeWPCLI, Log: &log})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(log.String(), pass) {
		t.Errorf("log shows the password: %q", log.String())
	}
}

func TestRunOutputCap(t *testing.T) {
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	start := time.Now()
	res, err := Run(context.Background(), Spec{Argv: []string{os.Args[0], "proc-flood"}, Purpose: PurposeSoundcheck, MaxOutput: 64 << 10})
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("err %v, want ErrOutputTooLarge", err)
	}
	if len(res.Stdout) != 64<<10 {
		t.Errorf("kept %d bytes, want exactly the cap", len(res.Stdout))
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Errorf("took %s to stop a flood", d)
	}
}

func TestRunTimeout(t *testing.T) {
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	start := time.Now()
	_, err := Run(context.Background(), Spec{Argv: []string{os.Args[0], "proc-sleep"}, Purpose: PurposeRoadie, Timeout: 200 * time.Millisecond})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v, want a deadline", err)
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Errorf("took %s", d)
	}
}

func TestRunRefuses(t *testing.T) {
	for _, s := range []Spec{
		{Purpose: PurposeGit},
		{Argv: []string{""}, Purpose: PurposeGit},
		{Argv: []string{os.Args[0]}, Purpose: "php"},
		{Argv: []string{os.Args[0]}},
	} {
		if _, err := Run(context.Background(), s); err == nil {
			t.Errorf("Run(%+v) succeeded", s)
		}
	}
	if _, err := Run(context.Background(), Spec{Argv: []string{"sightread-no-such-program"}, Purpose: PurposeGit}); err == nil {
		t.Error("a missing program started")
	}
}

func TestLookPath(t *testing.T) {
	if _, err := LookPath("sightread-no-such-program"); err == nil {
		t.Error("found a missing program")
	}
	if _, err := LookPath(os.Args[0]); err != nil {
		t.Errorf("LookPath of the test binary: %v", err)
	}
}
