// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build testbed

package main

import (
	"os"
	"os/exec" //nolint:depguard // runs the wrapper the benchmark writes
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestSoundcheckJail: the wrapper starts the real binary with its
// arguments, a HOME and XDG folders in the work folder and every proxy
// variable on its own guard, whatever the caller's environment says.
func TestSoundcheckJail(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the wrapper is a POSIX shell script")
	}
	dir := t.TempDir()
	real := filepath.Join(dir, "it's real")
	if err := os.WriteFile(real, []byte("#!/bin/sh\necho \"args=$*\"\nenv\n"), 0o750); err != nil { //nolint:gosec // a test script
		t.Fatal(err)
	}
	h := &harness{work: filepath.Join(dir, "work")}
	sc, err := h.jailSoundcheck(real)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = sc.guard.Close() }()
	cmd := exec.Command(filepath.Join(sc.bin, "rhythm-soundcheck"), "compare", "a b") //nolint:gosec // the wrapper under test
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/somewhere/else", "HTTPS_PROXY=http://127.0.0.1:1"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	home := filepath.Join(h.work, "soundcheck", "home")
	guard := "http://127.0.0.1:" + strconv.Itoa(sc.guard.Port())
	for _, want := range []string{"args=compare a b", "HOME=" + home, "XDG_CACHE_HOME=" + home + "/.cache",
		"XDG_CONFIG_HOME=" + home + "/.config", "HTTPS_PROXY=" + guard, "http_proxy=" + guard, "ALL_PROXY=" + guard} {
		if !strings.Contains(string(out), want+"\n") {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	if sc.guard.Port() == 0 || strings.Contains(string(out), "/somewhere/else") {
		t.Errorf("guard port %d, output:\n%s", sc.guard.Port(), out)
	}
}
