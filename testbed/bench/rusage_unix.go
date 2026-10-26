// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build testbed && unix

package main

import (
	"os"
	"os/exec" //nolint:depguard // the benchmark starts the binary it measures
	"runtime"
	"syscall"
)

// maxRSSMB is the child's peak resident set from its rusage. Linux
// reports kilobytes, macOS and the BSDs bytes.
func maxRSSMB(ps *os.ProcessState) float64 {
	ru, ok := ps.SysUsage().(*syscall.Rusage)
	if !ok || ru == nil {
		return 0
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		return float64(ru.Maxrss) / (1 << 20)
	}
	return float64(ru.Maxrss) / 1024
}

// interrupt sends Ctrl-C (SIGINT), as a terminal would.
func interrupt(cmd *exec.Cmd) { _ = cmd.Process.Signal(os.Interrupt) }
