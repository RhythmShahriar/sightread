// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build testbed && !unix

package main

import (
	"os"
	"os/exec" //nolint:depguard // the benchmark starts the binary it measures
)

// maxRSSMB is not measured where rusage is not available (Windows); the
// memory target is held on the Linux runner.
func maxRSSMB(*os.ProcessState) float64 { return 0 }

// interrupt ends the process: Windows has no SIGINT to send a child, so
// e08 is judged on Linux and macOS.
func interrupt(cmd *exec.Cmd) { _ = cmd.Process.Kill() }
