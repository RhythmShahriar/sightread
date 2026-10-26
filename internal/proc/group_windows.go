// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build windows

package proc

import "os/exec"

// ownGroup does nothing on Windows: stopGroup walks the tree instead.
func ownGroup(*exec.Cmd) {}

// stopGroup kills whatever the child started, which Windows leaves
// running when the child itself ends.
func stopGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = KillTree(cmd.Process)
	}
}
