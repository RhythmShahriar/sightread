// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build !windows

package proc

import (
	"os/exec"
	"syscall"
)

// ownGroup starts the child as the leader of a new process group, so
// stopGroup reaches whatever it starts in turn (wp over ssh, a browser
// under rhythm-soundcheck).
func ownGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// stopGroup kills what is left of the child's process group.
func stopGroup(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
