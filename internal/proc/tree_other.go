// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Derived from soundcheck/internal/proc/tree_other.go

//go:build !windows

package proc

import "os"

// KillOnExit does nothing outside Windows, where Run starts each child
// in a process group of its own and stops the whole group.
func KillOnExit() {}

// KillTree kills p. Run's children on Unix lead their own process group,
// which Run kills as a whole when it stops one.
func KillTree(p *os.Process) error { return p.Kill() }
