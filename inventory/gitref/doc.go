// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package gitref reads a file at a git ref with `git show <ref>:<path>`
// through internal/proc, for `changes`. It registers with
// core.SetGitShow. Every call runs with prompts, the system config,
// optional locks, fsmonitor and hooks turned off, so reading a
// repository never starts another program. Refs are checked before
// they reach git: one that starts with "-" is refused.
package gitref
