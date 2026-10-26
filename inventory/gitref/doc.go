// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package gitref reads a file at a git ref with `git show <ref>:<path>`
// through internal/proc, for `changes`. It registers with
// core.SetGitShow.
//
// The skeleton created this package empty; the inventory lane builds it.
package gitref
