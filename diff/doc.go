// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package diff compares two trees file by file and line by line, finds
// renames, keeps reformatting and line endings quiet and computes drift
// between an installed copy and the official one. It registers with
// core.SetDiffer.
//
// The skeleton created this package empty; the inventory lane builds it.
package diff
