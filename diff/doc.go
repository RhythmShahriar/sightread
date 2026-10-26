// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package diff compares two trees file by file and line by line, finds
// renames, keeps line-ending changes quiet and computes drift between an
// installed copy and the official one. It registers with core.SetDiffer.
//
// The line diff is a histogram diff with a Myers fallback, written here
// so the module needs no diff dependency. Hunks are computed from the
// blob store on demand. Minified files and lines over 64 KiB are
// compared in tokens cut at punctuation, so a one-line bundle still
// gives a hunk a person can read.
package diff
