// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build !unix

package inventory

import "os"

// openRead opens path for reading. Windows has no FIFOs in the file
// system, so a plain open can't block the way it can on unix. Copied
// from Tuner (tuner/local/fileread_other.go).
func openRead(path string) (*os.File, error) {
	return os.Open(path) //nolint:gosec // reading the user's own site and project files is the point
}
