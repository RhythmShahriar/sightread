// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import "time"

// Limits bound what one package may cost to fetch, unpack and analyse.
// They are counted on bytes actually read, never on sizes an archive
// claims.
type Limits struct {
	Download      int64 // archive bytes downloaded
	Uncompressed  int64 // all entries of one package
	EntryStored   int64 // one entry kept in the blob store
	EntryAnalysed int64 // one entry the analyzer reads; bigger code is unanalysed
	JSON          int64 // one metadata response
	Entries       int
	Ratio         int           // compression ratio allowed per entry over 1 MiB
	FileBudget    time.Duration // analysis time per file
}

const (
	mib = int64(1) << 20
	gib = int64(1) << 30
)

// DefaultLimits returns the limits of PRD section 11: 256 MiB download,
// 1 GiB uncompressed, 64 MiB stored and 4 MiB analysed per entry, 32 MiB
// of JSON, 100,000 entries, a 200:1 ratio and 2 s per file.
func DefaultLimits() Limits {
	return Limits{
		Download:      256 * mib,
		Uncompressed:  gib,
		EntryStored:   64 * mib,
		EntryAnalysed: 4 * mib,
		JSON:          32 * mib,
		Entries:       100000,
		Ratio:         200,
		FileBudget:    2 * time.Second,
	}
}
