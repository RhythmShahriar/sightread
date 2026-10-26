// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

// VerifiedBy says how one side of an update was checked against what its
// source publishes (PRD 5.4).
type VerifiedBy string

// The ways a side can be verified.
const (
	ByChecksums VerifiedBy = "checksums" // every file matches WordPress.org per-file SHA-256
	BySVN       VerifiedBy = "svn"       // every theme file matches themes.svn.wordpress.org
	BySignature VerifiedBy = "signature" // npm SHA-512 and the registry signature
	ByIntegrity VerifiedBy = "integrity" // npm SHA-512, no registry signature
	ByShasum    VerifiedBy = "shasum"    // Composer archive SHA-1 equals Packagist's
	ByCommit    VerifiedBy = "commit"    // Composer archive pinned to dist.reference
	ByTLS       VerifiedBy = "tls"       // theme over TLS from downloads.wordpress.org
	ByNone      VerifiedBy = "none"      // local file, or checksums unavailable
	ByFailed    VerifiedBy = "failed"    // a published hash does not match
)

// Integrity is the result of verifying one side.
type Integrity struct {
	By       VerifiedBy
	Method   string   // human text, PRD 18 item 4 wording
	Mismatch []string // files or fields that differ (integrity-mismatch evidence)
	Detail   string
}

// Partial reports whether the side was not verified at all, which makes
// the update UNVERIFIED unless --allow-unverified.
func (i Integrity) Partial() bool { return i.By == ByNone }
