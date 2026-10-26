// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package npm is the npm registry source: versions and dist-tags from
// the abbreviated packument, scripts, publisher, dist and provenance
// from the per-version document, publish dates from the full
// packument's time map. The tarball is verified by SHA-512 and the
// registry signature against keys pinned in keys.json. Private scopes
// go only to their own registry. It registers with core.RegisterSource.
//
// It only reads: no script of a package is run and nothing is installed.
package npm
