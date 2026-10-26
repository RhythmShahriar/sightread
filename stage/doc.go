// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package stage is the --soundcheck flow: it refuses production, checks
// the staging copy with rhythm-roadie, takes a Soundcheck snapshot,
// installs the verified archive on staging and compares.
//
// The skeleton created this package empty; the cli lane builds it.
package stage
