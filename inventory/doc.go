// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package inventory finds what a folder has installed: WordPress plugins
// and themes, composer.lock and npm lockfiles. It reads lockfile changes
// for `changes` and installed folders as trees. It registers with
// core.SetInventory.
//
// The skeleton created this package empty; the inventory lane builds it.
package inventory
