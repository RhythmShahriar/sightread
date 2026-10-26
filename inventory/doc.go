// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package inventory finds what a folder has installed: WordPress plugins
// and themes (from disk, the user's wp command or a Tuner report),
// composer.lock and npm lockfiles. It reads lockfile changes for
// `changes` and installed folders as trees. Reader registers with
// core.SetInventory.
//
// It only reads files: nothing it finds is run. wp-config.php, .env
// and other secrets files are never opened.
package inventory
