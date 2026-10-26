// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package packagist is the Composer source: Packagist's p2 metadata
// (expanded from the minified composer/2.0 form), maintainers and the
// abandoned flag from packagist.org, private Composer repositories from
// config and the dist archive, verified by its shasum or pinned to the
// commit dist.reference names. It registers with core.RegisterSource.
//
// It only reads: the composer.json of a package is parsed for its type,
// scripts and autoload files; nothing in the archive is run.
package packagist
