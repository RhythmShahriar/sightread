// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package archive unpacks zip and tgz archives into core trees without
// writing any entry under its own name: it validates every path, records
// links and collisions, counts limits on bytes actually read and
// registers the local archive reader with core.SetLocalArchive.
//
// The skeleton created this package empty; the fetch lane builds it.
package archive
