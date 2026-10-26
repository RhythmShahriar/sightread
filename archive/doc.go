// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package archive unpacks zip and tgz archives into core trees without
// writing any entry under its own name: it validates every path, records
// links and collisions, counts limits on bytes actually read and
// registers the local archive reader with core.SetLocalArchive.
//
// What is wrong with an entry is recorded in Tree.Issues, never fatal:
// a refused name, a link, a collision, an encrypted or malformed entry,
// a limit hit. Only an archive that unpacks past the uncompressed cap
// fails, with E11. Files whose Mode is not regular (links, devices,
// pipes) carry their Link text and have no blob.
package archive
