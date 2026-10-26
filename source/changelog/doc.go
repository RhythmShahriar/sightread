// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package changelog reads changelog entries from a WordPress readme.txt
// and from CHANGELOG.md, HISTORY.md or CHANGES.md, marks the generic
// ones ("Check compatibility with WordPress 6.8") and keeps those
// between two versions. Sources fill core.Meta.Changelog from it.
package changelog
