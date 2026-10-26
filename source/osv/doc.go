// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package osv looks up OSV advisories for public npm and Packagist
// packages: one querybatch request per 1,000 references, then each
// record (cached 6 hours). MAL- records mark known malware. Private
// names are never sent. It registers with core.SetAdvisories.
package osv
