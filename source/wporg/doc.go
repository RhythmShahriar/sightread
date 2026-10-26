// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package wporg is the WordPress.org source for plugins and themes: the
// info API for versions and owners, the release zips, the per-file
// checksums WordPress.org publishes for plugins, the SVN tag's committer
// and, with --svn-check, a per-file comparison of a theme with
// themes.svn.wordpress.org. It registers both with core.RegisterSource.
//
// It only reads: nothing it downloads is run. Every path in a zip or an
// SVN listing goes through archive.ValidateName before it is used.
package wporg
