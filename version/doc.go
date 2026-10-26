// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package version holds the version schemes of WordPress, Composer and
// npm: ordering, prereleases and constraints. It registers each with
// core.RegisterVersionScheme: WordPress for wp-plugin and wp-theme,
// Composer for composer and NPM for npm.
//
// Nothing here trusts its input: versions and constraints come from
// registries and lockfiles, so every parser bounds its input and an
// unreadable constraint is an error, never a panic.
package version

import "github.com/RhythmShahriar/sightread/core"

func init() {
	core.RegisterVersionScheme(core.WPPlugin, WordPress)
	core.RegisterVersionScheme(core.WPTheme, WordPress)
	core.RegisterVersionScheme(core.Composer, Composer)
	core.RegisterVersionScheme(core.NPM, NPM)
}
