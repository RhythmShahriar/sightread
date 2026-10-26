// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package demo holds what `rhythm-sightread demo` reviews: three updates
// of fictional packages written out as text (a routine plugin update,
// a plugin update in the Essential Plugin pattern and an npm update that
// adds an install script and a typosquatted dependency), a server that
// publishes them on 127.0.0.1 in the layout of WordPress.org, npm and
// OSV. The small site it writes has the old versions installed. The demo
// command points the normal pipeline at the server, so a first run
// exercises the real code paths with no network. Nothing in the
// packages is ever run.
package demo
