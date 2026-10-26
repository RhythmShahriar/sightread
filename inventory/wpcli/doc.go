// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package wpcli reads installed plugins and themes from the user's own
// wp command, run through internal/proc. It runs only a fixed table of
// read-only listings (plugin list, theme list, core version and the
// auto_update_plugins option) and never runs WP-CLI against fetched
// code.
package wpcli
