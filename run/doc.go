// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package run is the review pipeline: it resolves what to review,
// fetches and verifies both versions, diffs and analyses them, runs the
// detectors and the scorer and builds the report, through the core
// registries only.
//
// The skeleton created this package empty; the cli lane builds it.
package run
