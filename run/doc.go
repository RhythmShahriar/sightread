// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package run is the review pipeline: it resolves what to review,
// fetches and verifies both versions, diffs and analyses them, runs the
// detectors and the scorer and builds the report, through the core
// registries only.
//
// Review is the one entry point every review command calls. It merges
// .sightread/config.yaml under the flags, reads the inventory (a site
// folder, lockfiles, a fleet file or a lockfile change), keeps private
// names away from every public host, picks each candidate version,
// reviews the updates on a pool of --jobs workers and saves the report
// under the cache's runs/ folder. An archive index in the cache makes a
// second review of the same versions download nothing.
package run
