// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package benchdoc holds the benchmark's results (results.json), checks
// them against the 1.0 targets, renders docs/benchmark.md and compares
// two runs for make reproduce. It starts no process and needs no
// testbed, so all of it is tested on recorded results; testbed/bench
// fills a Results by running the real binary and testbed/corpus adds the
// owner-run real-release section.
package benchdoc
