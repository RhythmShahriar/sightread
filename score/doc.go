// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package score applies severity overrides, the context rules, ignore,
// allow and baseline to each update, sets its verdict, counts the report
// and gates the exit code. It registers with core.SetScorer.
package score
