// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package score applies severity overrides, the context rules, ignore,
// allow and baseline to each update, sets its verdict, counts the report
// and gates the exit code. It registers with core.SetScorer.
//
// The skeleton created this package empty; the output lane builds it.
package score
