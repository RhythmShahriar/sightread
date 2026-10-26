// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package analyze extracts features (network calls, execution sinks,
// writes, hooks, domains, encoded blobs) from PHP and JavaScript with
// the lexers, within the per-file budget. It registers with
// core.SetAnalyzer and never touches the network.
//
// The skeleton created this package empty; the analyze lane builds it.
package analyze
