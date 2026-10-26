// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package analyze extracts features (network calls, execution sinks,
// writes, hooks, domains, encoded blobs) from PHP and JavaScript with
// the lexers, within the per-file budget. It registers with
// core.SetAnalyzer and never touches the network.
//
// The lexers' tokens are normalised into one stream for both languages
// (norm.go). A forward-only evaluator (eval.go) reads expressions from
// it, folding built names and strings (fold.go) and following data from
// sources to sinks within each function (flow.go).
package analyze
