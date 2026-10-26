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
// sources to sinks within each function (flow.go). Feature extraction
// (extract.go, php.go, js.go, npm.go) rides on that walk as its
// observer. Hosts are read from literals, comments, JSON and docs
// without resolving any (hosts.go, hostcat.go). Encoded literals are
// decoded within fixed limits and their payloads analysed again
// (blob.go). Minified bundles, Unicode tricks in code and code hidden in
// images, fonts and text files are told apart in kinds.go. The Analyzer
// (analyzer.go) runs all of it over a tree on a worker pool within the
// size, time and memory limits; what it could not read is listed as
// Unanalysed.
package analyze
