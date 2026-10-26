// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package code holds the detectors for signals found in code: remote
// fetch and exec, decode and exec, eval, obfuscation, writes, users,
// capabilities, domains and the rest.
//
// The detectors read only the update's features (core.FeatureSet, from
// the analyzer) and its trees. They never resolve or contact a host and
// never run package code. A feature fires only when it is new in the
// candidate and sits in code, a decoded payload or vendored code;
// comments, docs and tests never fire (the scorer demotes vendored
// paths).
package code
