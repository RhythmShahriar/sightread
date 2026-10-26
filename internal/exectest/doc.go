// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package exectest guards Sightread's first principle: it never runs
// fetched code (SR-1, SR-4, SR-15). It reads the import graph with go
// list and fails when a package starts programs outside internal/proc,
// when a package that has no reason to start one imports internal/proc,
// when the module pulls in a JavaScript or WASM engine or a git library,
// when the code paths that read package text import the network, or
// when any Go file turns TLS verification off.
package exectest
