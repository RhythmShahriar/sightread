// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package core holds the types every Sightread stage shares: package
// references, trees of archive files, metadata, feature sets, findings
// and the report, plus the interfaces each stage implements and the
// registries that link them.
//
// Every other package builds against core only. A stage registers its
// implementation from its package init (RegisterSource, SetDiffer,
// SetAnalyzer and the rest in registry.go) and the review pipeline finds
// it through the matching getter, so the stages never import each other.
// core itself does no I/O: it has types, constants, small pure helpers
// and the registries.
package core
