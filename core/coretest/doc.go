// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package coretest holds the fakes and helpers every Sightread package
// tests with: an in-memory blob store, tree builders, a fake of every
// stage interface with an Install helper, a sample report covering every
// signal, golden files, a loopback-only transport, fake secrets
// assembled at run time and the Need* checks for stages other lanes
// build.
//
// It is imported by tests only.
package coretest
