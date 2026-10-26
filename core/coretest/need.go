// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package coretest

import (
	"testing"

	"github.com/RhythmShahriar/sightread/core"
)

// The Need* helpers let a test use another lane's stage once it is
// linked. Before integration they skip with "<stage> not linked yet";
// with SIGHTREAD_REQUIRE_LINKED=1 they fail, so an integrated build
// can't pass by skipping.

// NeedAnalyzer needs core.GetAnalyzer.
func NeedAnalyzer(t testing.TB) {
	t.Helper()
	need(t, core.GetAnalyzer() != nil, "analyzer")
}

// NeedDiffer needs core.GetDiffer.
func NeedDiffer(t testing.TB) {
	t.Helper()
	need(t, core.GetDiffer() != nil, "differ")
}

// NeedSource needs the source of eco.
func NeedSource(t testing.TB, eco core.Ecosystem) {
	t.Helper()
	need(t, core.SourceFor(eco, &core.Env{Limits: core.DefaultLimits()}) != nil, string(eco)+" source")
}

// NeedScorer needs core.GetScorer.
func NeedScorer(t testing.TB) {
	t.Helper()
	need(t, core.GetScorer() != nil, "scorer")
}

// NeedPolicy needs core.GetPolicy.
func NeedPolicy(t testing.TB) {
	t.Helper()
	need(t, core.GetPolicy() != nil, "policy")
}

// NeedWriter needs the writer of format.
func NeedWriter(t testing.TB, format string) {
	t.Helper()
	need(t, core.WriterFor(format) != nil, format+" writer")
}

// NeedInventory needs core.GetInventory.
func NeedInventory(t testing.TB) {
	t.Helper()
	need(t, core.GetInventory() != nil, "inventory")
}

// NeedDetectors needs at least one registered detector.
func NeedDetectors(t testing.TB) {
	t.Helper()
	need(t, len(core.Detectors()) > 0, "detectors")
}
