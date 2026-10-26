// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

func panics(f func()) (msg string) {
	defer func() {
		if r := recover(); r != nil {
			msg, _ = r.(string)
		}
	}()
	f()
	return ""
}

// A second registration is a bug two packages made; it must panic, not
// silently win by init order.
func TestRegisterTwicePanics(t *testing.T) {
	var s slot[int]
	s.name = "thing"
	s.register(1)
	if msg := panics(func() { s.register(2) }); !strings.Contains(msg, "thing registered twice") {
		t.Errorf("slot: panic %q", msg)
	}
	var tb table[string, int]
	tb.name = "writer"
	tb.register("json", 1)
	tb.register("md", 2)
	if msg := panics(func() { tb.register("json", 3) }); !strings.Contains(msg, "writer json registered twice") {
		t.Errorf("table: panic %q", msg)
	}
}

func TestSwapRestores(t *testing.T) {
	var s slot[string]
	restore := s.swap("a")
	if v, ok := s.get(); !ok || v != "a" {
		t.Fatalf("after swap: %q, %v", v, ok)
	}
	restore()
	if _, ok := s.get(); ok {
		t.Error("restore left the slot set")
	}
	var tb table[string, int]
	tb.register("k", 1)
	r := tb.swap("k", 2)
	r2 := tb.swap("new", 3)
	r2()
	r()
	if v, _ := tb.get("k"); v != 1 {
		t.Errorf("k = %d after restore, want 1", v)
	}
	if _, ok := tb.get("new"); ok {
		t.Error("restore left a new key behind")
	}
}

type namedDetector string

func (d namedDetector) Info() DetectorInfo                            { return DetectorInfo{Name: string(d)} }
func (namedDetector) Detect(context.Context, *Subject, func(Finding)) {}

func TestRegistryGetters(t *testing.T) {
	if GetAnalyzer() != nil || GetScorer() != nil || WriterFor("json") != nil || SourceFor(NPM, &Env{}) != nil {
		t.Skip("something is linked into this test binary")
	}
	if _, err := NewGetter(GetterConfig{}); !errors.Is(err, ErrNotLinked) {
		t.Errorf("NewGetter: %v, want ErrNotLinked", err)
	}
	if _, err := ReadReport(strings.NewReader("{}")); err == nil || err.Error() != "report reader not linked" {
		t.Errorf("ReadReport: %v", err)
	}
	if _, err := OpenBlobs(t.TempDir()); !errors.Is(err, ErrNotLinked) {
		t.Errorf("OpenBlobs: %v", err)
	}
	if _, err := ReadLocalArchive(context.Background(), "x.zip", nil, DefaultLimits()); !errors.Is(err, ErrNotLinked) {
		t.Errorf("ReadLocalArchive: %v", err)
	}
	t.Cleanup(SwapDetectors(namedDetector("zeta"), namedDetector("alpha")))
	var names []string
	for _, d := range Detectors() {
		names = append(names, d.Info().Name)
	}
	if !slices.Equal(names, []string{"alpha", "zeta"}) {
		t.Errorf("Detectors() = %v, want sorted", names)
	}
	if l := Linked(); !slices.Contains(l, "detectors") || slices.Contains(l, "analyzer") {
		t.Errorf("Linked() = %v", l)
	}
}
