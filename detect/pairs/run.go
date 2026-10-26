// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package pairs

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// NeedsAnalyzer reports whether the case's features come from the
// analyzer: it has files and leaves out features_old or features_new.
func (c *Case) NeedsAnalyzer() bool {
	return c.FeaturesOld == nil && len(c.Old) > 0 || c.FeaturesNew == nil && len(c.New) > 0
}

// HasOld reports whether the case has an installed side. Without one
// the update adds the package (Subject.Old is nil).
func (c *Case) HasOld() bool { return c.Old != nil || c.MetaOld != nil || c.LockOld != nil }

// Subject builds the detectors' input. It skips the test (or fails it
// under SIGHTREAD_REQUIRE_LINKED=1) when the case needs the analyzer
// and none is linked.
func (c *Case) Subject(t testing.TB) *core.Subject {
	t.Helper()
	ctx := context.Background()
	s := &core.Subject{
		OldIntegrity: c.IntegrityOld, NewIntegrity: c.IntegrityNew,
		OldLock: c.LockOld, NewLock: c.LockNew,
		Drift: c.Drift, Config: c.Config, Now: c.Now,
	}
	if s.Config == nil {
		s.Config = &core.Config{}
	}
	if s.Now.IsZero() {
		s.Now = DefaultNow
	}
	s.New = c.meta(c.MetaNew, "2.0.0")
	s.Update = s.New.Ref
	s.NewTree = coretest.TreeWith(c.New, c.Issues)
	if c.HasOld() {
		s.Old = c.meta(c.MetaOld, "1.0.0")
		s.OldTree = coretest.TreeWith(c.Old, c.IssuesOld)
	}

	differ := core.GetDiffer()
	if differ == nil {
		differ = coretest.FakeDiffer{}
	}
	old := s.OldTree
	if old == nil {
		old = coretest.Tree(nil)
	}
	d, err := differ.Diff(ctx, old, s.NewTree)
	if err != nil {
		t.Fatalf("%s: diff: %v", c, err)
	}
	s.Diff = d

	s.OldFeatures, s.NewFeatures = c.FeaturesOld, c.FeaturesNew
	if c.NeedsAnalyzer() {
		coretest.NeedAnalyzer(t)
	}
	if s.NewFeatures == nil {
		s.NewFeatures = analyse(t, c, s.NewTree)
	}
	if s.OldFeatures == nil && s.OldTree != nil {
		s.OldFeatures = analyse(t, c, s.OldTree)
	}
	return s
}

// meta returns m (or an empty Meta) with the ecosystem, a name and a
// version filled in when the case leaves them out.
func (c *Case) meta(m *core.Meta, version string) *core.Meta {
	out := &core.Meta{}
	if m != nil {
		cp := *m
		out = &cp
	}
	if out.Ref.Eco == "" {
		out.Ref.Eco = c.Eco
	}
	if out.Ref.Name == "" {
		out.Ref.Name = "fixture"
		if c.Eco == core.Composer {
			out.Ref.Name = "acme/fixture"
		}
	}
	if out.Ref.Version == "" {
		out.Ref.Version = version
	}
	return out
}

func analyse(t testing.TB, c *Case, tr *core.Tree) *core.FeatureSet {
	t.Helper()
	if len(tr.Files) == 0 {
		return core.NewFeatureSet()
	}
	a := core.GetAnalyzer()
	paths := make([]string, len(tr.Files))
	for i, f := range tr.Files {
		paths[i] = f.Path
	}
	fs, err := a.Analyze(context.Background(), tr, paths, core.DefaultLimits())
	if err != nil {
		t.Fatalf("%s: analyze: %v", c, err)
	}
	return fs
}

// Detect runs every registered detector on s and returns what they
// emit, in detector order. No context rule is applied.
func Detect(ctx context.Context, s *core.Subject) []core.Finding {
	var out []core.Finding
	for _, d := range core.Detectors() {
		d.Detect(ctx, s, func(f core.Finding) { out = append(out, f) })
	}
	return out
}

// Check compares findings with the case's expect and forbid lists and
// returns one line per problem.
func (c *Case) Check(findings []core.Finding) []string {
	var problems []string
	for _, e := range c.Expect {
		found := false
		for _, f := range findings {
			if f.ID != e.ID {
				continue
			}
			if f.Severity >= e.Min {
				found = true
			}
			if e.Max != cli.SeverityNone && f.Severity > e.Max {
				problems = append(problems, fmt.Sprintf("%s fired at %s, want at most %s (%s:%d)", e.ID, f.Severity, e.Max, f.File, f.Line))
			}
		}
		if !found {
			problems = append(problems, fmt.Sprintf("want %s at %s or worse, it did not fire", e.ID, e.Min))
		}
	}
	for _, id := range c.Forbid {
		for _, f := range findings {
			if f.ID == id {
				problems = append(problems, fmt.Sprintf("%s fired at %s, want none (%s:%d)", id, f.Severity, f.File, f.Line))
			}
		}
	}
	return problems
}

// Emitted lists the signals the registered detectors declare.
func Emitted() map[string]bool {
	out := map[string]bool{}
	for _, d := range core.Detectors() {
		for _, id := range d.Info().Signals {
			out[id] = true
		}
	}
	return out
}

// RequireLinked reports whether a missing stage fails instead of skips.
func RequireLinked() bool { return os.Getenv(coretest.RequireLinkedEnv) == "1" }

// Run runs one case as a test: it builds the subject, runs the
// detectors and reports every expect and forbid problem with the
// findings that were emitted. A case whose signal no registered
// detector emits yet is skipped (failed under SIGHTREAD_REQUIRE_LINKED=1).
func Run(t *testing.T, c *Case) {
	t.Helper()
	if !Emitted()[c.Signal] {
		if RequireLinked() {
			t.Fatalf("%s: no detector emits %s (%s=1)", c, c.Signal, coretest.RequireLinkedEnv)
		}
		t.Skipf("%s: no detector emits %s yet", c, c.Signal)
	}
	s := c.Subject(t)
	got := Detect(t.Context(), s)
	if problems := c.Check(got); len(problems) > 0 {
		t.Errorf("%s (%s):\n  %s\nfindings:\n%s", c, c.File, strings.Join(problems, "\n  "), describe(got))
	}
}

func describe(fs []core.Finding) string {
	if len(fs) == 0 {
		return "  (none)"
	}
	var b strings.Builder
	for _, f := range fs {
		fmt.Fprintf(&b, "  %s %s %s:%d %s\n", f.ID, f.Severity, f.File, f.Line, f.Evidence)
	}
	return b.String()
}

// Count is how many cases of each kind a signal has.
type Count struct{ Pos, Neg, Lookalike int }

// Counts tallies cases per signal.
func Counts(cases []*Case) map[string]Count {
	out := map[string]Count{}
	for _, c := range cases {
		n := out[c.Signal]
		switch c.Kind {
		case Pos:
			n.Pos++
		case Neg:
			n.Neg++
			if c.Lookalike {
				n.Lookalike++
			}
		}
		out[c.Signal] = n
	}
	return out
}

// MinPos and MinNeg are the fewest cases a signal may have (PRD 12).
const (
	MinPos = 3
	MinNeg = 3
)

// Shortfalls returns, sorted, what each of ids lacks: fewer than MinPos
// positive or MinNeg negative cases, or no lookalike negative.
func Shortfalls(ids []string, counts map[string]Count) []string {
	var out []string
	for _, id := range ids {
		n := counts[id]
		var miss []string
		if n.Pos < MinPos {
			miss = append(miss, fmt.Sprintf("%d of %d pos cases", n.Pos, MinPos))
		}
		if n.Neg < MinNeg {
			miss = append(miss, fmt.Sprintf("%d of %d neg cases", n.Neg, MinNeg))
		}
		if n.Lookalike == 0 {
			miss = append(miss, "no neg case with lookalike: true")
		}
		if len(miss) > 0 {
			out = append(out, id+": "+strings.Join(miss, ", "))
		}
	}
	slices.Sort(out)
	return out
}

// DetectSignals lists the catalogue IDs detectors emit (Emitter
// detect), in catalogue order.
func DetectSignals() []string {
	var out []string
	for _, s := range core.Catalog {
		if s.Emitter == core.EmitDetect {
			out = append(out, s.ID)
		}
	}
	return out
}
