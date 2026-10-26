// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package pairs is the fixture pair harness every signal is tested with
// (PRD 12, qa.md 4). A case is one update, written as a case.yaml under
// testdata/pairs/<signal-id>/<pos|neg>-<n>/: the old and new trees, the
// metadata, lock entries and integrity of both sides plus the signals
// the detectors must and must not emit for it.
//
// The harness runs the registered detectors only. The scorer's context
// rules (owner change raises, vendored paths demote) are not applied,
// so a case states what a detector emits on its own.
//
// It is imported by tests only.
package pairs

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"gopkg.in/yaml.v3"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// Kinds of case, from the folder name's prefix.
const (
	Pos = "pos" // the signal must fire
	Neg = "neg" // the signal must not fire
)

// DefaultNow is the clock of a case that sets no now.
var DefaultNow = time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

// Expect is one signal a case needs: at least one finding at Min or
// worse and, when Max is set, none worse than Max. A neg case uses Max
// to say its signal stays low, e.g. a documentation link that must be
// info and never medium.
type Expect struct {
	ID       string
	Min, Max cli.Severity
}

// Case is one fixture pair, loaded and checked.
type Case struct {
	File   string // the case.yaml
	Signal string // the signal folder it sits in
	Kind   string // Pos or Neg
	Name   string // the case folder, e.g. "neg-2"

	Eco                        core.Ecosystem
	Old, New                   map[string]string // nil: that side has no files
	MetaOld, MetaNew           *core.Meta
	LockOld, LockNew           *core.Installed
	IntegrityOld, IntegrityNew core.Integrity
	IssuesOld, Issues          []core.ArchiveIssue // archive issues of each side
	Drift                      *core.Drift
	Config                     *core.Config
	Now                        time.Time
	// Lookalike marks a negative case built to look like the bad one.
	Lookalike bool
	// FeaturesOld and FeaturesNew, when set, replace the analyzer, so
	// detector logic is tested before (and apart from) the analyzer.
	FeaturesOld, FeaturesNew *core.FeatureSet
	Expect                   []Expect
	Forbid                   []string
}

// String names the case as its folder does: "<signal>/<name>".
func (c *Case) String() string { return c.Signal + "/" + c.Name }

// rawCase is case.yaml. Each key is decoded on its own, so an error
// names the key it is in.
type rawCase struct {
	Eco          string              `yaml:"eco"`
	Old          map[string]string   `yaml:"old"`
	OldDir       string              `yaml:"old_dir"`
	New          map[string]string   `yaml:"new"`
	NewDir       string              `yaml:"new_dir"`
	MetaOld      *core.Meta          `yaml:"meta_old"`
	MetaNew      *core.Meta          `yaml:"meta_new"`
	LockOld      *core.Installed     `yaml:"lock_old"`
	LockNew      *core.Installed     `yaml:"lock_new"`
	IntegrityOld core.Integrity      `yaml:"integrity_old"`
	IntegrityNew core.Integrity      `yaml:"integrity_new"`
	IssuesOld    []core.ArchiveIssue `yaml:"issues_old"`
	Issues       []core.ArchiveIssue `yaml:"issues"`
	Drift        *core.Drift         `yaml:"drift"`
	Config       *core.Config        `yaml:"config"`
	Now          time.Time           `yaml:"now"`
	Lookalike    bool                `yaml:"lookalike"`
	FeaturesOld  *rawFeatures        `yaml:"features_old"`
	FeaturesNew  *rawFeatures        `yaml:"features_new"`
	Expect       []rawExpect         `yaml:"expect"`
	Forbid       []string            `yaml:"forbid"`
	Note         string              `yaml:"note"` // what the case shows; read by people only
}

type rawExpect struct {
	ID          string `yaml:"id"`
	MinSeverity string `yaml:"min_severity"`
	MaxSeverity string `yaml:"max_severity"`
}

// rawFeatures is a feature set: a list of features, or a mapping with
// found, minified and unanalysed.
type rawFeatures struct {
	Found      []rawFeature      `yaml:"found"`
	Minified   []string          `yaml:"minified"`
	Unanalysed []core.Unanalysed `yaml:"unanalysed"`
}

type rawFeature struct {
	Kind    string            `yaml:"kind"`
	Key     string            `yaml:"key"`
	Context string            `yaml:"context"`
	Attrs   map[string]string `yaml:"attrs"`
	Path    string            `yaml:"path"`
	Line    int               `yaml:"line"`
	EndLine int               `yaml:"end_line"`
	Snippet string            `yaml:"snippet"`
	Func    string            `yaml:"func"`
}

var knownKinds = map[core.FeatureKind]bool{
	core.FCall: true, core.FDomain: true, core.FURL: true, core.FHook: true, core.FCap: true,
	core.FUserCreate: true, core.FUserHide: true, core.FCron: true, core.FWrite: true, core.FRoute: true,
	core.FBlob: true, core.FFlow: true, core.FUACheck: true, core.FEnvRead: true, core.FCredRead: true,
	core.FSend: true, core.FUnicode: true, core.FCodeInAsset: true, core.FUnserialize: true,
	core.FDynCall: true, core.FEval: true, core.FInclude: true, core.FUpdateFilter: true,
	core.FHalt: true, core.FSecret: true,
}

var knownContexts = []string{core.CtxCode, core.CtxComment, core.CtxDoc, core.CtxTest, core.CtxVendored, core.CtxDecoded}

func (r *rawFeatures) set() (*core.FeatureSet, error) {
	s := core.NewFeatureSet()
	s.Minified = r.Minified
	s.Unanalysed = r.Unanalysed
	for i, f := range r.Found {
		kind := core.FeatureKind(f.Kind)
		if !knownKinds[kind] {
			return nil, fmt.Errorf("feature %d: unknown kind %q", i+1, f.Kind)
		}
		if f.Path == "" {
			return nil, fmt.Errorf("feature %d: needs a path", i+1)
		}
		if f.Context == "" {
			f.Context = core.CtxCode
		}
		if !slices.Contains(knownContexts, f.Context) {
			return nil, fmt.Errorf("feature %d: unknown context %q", i+1, f.Context)
		}
		if f.EndLine == 0 {
			f.EndLine = f.Line
		}
		if f.Snippet == "" {
			f.Snippet = f.Kind + " " + f.Key
		}
		s.Add(core.Feature{Kind: kind, Key: f.Key, Context: f.Context, Attrs: f.Attrs, Ev: core.Evidence{
			Path: f.Path, Line: f.Line, EndLine: f.EndLine, Snippet: core.NewSnippet(f.Snippet), Func: f.Func,
		}})
	}
	return s, nil
}

// placeholder is a fake secret in a case: {{fakekey:<kind>}} becomes
// coretest.FakeKey(kind) at load, so no case file holds a literal key.
var placeholder = regexp.MustCompile(`\{\{fakekey:([^}]*)\}\}`)

// Expand replaces every {{fakekey:<kind>}} in b. An unknown kind is an
// error that names its line.
func Expand(b []byte) ([]byte, error) {
	var err error
	out := placeholder.ReplaceAllFunc(b, func(m []byte) []byte {
		kind := string(placeholder.FindSubmatch(m)[1])
		if !slices.Contains(coretest.FakeKeyKinds(), kind) {
			if err == nil {
				line := bytes.Count(b[:bytes.Index(b, m)], []byte("\n")) + 1
				err = fmt.Errorf("line %d: unknown fake key kind %q (want one of %s)",
					line, kind, strings.Join(coretest.FakeKeyKinds(), ", "))
			}
			return m
		}
		return []byte(coretest.FakeKey(kind))
	})
	return out, err
}

// caseDir matches a case folder name.
var caseDir = regexp.MustCompile(`^(pos|neg)-[1-9][0-9]*$`)

// Load reads every case under root (root/<signal-id>/<pos|neg>-<n>/
// case.yaml). Any bad case fails the whole load: a case that can't be
// read must not quietly drop out of the count.
func Load(root string) ([]*Case, error) {
	sigs, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	var out []*Case
	for _, sd := range sigs {
		if sd.Name() == "README.md" {
			continue
		}
		if !sd.IsDir() {
			return nil, fmt.Errorf("%s: only signal folders belong here", filepath.Join(root, sd.Name()))
		}
		if _, ok := core.Signal(sd.Name()); !ok {
			return nil, fmt.Errorf("%s: unknown signal ID %q", filepath.Join(root, sd.Name()), sd.Name())
		}
		cases, err := os.ReadDir(filepath.Join(root, sd.Name()))
		if err != nil {
			return nil, err
		}
		for _, cd := range cases {
			dir := filepath.Join(root, sd.Name(), cd.Name())
			if !cd.IsDir() || !caseDir.MatchString(cd.Name()) {
				return nil, fmt.Errorf("%s: want a folder named pos-<n> or neg-<n>", dir)
			}
			c, err := LoadCase(filepath.Join(dir, "case.yaml"))
			if err != nil {
				return nil, err
			}
			out = append(out, c)
		}
	}
	return out, nil
}

// LoadCase reads one case.yaml. Its folder names the signal and the
// kind of case. Errors name the file and the key.
func LoadCase(file string) (*Case, error) {
	dir := filepath.Dir(file)
	c := &Case{File: file, Name: filepath.Base(dir), Signal: filepath.Base(filepath.Dir(dir))}
	c.Kind, _, _ = strings.Cut(c.Name, "-")
	if !caseDir.MatchString(c.Name) {
		return nil, fmt.Errorf("%s: the case folder must be named pos-<n> or neg-<n>", file)
	}
	b, err := os.ReadFile(file) // #nosec G304 -- test fixtures under testdata
	if err != nil {
		return nil, err
	}
	if b, err = Expand(b); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	var raw rawCase
	if err := decodeCase(b, &raw); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	if err := c.fill(&raw, dir); err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	return c, nil
}

func (c *Case) fill(raw *rawCase, dir string) error {
	if raw.Eco == "" {
		return errors.New("eco: missing; name the ecosystem (wp-plugin, wp-theme, composer or npm)")
	}
	eco, err := core.ParseEcosystem(raw.Eco)
	if err != nil {
		return fmt.Errorf("eco: %w", err)
	}
	c.Eco = eco
	if c.Old, err = files(raw.Old, raw.OldDir, dir, "old"); err != nil {
		return err
	}
	if c.New, err = files(raw.New, raw.NewDir, dir, "new"); err != nil {
		return err
	}
	c.MetaOld, c.MetaNew = raw.MetaOld, raw.MetaNew
	c.LockOld, c.LockNew = raw.LockOld, raw.LockNew
	c.IntegrityOld, c.IntegrityNew = raw.IntegrityOld, raw.IntegrityNew
	c.IssuesOld, c.Issues = raw.IssuesOld, raw.Issues
	c.Drift, c.Config, c.Now, c.Lookalike = raw.Drift, raw.Config, raw.Now, raw.Lookalike
	if c.Lookalike && c.Kind != Neg {
		return errors.New("lookalike: only a neg case can be a lookalike")
	}
	if raw.FeaturesOld != nil {
		if c.FeaturesOld, err = raw.FeaturesOld.set(); err != nil {
			return fmt.Errorf("features_old: %w", err)
		}
	}
	if raw.FeaturesNew != nil {
		if c.FeaturesNew, err = raw.FeaturesNew.set(); err != nil {
			return fmt.Errorf("features_new: %w", err)
		}
	}
	for i, e := range raw.Expect {
		if _, ok := core.Signal(e.ID); !ok {
			return fmt.Errorf("expect: entry %d: unknown signal ID %q", i+1, e.ID)
		}
		x := Expect{ID: e.ID, Min: cli.SeverityInfo}
		if x.Min, err = severity(e.MinSeverity, cli.SeverityInfo); err != nil {
			return fmt.Errorf("expect: entry %d: min_severity %w", i+1, err)
		}
		if x.Max, err = severity(e.MaxSeverity, cli.SeverityNone); err != nil {
			return fmt.Errorf("expect: entry %d: max_severity %w", i+1, err)
		}
		if x.Max != cli.SeverityNone && x.Max < x.Min {
			return fmt.Errorf("expect: entry %d: max_severity is below min_severity", i+1)
		}
		c.Expect = append(c.Expect, x)
	}
	for i, id := range raw.Forbid {
		if _, ok := core.Signal(id); !ok {
			return fmt.Errorf("forbid: entry %d: unknown signal ID %q", i+1, id)
		}
	}
	c.Forbid = raw.Forbid
	switch {
	case c.Kind == Pos && !slices.ContainsFunc(c.Expect, func(e Expect) bool { return e.ID == c.Signal }):
		return fmt.Errorf("expect: a pos case of %s must expect %s", c.Signal, c.Signal)
	case c.Kind == Neg && !slices.Contains(c.Forbid, c.Signal) && !c.capsSignal():
		return fmt.Errorf("forbid: a neg case of %s must forbid it, or expect it with a max_severity below its default", c.Signal)
	}
	for _, e := range c.Expect {
		if slices.Contains(c.Forbid, e.ID) {
			return fmt.Errorf("forbid: %s is also expected", e.ID)
		}
	}
	return nil
}

// capsSignal reports whether a neg case expects its own signal with a
// max_severity below the signal's default: the guard lowers it instead
// of silencing it.
func (c *Case) capsSignal() bool {
	info, _ := core.Signal(c.Signal)
	for _, e := range c.Expect {
		if e.ID == c.Signal && e.Max != cli.SeverityNone && e.Max < info.Severity {
			return true
		}
	}
	return false
}

// severity parses a min_severity or max_severity value; "" is def.
func severity(s string, def cli.Severity) (cli.Severity, error) {
	if s == "" {
		return def, nil
	}
	v, err := cli.ParseFailOn(s)
	if err != nil || v == cli.SeverityNone {
		return 0, fmt.Errorf("%q: want info, low, medium, high or critical", s)
	}
	return v, nil
}

// files returns a side's files: inline, or read from a folder next to
// the case. Neither means the side has none (nil).
func files(inline map[string]string, sub, caseDir, key string) (map[string]string, error) {
	if inline != nil && sub != "" {
		return nil, fmt.Errorf("%s: give %s or %s_dir, not both", key, key, key)
	}
	if sub == "" {
		return inline, nil
	}
	root := filepath.Join(caseDir, filepath.FromSlash(sub))
	if rel, err := filepath.Rel(caseDir, root); err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, fmt.Errorf("%s_dir: %q leaves the case folder", key, sub)
	}
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, fmt.Errorf("%s_dir: %w", key, err)
	}
	defer func() { _ = r.Close() }()
	out := map[string]string{}
	err = fs.WalkDir(r.FS(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if !d.Type().IsRegular() {
			return fmt.Errorf("%s: not a regular file", p)
		}
		b, err := r.ReadFile(p)
		if err != nil {
			return err
		}
		if b, err = Expand(b); err != nil {
			return fmt.Errorf("%s: %w", p, err)
		}
		out[p] = string(b)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%s_dir: %w", key, err)
	}
	return out, nil
}

// decodeCase decodes case.yaml into raw strictly: an unknown key, at
// any depth, is an error naming the top-level key and the line.
func decodeCase(b []byte, raw *rawCase) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return err
	}
	if len(doc.Content) == 0 {
		return errors.New("empty case")
	}
	top := doc.Content[0]
	if top.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: a case is a mapping of keys", top.Line)
	}
	fields := yamlFields(raw)
	seen := map[string]bool{}
	for i := 0; i+1 < len(top.Content); i += 2 {
		k, v := top.Content[i], top.Content[i+1]
		dst, ok := fields[k.Value]
		if !ok {
			return fmt.Errorf("line %d: unknown key %q", k.Line, k.Value)
		}
		if seen[k.Value] {
			return fmt.Errorf("line %d: %s given twice", k.Line, k.Value)
		}
		seen[k.Value] = true
		if err := decodeStrict(v, dst); err != nil {
			if !strings.Contains(err.Error(), "line ") {
				// time.Time and some type errors carry no line.
				return fmt.Errorf("%s: line %d: %w", k.Value, v.Line, err)
			}
			return fmt.Errorf("%s: %w", k.Value, err)
		}
	}
	return nil
}

// UnmarshalYAML accepts a plain list of features as well as the mapping.
func (r *rawFeatures) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.SequenceNode {
		return decodeStrict(n, &r.Found)
	}
	type plain rawFeatures
	return decodeStrict(n, (*plain)(r))
}
