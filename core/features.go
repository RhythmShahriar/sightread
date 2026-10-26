// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"slices"
	"strings"
)

// FeatureKind is a capability the analyzer found in code.
type FeatureKind string

// The feature kinds.
const (
	FCall         FeatureKind = "call"
	FDomain       FeatureKind = "domain"
	FURL          FeatureKind = "url"
	FHook         FeatureKind = "hook"
	FCap          FeatureKind = "cap"
	FUserCreate   FeatureKind = "user-create"
	FUserHide     FeatureKind = "user-hide"
	FCron         FeatureKind = "cron"
	FWrite        FeatureKind = "write"
	FRoute        FeatureKind = "route"
	FBlob         FeatureKind = "blob"
	FFlow         FeatureKind = "flow"
	FUACheck      FeatureKind = "ua-check"
	FEnvRead      FeatureKind = "env-read"
	FCredRead     FeatureKind = "cred-read"
	FSend         FeatureKind = "send"
	FUnicode      FeatureKind = "unicode"
	FCodeInAsset  FeatureKind = "code-in-asset"
	FUnserialize  FeatureKind = "unserialize"
	FDynCall      FeatureKind = "dyn-call"
	FEval         FeatureKind = "eval"
	FInclude      FeatureKind = "include"
	FUpdateFilter FeatureKind = "update-filter"
	FHalt         FeatureKind = "halt-compiler"
	FSecret       FeatureKind = "secret"
)

// Contexts of Feature.Context.
const (
	CtxCode     = "code"
	CtxComment  = "comment"
	CtxDoc      = "doc"
	CtxTest     = "test"
	CtxVendored = "vendored"
	CtxDecoded  = "decoded"
	// CtxAsset is a data URI: an image, font or style embedded in a
	// file, not code.
	CtxAsset = "asset"
)

// Evidence is where a feature or finding is.
type Evidence struct {
	Path    string
	Line    int
	EndLine int
	Snippet Snippet
	Func    string // enclosing function, for the same-function context rule
}

// Feature is one capability at one place.
type Feature struct {
	Kind FeatureKind
	// Key is the feature's identity across versions, e.g. "eval",
	// "example.com", "add_cap:subscriber:manage_options", "fetch->eval".
	Key     string
	Context string            // one of the Ctx* constants
	Attrs   map[string]string // e.g. "source": "request|remote|literal", "target": "wp-config.php"
	Ev      Evidence
}

// SetKey is the key a feature has in FeatureSet.ByKey.
func (f Feature) SetKey() string { return string(f.Kind) + ":" + f.Key }

// Unanalysed is a code file the analyzer could not read, with why.
type Unanalysed struct{ Path, Reason string }

// FeatureSet is every feature of one tree.
type FeatureSet struct {
	ByKey      map[string][]Feature // key = string(Kind)+":"+Key
	Unanalysed []Unanalysed
	Minified   []string // paths recognised as minified or bundled
}

// NewFeatureSet returns an empty set.
func NewFeatureSet() *FeatureSet { return &FeatureSet{ByKey: map[string][]Feature{}} }

// Add records f.
func (s *FeatureSet) Add(f Feature) {
	if s.ByKey == nil {
		s.ByKey = map[string][]Feature{}
	}
	k := f.SetKey()
	s.ByKey[k] = append(s.ByKey[k], f)
}

// Has reports whether the set holds a feature of kind with key.
func (s *FeatureSet) Has(kind FeatureKind, key string) bool {
	if s == nil {
		return false
	}
	return len(s.ByKey[string(kind)+":"+key]) > 0
}

// NewIn returns the features of s whose kind and key are absent from
// old, sorted by path, then line, then key. A nil old makes every
// feature new (an added package). Signals compare capabilities, not
// lines, so a feature that moved stays quiet.
func (s *FeatureSet) NewIn(old *FeatureSet) []Feature {
	if s == nil {
		return nil
	}
	var out []Feature
	for k, fs := range s.ByKey {
		if old != nil && len(old.ByKey[k]) > 0 {
			continue
		}
		out = append(out, fs...)
	}
	slices.SortStableFunc(out, func(a, b Feature) int {
		if c := strings.Compare(a.Ev.Path, b.Ev.Path); c != 0 {
			return c
		}
		if a.Ev.Line != b.Ev.Line {
			return a.Ev.Line - b.Ev.Line
		}
		return strings.Compare(a.SetKey(), b.SetKey())
	})
	return out
}

// Analyzer extracts features from code (package analyze). It never runs
// the code and never reaches the network.
type Analyzer interface {
	Analyze(ctx context.Context, t *Tree, paths []string, lim Limits) (*FeatureSet, error)
	// AnalyzeText analyses text that is not a file of a tree, such as an
	// npm script.
	AnalyzeText(ctx context.Context, kind FileKind, path string, src []byte) (*FeatureSet, error)
}
