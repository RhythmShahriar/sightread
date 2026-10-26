// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
)

// The registries link the stages. Each stage registers from its package
// init; the pipeline and commands look implementations up through the
// getters, which return nil (or ErrNotLinked) when nothing registered.
// Register* and Set* panic on a second registration: two packages
// claiming one slot is a bug that must not depend on init order.
//
// The Swap* functions replace a registration and return a function that
// restores the previous one. They are for tests only (coretest's
// Install helpers use them), because a test can't register twice.

// ErrNotLinked is returned by a getter whose stage isn't linked into
// the binary.
var ErrNotLinked = errors.New("not linked")

// GetterConfig is what fetch needs to build the run's Getter.
type GetterConfig struct {
	Bases       map[string]string // the Base* keys
	Hosts       []string          // extra allowed hosts (mirrors, private registries)
	UserAgent   string
	Proxy       string
	Timeout     time.Duration
	Retries     int
	PerHost     int
	GitHubToken string            // sent only to api.github.com
	ScopeTokens map[string]string // "@acme" to its token, sent only to that registry
	// ComposerAuth is COMPOSER_AUTH as Composer reads it; each credential
	// goes only to its own host.
	ComposerAuth string
	Offline      bool
	CacheDir     string
	Debug        io.Writer // -v: one line per request, header values masked
}

// slot holds one registration.
type slot[T any] struct {
	name string
	mu   sync.RWMutex
	v    T
	set  bool
}

func (s *slot[T]) register(v T) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.set {
		panic("core: " + s.name + " registered twice")
	}
	s.v, s.set = v, true
}

func (s *slot[T]) get() (T, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.v, s.set
}

func (s *slot[T]) swap(v T) (restore func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, oldSet := s.v, s.set
	s.v, s.set = v, true
	return func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.v, s.set = old, oldSet
	}
}

// table holds registrations by key.
type table[K comparable, T any] struct {
	name string
	mu   sync.RWMutex
	m    map[K]T
}

func (t *table[K, T]) register(k K, v T) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, dup := t.m[k]; dup {
		panic(fmt.Sprintf("core: %s %v registered twice", t.name, k))
	}
	if t.m == nil {
		t.m = map[K]T{}
	}
	t.m[k] = v
}

func (t *table[K, T]) get(k K) (T, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	v, ok := t.m[k]
	return v, ok
}

func (t *table[K, T]) swap(k K, v T) (restore func()) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[K]T{}
	}
	old, had := t.m[k]
	t.m[k] = v
	return func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		if had {
			t.m[k] = old
		} else {
			delete(t.m, k)
		}
	}
}

var (
	sources         = table[Ecosystem, SourceFactory]{name: "source"}
	advisories      = slot[func(env *Env) Advisories]{name: "advisories"}
	tagCheckers     = slot[func(env *Env) TagChecker]{name: "tag checker"}
	getters         = slot[func(cfg GetterConfig) (Getter, error)]{name: "getter"}
	blobStores      = slot[func(dir string) (BlobStore, error)]{name: "blob store"}
	versionSchemes  = table[Ecosystem, VersionScheme]{name: "version scheme"}
	inventories     = slot[Inventory]{name: "inventory"}
	gitShows        = slot[GitShow]{name: "git show"}
	differs         = slot[Differ]{name: "differ"}
	analyzers       = slot[Analyzer]{name: "analyzer"}
	detectors       = table[string, Detector]{name: "detector"}
	explains        = table[string, Explain]{name: "explain text"}
	dataPacks       = slot[DataPacks]{name: "data packs"}
	scorers         = slot[Scorer]{name: "scorer"}
	policies        = slot[Policy]{name: "policy"}
	writers         = table[string, Writer]{name: "writer"}
	explainRenderer = slot[ExplainRenderer]{name: "explain renderer"}
	signers         = slot[Signer]{name: "signer"}
	reportReaders   = slot[ReportReader]{name: "report reader"}
	localArchives   = slot[LocalArchiveReader]{name: "local archive reader"}
)

// LocalArchiveReader reads a zip or tgz on disk into a tree, picking the
// format by its magic bytes (package archive).
type LocalArchiveReader func(ctx context.Context, path string, blobs BlobStore, lim Limits) (*Tree, error)

// RegisterSource registers the source of one ecosystem.
func RegisterSource(eco Ecosystem, f SourceFactory) { sources.register(eco, f) }

// SourceFor builds eco's source for env, or returns nil.
func SourceFor(eco Ecosystem, env *Env) Source {
	if f, ok := sources.get(eco); ok && f != nil {
		return f(env)
	}
	return nil
}

// SwapSource replaces eco's source; for tests only.
func SwapSource(eco Ecosystem, f SourceFactory) (restore func()) { return sources.swap(eco, f) }

// SetAdvisories registers the OSV lookup.
func SetAdvisories(f func(env *Env) Advisories) { advisories.register(f) }

// AdvisoriesFor builds the OSV lookup for env, or returns nil.
func AdvisoriesFor(env *Env) Advisories {
	if f, ok := advisories.get(); ok && f != nil {
		return f(env)
	}
	return nil
}

// SwapAdvisories replaces the OSV lookup; for tests only.
func SwapAdvisories(f func(env *Env) Advisories) (restore func()) { return advisories.swap(f) }

// SetTagChecker registers the git tag check.
func SetTagChecker(f func(env *Env) TagChecker) { tagCheckers.register(f) }

// TagCheckerFor builds the git tag check for env, or returns nil.
func TagCheckerFor(env *Env) TagChecker {
	if f, ok := tagCheckers.get(); ok && f != nil {
		return f(env)
	}
	return nil
}

// SwapTagChecker replaces the git tag check; for tests only.
func SwapTagChecker(f func(env *Env) TagChecker) (restore func()) { return tagCheckers.swap(f) }

// SetGetter registers the Getter constructor.
func SetGetter(f func(cfg GetterConfig) (Getter, error)) { getters.register(f) }

// NewGetter builds the run's Getter. It fails with ErrNotLinked when
// fetch isn't linked.
func NewGetter(cfg GetterConfig) (Getter, error) {
	if f, ok := getters.get(); ok && f != nil {
		return f(cfg)
	}
	return nil, fmt.Errorf("getter %w", ErrNotLinked)
}

// SwapGetter replaces the Getter constructor; for tests only.
func SwapGetter(f func(cfg GetterConfig) (Getter, error)) (restore func()) { return getters.swap(f) }

// SetBlobStore registers the blob store constructor.
func SetBlobStore(f func(dir string) (BlobStore, error)) { blobStores.register(f) }

// OpenBlobs opens the blob store under dir. It fails with ErrNotLinked
// when blob isn't linked.
func OpenBlobs(dir string) (BlobStore, error) {
	if f, ok := blobStores.get(); ok && f != nil {
		return f(dir)
	}
	return nil, fmt.Errorf("blob store %w", ErrNotLinked)
}

// SwapBlobStore replaces the blob store constructor; for tests only.
func SwapBlobStore(f func(dir string) (BlobStore, error)) (restore func()) {
	return blobStores.swap(f)
}

// RegisterVersionScheme registers eco's version scheme.
func RegisterVersionScheme(eco Ecosystem, s VersionScheme) { versionSchemes.register(eco, s) }

// Versions returns eco's version scheme, or nil.
func Versions(eco Ecosystem) VersionScheme {
	s, _ := versionSchemes.get(eco)
	return s
}

// SwapVersionScheme replaces eco's version scheme; for tests only.
func SwapVersionScheme(eco Ecosystem, s VersionScheme) (restore func()) {
	return versionSchemes.swap(eco, s)
}

// SetInventory registers the inventory.
func SetInventory(i Inventory) { inventories.register(i) }

// GetInventory returns the inventory, or nil.
func GetInventory() Inventory { v, _ := inventories.get(); return v }

// SwapInventory replaces the inventory; for tests only.
func SwapInventory(i Inventory) (restore func()) { return inventories.swap(i) }

// SetGitShow registers the git show reader.
func SetGitShow(g GitShow) { gitShows.register(g) }

// GetGitShow returns the git show reader, or nil.
func GetGitShow() GitShow { v, _ := gitShows.get(); return v }

// SwapGitShow replaces the git show reader; for tests only.
func SwapGitShow(g GitShow) (restore func()) { return gitShows.swap(g) }

// SetDiffer registers the differ.
func SetDiffer(d Differ) { differs.register(d) }

// GetDiffer returns the differ, or nil.
func GetDiffer() Differ { v, _ := differs.get(); return v }

// SwapDiffer replaces the differ; for tests only.
func SwapDiffer(d Differ) (restore func()) { return differs.swap(d) }

// SetAnalyzer registers the analyzer.
func SetAnalyzer(a Analyzer) { analyzers.register(a) }

// GetAnalyzer returns the analyzer, or nil.
func GetAnalyzer() Analyzer { v, _ := analyzers.get(); return v }

// SwapAnalyzer replaces the analyzer; for tests only.
func SwapAnalyzer(a Analyzer) (restore func()) { return analyzers.swap(a) }

// RegisterDetector registers a detector under its Info().Name.
func RegisterDetector(d Detector) { detectors.register(d.Info().Name, d) }

// Detectors returns every registered detector sorted by name, so the
// order of findings never depends on init order.
func Detectors() []Detector {
	detectors.mu.RLock()
	defer detectors.mu.RUnlock()
	names := slices.Sorted(maps.Keys(detectors.m))
	out := make([]Detector, 0, len(names))
	for _, n := range names {
		out = append(out, detectors.m[n])
	}
	return out
}

// SwapDetectors replaces every detector with ds; for tests only.
func SwapDetectors(ds ...Detector) (restore func()) {
	m := map[string]Detector{}
	for _, d := range ds {
		m[d.Info().Name] = d
	}
	detectors.mu.Lock()
	defer detectors.mu.Unlock()
	old := detectors.m
	detectors.m = m
	return func() {
		detectors.mu.Lock()
		defer detectors.mu.Unlock()
		detectors.m = old
	}
}

// RegisterExplain registers a signal's explain text.
func RegisterExplain(id string, e Explain) { explains.register(id, e) }

// ExplainFor returns a signal's explain text.
func ExplainFor(id string) (Explain, bool) { return explains.get(id) }

// SwapExplain replaces one signal's explain text; for tests only.
func SwapExplain(id string, e Explain) (restore func()) { return explains.swap(id, e) }

// SetDataPacks registers the data packs.
func SetDataPacks(d DataPacks) { dataPacks.register(d) }

// GetDataPacks returns the data packs, or nil.
func GetDataPacks() DataPacks { v, _ := dataPacks.get(); return v }

// SwapDataPacks replaces the data packs; for tests only.
func SwapDataPacks(d DataPacks) (restore func()) { return dataPacks.swap(d) }

// SetScorer registers the scorer.
func SetScorer(s Scorer) { scorers.register(s) }

// GetScorer returns the scorer, or nil.
func GetScorer() Scorer { v, _ := scorers.get(); return v }

// SwapScorer replaces the scorer; for tests only.
func SwapScorer(s Scorer) (restore func()) { return scorers.swap(s) }

// SetPolicy registers the policy.
func SetPolicy(p Policy) { policies.register(p) }

// GetPolicy returns the policy, or nil.
func GetPolicy() Policy { v, _ := policies.get(); return v }

// SwapPolicy replaces the policy; for tests only.
func SwapPolicy(p Policy) (restore func()) { return policies.swap(p) }

// RegisterWriter registers a writer under its Format().
func RegisterWriter(w Writer) { writers.register(w.Format(), w) }

// WriterFor returns the writer of format, or nil.
func WriterFor(format string) Writer { v, _ := writers.get(format); return v }

// Formats lists the registered writer formats, sorted.
func Formats() []string {
	writers.mu.RLock()
	defer writers.mu.RUnlock()
	return slices.Sorted(maps.Keys(writers.m))
}

// SwapWriter replaces the writer of w.Format(); for tests only.
func SwapWriter(w Writer) (restore func()) { return writers.swap(w.Format(), w) }

// SetExplainRenderer registers the explain renderer.
func SetExplainRenderer(e ExplainRenderer) { explainRenderer.register(e) }

// GetExplainRenderer returns the explain renderer, or nil.
func GetExplainRenderer() ExplainRenderer { v, _ := explainRenderer.get(); return v }

// SwapExplainRenderer replaces the explain renderer; for tests only.
func SwapExplainRenderer(e ExplainRenderer) (restore func()) { return explainRenderer.swap(e) }

// SetSigner registers the report signer.
func SetSigner(s Signer) { signers.register(s) }

// GetSigner returns the report signer, or nil.
func GetSigner() Signer { v, _ := signers.get(); return v }

// SwapSigner replaces the report signer; for tests only.
func SwapSigner(s Signer) (restore func()) { return signers.swap(s) }

// SetReportReader registers the report reader.
func SetReportReader(f ReportReader) { reportReaders.register(f) }

// ReadReport parses a saved kind review report. It fails with
// "report reader not linked" when report isn't linked.
func ReadReport(r io.Reader) (*Report, error) {
	if f, ok := reportReaders.get(); ok && f != nil {
		return f(r)
	}
	return nil, fmt.Errorf("report reader %w", ErrNotLinked)
}

// SwapReportReader replaces the report reader; for tests only.
func SwapReportReader(f ReportReader) (restore func()) { return reportReaders.swap(f) }

// SetLocalArchive registers the local archive reader.
func SetLocalArchive(f func(ctx context.Context, path string, blobs BlobStore, lim Limits) (*Tree, error)) {
	localArchives.register(f)
}

// ReadLocalArchive reads a zip or tgz on disk (--to-file, --from-file,
// local_files). It fails with ErrNotLinked when archive isn't linked.
func ReadLocalArchive(ctx context.Context, path string, blobs BlobStore, lim Limits) (*Tree, error) {
	if f, ok := localArchives.get(); ok && f != nil {
		return f(ctx, path, blobs, lim)
	}
	return nil, fmt.Errorf("local archive reader %w", ErrNotLinked)
}

// SwapLocalArchive replaces the local archive reader; for tests only.
func SwapLocalArchive(f func(ctx context.Context, path string, blobs BlobStore, lim Limits) (*Tree, error)) (restore func()) {
	return localArchives.swap(f)
}

// Linked lists the stages that are registered, for doctor -v and the
// integration check. Each entry is a stage name; sources and version
// schemes are listed per ecosystem.
func Linked() []string {
	var out []string
	add := func(name string, ok bool) {
		if ok {
			out = append(out, name)
		}
	}
	for _, eco := range Ecosystems() {
		_, ok := sources.get(eco)
		add("source:"+string(eco), ok)
		_, ok = versionSchemes.get(eco)
		add("version:"+string(eco), ok)
	}
	_, ok := advisories.get()
	add("advisories", ok)
	_, ok = tagCheckers.get()
	add("tag-checker", ok)
	_, ok = getters.get()
	add("getter", ok)
	_, ok = blobStores.get()
	add("blobs", ok)
	add("inventory", GetInventory() != nil)
	add("git-show", GetGitShow() != nil)
	add("differ", GetDiffer() != nil)
	add("analyzer", GetAnalyzer() != nil)
	add("detectors", len(Detectors()) > 0)
	add("data-packs", GetDataPacks() != nil)
	add("scorer", GetScorer() != nil)
	add("policy", GetPolicy() != nil)
	if f := Formats(); len(f) > 0 {
		out = append(out, "writers:"+strings.Join(f, ","))
	}
	add("explain-renderer", GetExplainRenderer() != nil)
	add("signer", GetSigner() != nil)
	_, ok = reportReaders.get()
	add("report-reader", ok)
	_, ok = localArchives.get()
	add("local-archive", ok)
	return out
}
