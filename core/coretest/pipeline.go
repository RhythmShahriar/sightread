// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package coretest

import (
	"bytes"
	"context"
	"crypto/sha1" //nolint:gosec // Packagist publishes SHA-1; the fake computes what fetch does
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

// FakeGetter serves canned bodies by URL and records every request.
type FakeGetter struct {
	Bodies map[string][]byte // URL to body
	Errs   map[string]error  // URL to the error it fails with

	mu       sync.Mutex
	requests []string
}

// Requests returns "METHOD url" for every request so far, in order.
func (g *FakeGetter) Requests() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.requests...)
}

func (g *FakeGetter) body(method, url string) ([]byte, error) {
	g.mu.Lock()
	g.requests = append(g.requests, method+" "+url)
	g.mu.Unlock()
	if err, ok := g.Errs[url]; ok {
		return nil, err
	}
	b, ok := g.Bodies[url]
	if !ok {
		return nil, fmt.Errorf("fake getter: no body for %s", url)
	}
	return b, nil
}

// JSON decodes the canned body of url into v.
func (g *FakeGetter) JSON(_ context.Context, url string, v any, _ string) error {
	b, err := g.body(http.MethodGet, url)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Download stores the canned body of url in blobs with every hash.
func (g *FakeGetter) Download(ctx context.Context, url string, limit int64, blobs core.BlobStore) (core.Download, error) {
	b, err := g.body(http.MethodGet, url)
	if err != nil {
		return core.Download{}, err
	}
	if int64(len(b)) > limit {
		return core.Download{}, core.ErrTooLarge
	}
	if _, _, err := blobs.Put(ctx, bytes.NewReader(b), limit); err != nil {
		return core.Download{}, err
	}
	return core.Download{SHA256: sha256.Sum256(b), SHA512: sha512.Sum512(b), SHA1: sha1.Sum(b), Size: int64(len(b))}, nil //nolint:gosec // see the import
}

// Text returns the canned body of url.
func (g *FakeGetter) Text(_ context.Context, method, url string, _ io.Reader, limit int64) ([]byte, http.Header, error) {
	b, err := g.body(method, url)
	if err != nil {
		return nil, nil, err
	}
	if int64(len(b)) > limit {
		return nil, nil, core.ErrTooLarge
	}
	return b, http.Header{}, nil
}

// Install registers g as what core.NewGetter returns for the test.
func (g *FakeGetter) Install(t testing.TB) {
	t.Helper()
	t.Cleanup(core.SwapGetter(func(core.GetterConfig) (core.Getter, error) { return g, nil }))
}

// FakeDetector emits the given findings for every subject.
type FakeDetector struct {
	Name     string
	Findings []core.Finding
}

// Info names the detector and the signals of its findings.
func (d *FakeDetector) Info() core.DetectorInfo {
	info := core.DetectorInfo{Name: d.Name}
	for _, f := range d.Findings {
		info.Signals = append(info.Signals, f.ID)
	}
	return info
}

// Detect emits every finding.
func (d *FakeDetector) Detect(_ context.Context, _ *core.Subject, emit func(core.Finding)) {
	for _, f := range d.Findings {
		emit(f)
	}
}

// Install makes d the only detector for the test.
func (d *FakeDetector) Install(t testing.TB) {
	t.Helper()
	t.Cleanup(core.SwapDetectors(d))
}

// FakeScorer is a plain scorer: catalogue defaults, allow and baseline,
// the verdict from the worst counted severity and the gate of PRD
// section 10. It applies no context rules.
type FakeScorer struct{}

// Score fills defaults and fingerprints, applies allow and baseline and
// sets the verdict.
func (FakeScorer) Score(_ context.Context, u *core.Update, _ *core.Config, allow core.AllowSet, baseline map[string]bool) {
	var match *core.AllowEntry
	counted := false
	if allow != nil {
		match, counted, _ = allow.Match(u.Eco, u.Name, u.To.Version, u.To.SHA256)
	}
	worst, allowed := cli.SeverityNone, 0
	for i := range u.Findings {
		f := &u.Findings[i]
		if info, ok := core.Signal(f.ID); ok {
			if f.Title == "" {
				f.Title = info.Title
			}
			if f.Severity == cli.SeverityNone {
				f.Severity = info.Severity
			}
			if f.Confidence == "" {
				f.Confidence = info.Confidence
			}
		}
		f.Fingerprint = core.Fingerprint(u.Eco, u.Name, u.To.Version, f.ID, f.File, f.Evidence)
		if match != nil && counted && !core.Unignorable(f.ID) {
			f.Allowed = &core.AllowMatch{By: match.By, Reason: match.Reason, Date: match.Date, Until: match.Until}
			allowed++
		}
		if baseline[f.Fingerprint] {
			f.Baselined = true
		}
		if f.Counted() && f.Severity > worst {
			worst = f.Severity
		}
	}
	switch {
	case u.From.Verified == core.ByNone || u.To.Verified == core.ByNone:
		u.Verdict = core.Unverified
	case worst == cli.SeverityCritical:
		u.Verdict = core.Hold
	case worst >= cli.SeverityMedium:
		u.Verdict = core.Review
	case allowed > 0 && allowed == len(u.Findings):
		u.Verdict = core.Allowed
	default:
		u.Verdict = core.Routine
	}
}

// Summarise counts the report.
func (FakeScorer) Summarise(r *core.Report) {
	s := core.Summary{Updates: len(r.Updates), NotChecked: core.CountNotChecked(r.NotChecked)}
	for _, u := range r.Updates {
		switch u.Verdict {
		case core.Hold:
			s.Hold++
		case core.Review:
			s.Review++
		case core.Routine:
			s.Routine++
		case core.Allowed:
			s.Allowed++
		case core.Unverified:
			s.Unverified++
		}
		if u.FromCache {
			s.FromCache++
		}
		s.Hidden += len(u.Hidden)
		for _, f := range u.Findings {
			switch {
			case f.Allowed != nil:
				s.AllowedFindings++
				continue
			case f.Baselined:
				s.Baselined++
				continue
			case f.Ignored:
				s.Ignored++
				continue
			}
			if f.Demoted != "" {
				s.Demoted++
			}
			switch f.Severity {
			case cli.SeverityCritical:
				s.Critical++
			case cli.SeverityHigh:
				s.High++
			case cli.SeverityMedium:
				s.Medium++
			case cli.SeverityLow:
				s.Low++
			case cli.SeverityInfo:
				s.Info++
			}
		}
	}
	r.Summary = s
	r.Complete = s.Unverified == 0 && s.NotChecked == 0 && len(r.Errors) == 0 && r.StoppedBy == ""
}

// Gate returns 1 for a counted finding at --fail-on, else 3 for a
// partial run under --fail-on, else 0. Like the real scorer, a partial
// run's reason is the problem then the fix on a second line.
func (FakeScorer) Gate(r *core.Report, o core.GateOptions) (int, string) {
	if o.FailOn == cli.SeverityNone {
		return cli.ExitOK, ""
	}
	for _, u := range r.Updates {
		for _, f := range slices.Concat(u.Findings, u.Hidden) {
			if f.Counted() && o.FailOn.Fails(f.Severity) {
				return cli.ExitFindings, fmt.Sprintf("findings at or above %s", o.FailOn)
			}
		}
	}
	unverified := r.Summary.Unverified > 0 && !o.AllowUnverified
	partial := (r.Summary.NotChecked > 0 || len(r.Errors) > 0 || r.StoppedBy != "") && !o.AllowPartial
	if unverified || partial {
		return cli.ExitUnavailable, fmt.Sprintf("the run is partial, so --fail-on %s can't pass it\nadd --allow-partial to accept it", o.FailOn)
	}
	return cli.ExitOK, ""
}

// Install registers the fake scorer for the test.
func (s FakeScorer) Install(t testing.TB) {
	t.Helper()
	t.Cleanup(core.SwapScorer(s))
}

// FakePolicy keeps config, allow entries and baselines in memory.
type FakePolicy struct {
	Config    *core.Config
	Allow     []core.AllowEntry
	Baselines map[string]map[string]bool // path to fingerprints

	mu sync.Mutex
}

// LoadConfig returns Config, or an empty one.
func (p *FakePolicy) LoadConfig(string, string, bool) (*core.Config, string, error) {
	if p.Config == nil {
		return &core.Config{}, "", nil
	}
	c := *p.Config
	return &c, "", nil
}

// LoadAllow returns the in-memory entries as an AllowSet.
func (p *FakePolicy) LoadAllow(*core.Config, string, string) (core.AllowSet, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return AllowList(append([]core.AllowEntry(nil), p.Allow...)), nil
}

// AddAllow appends e, or refuses it like the real policy when the same
// package, version and hash is already there.
func (p *FakePolicy) AddAllow(_ string, e core.AllowEntry) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, a := range p.Allow {
		if a.Package == e.Package && a.Version == e.Version && strings.EqualFold(a.SHA256, e.SHA256) {
			return &core.Error{Code: core.EBadConfig, Exit: cli.ExitUsage, What: e.Package + "@" + e.Version + " is already allowed",
				Err: core.ErrAlreadyAllowed}
		}
	}
	p.Allow = append(p.Allow, e)
	return nil
}

// RemoveAllow drops the entries for r.
func (p *FakePolicy) RemoveAllow(_ string, r core.Ref) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	kept := p.Allow[:0]
	for _, e := range p.Allow {
		if e.Package != r.Unversioned().String() || r.Version != "" && e.Version != r.Version {
			kept = append(kept, e)
		}
	}
	if len(kept) == len(p.Allow) {
		return fmt.Errorf("fake policy: %s is not allowed", r)
	}
	p.Allow = kept
	return nil
}

// ImportAllow imports nothing.
func (p *FakePolicy) ImportAllow(string, string) (int, error) { return 0, nil }

// LoadBaseline returns Baselines[path].
func (p *FakePolicy) LoadBaseline(path string) (map[string]bool, error) {
	b, ok := p.Baselines[path]
	if !ok {
		return nil, fmt.Errorf("fake policy: no baseline %s: %w", path, os.ErrNotExist)
	}
	return b, nil
}

// Install registers p as the policy for the test.
func (p *FakePolicy) Install(t testing.TB) {
	t.Helper()
	t.Cleanup(core.SwapPolicy(p))
}

// AllowList is an AllowSet over a slice of entries. Every match counts.
type AllowList []core.AllowEntry

// Match finds the entry for this exact version and hash and any entry
// for the version with another hash.
func (l AllowList) Match(eco core.Ecosystem, name, version, sha256 string) (*core.AllowEntry, bool, *core.AllowEntry) {
	pkg := core.Ref{Eco: eco, Name: name}.String()
	var match, conflict *core.AllowEntry
	for i := range l {
		e := &l[i]
		if e.Package != pkg || e.Version != version {
			continue
		}
		if e.SHA256 == sha256 {
			match = e
		} else {
			conflict = e
		}
	}
	return match, match != nil, conflict
}

// FakeWriter records the report it is given and writes one line.
type FakeWriter struct {
	Name string // the format it registers as

	mu  sync.Mutex
	got []*core.Report
}

// Format returns Name.
func (w *FakeWriter) Format() string { return w.Name }

// Write records r and writes "fake <format>: <n> updates".
func (w *FakeWriter) Write(out io.Writer, r *core.Report, _ core.WriteOptions) error {
	w.mu.Lock()
	w.got = append(w.got, r)
	w.mu.Unlock()
	_, err := fmt.Fprintf(out, "fake %s: %d updates\n", w.Name, len(r.Updates))
	return err
}

// Got returns the reports written so far.
func (w *FakeWriter) Got() []*core.Report {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]*core.Report(nil), w.got...)
}

// Install registers w for its format for the test.
func (w *FakeWriter) Install(t testing.TB) {
	t.Helper()
	t.Cleanup(core.SwapWriter(w))
}

// FakeDataPacks is the data packs over fixed lists.
type FakeDataPacks struct {
	PopularNames map[core.Ecosystem][]string
	Domains      []string
	PackList     []cli.DataPack

	mu       sync.Mutex
	embedded bool
}

// Names returns an index over PopularNames.
func (d *FakeDataPacks) Names() core.NameIndex { return fakeNames(d.PopularNames) }

// DomainsOK returns Domains.
func (d *FakeDataPacks) DomainsOK() []string { return d.Domains }

// Packs returns PackList.
func (d *FakeDataPacks) Packs() []cli.DataPack { return d.PackList }

// Update returns PackList.
func (d *FakeDataPacks) Update(context.Context, io.Writer) ([]cli.DataPack, error) {
	return d.PackList, nil
}

// UpdatePinned returns PackList.
func (d *FakeDataPacks) UpdatePinned(context.Context, io.Writer, map[string]string) ([]cli.DataPack, error) {
	return d.PackList, nil
}

// UseEmbedded records on.
func (d *FakeDataPacks) UseEmbedded(on bool) {
	d.mu.Lock()
	d.embedded = on
	d.mu.Unlock()
}

// Embedded reports the last UseEmbedded value.
func (d *FakeDataPacks) Embedded() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.embedded
}

// Install registers d as the data packs for the test.
func (d *FakeDataPacks) Install(t testing.TB) {
	t.Helper()
	t.Cleanup(core.SwapDataPacks(d))
}

type fakeNames map[core.Ecosystem][]string

func (n fakeNames) Popular(eco core.Ecosystem, name string) bool {
	for _, p := range n[eco] {
		if p == name {
			return true
		}
	}
	return false
}

// Near returns popular names one edit away (same length, one byte
// different, or one byte added or removed).
func (n fakeNames) Near(eco core.Ecosystem, name string) []string {
	var out []string
	for _, p := range n[eco] {
		if p != name && oneEdit(p, name) {
			out = append(out, p)
		}
	}
	return out
}

func oneEdit(a, b string) bool {
	if len(a) < len(b) {
		a, b = b, a
	}
	switch len(a) - len(b) {
	case 0:
		diff := 0
		for i := range a {
			if a[i] != b[i] {
				diff++
			}
		}
		return diff == 1
	case 1:
		for i := range b {
			if a[i] != b[i] {
				return a[i+1:] == b[i:]
			}
		}
		return true
	}
	return false
}

// FakeExplainRenderer writes the signal ID or the selector it was asked
// for.
type FakeExplainRenderer struct{}

// RenderSignal writes "explain <id>".
func (FakeExplainRenderer) RenderSignal(w io.Writer, id string, _ core.WriteOptions, _ bool) error {
	if _, ok := core.Signal(id); !ok {
		return fmt.Errorf("fake explain: no signal %q", id)
	}
	_, err := fmt.Fprintf(w, "explain %s\n", id)
	return err
}

// RenderFinding writes "explain finding <sel> (<n> hunks)".
func (FakeExplainRenderer) RenderFinding(w io.Writer, _ *core.Report, sel string, hunks []core.Hunk, _ core.WriteOptions, _ bool) error {
	_, err := fmt.Fprintf(w, "explain finding %s (%d hunks)\n", sel, len(hunks))
	return err
}

// Install registers the fake explain renderer for the test.
func (e FakeExplainRenderer) Install(t testing.TB) {
	t.Helper()
	t.Cleanup(core.SwapExplainRenderer(e))
}

// FakeSigner "signs" with the sha256 of the JSON: Sign writes it as hex
// to <json>.sig and Verify checks it. It proves the wiring, not crypto.
type FakeSigner struct{}

// ErrBadSignature is what FakeSigner.Verify returns for a wrong .sig.
var ErrBadSignature = errors.New("fake signer: signature does not match")

// Sign writes <jsonPath>.sig.
func (FakeSigner) Sign(jsonPath, _ string) (string, error) {
	b, err := os.ReadFile(jsonPath) //nolint:gosec // the test's own file
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	sig := jsonPath + ".sig"
	return sig, os.WriteFile(sig, []byte(hex.EncodeToString(sum[:])), 0o600) //nolint:gosec // beside the test's own file
}

// Verify checks sigBytes against jsonBytes. The key ID is "fake".
func (FakeSigner) Verify(jsonBytes, sigBytes []byte, _ [][]byte) (string, error) {
	sum := sha256.Sum256(jsonBytes)
	if string(bytes.TrimSpace(sigBytes)) != hex.EncodeToString(sum[:]) {
		return "", ErrBadSignature
	}
	return "fake", nil
}

// Install registers the fake signer for the test.
func (s FakeSigner) Install(t testing.TB) {
	t.Helper()
	t.Cleanup(core.SwapSigner(s))
}
