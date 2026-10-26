// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/RhythmShahriar/rhythm/kit/config"
	"github.com/RhythmShahriar/rhythm/kit/secrets"
	"github.com/RhythmShahriar/sightread/core"
)

// NothingToCompare ends the note a run leaves for a named package that
// is already at its candidate version. A command whose run reviewed
// nothing else prints these notes instead of a report.
const NothingToCompare = ": nothing to compare"

// Stop reasons of core.Report.StoppedBy.
const (
	StoppedInterrupted = "interrupted"
	StoppedDeadline    = "deadline"
)

// reviewer holds one run's state.
type reviewer struct {
	req      Request
	cfg      *core.Config
	cfgPath  string
	allow    core.AllowSet
	baseline map[string]bool
	cache    string
	blobs    core.BlobStore
	env      *core.Env
	inv      core.Inventory
	differ   core.Differ
	analyzer core.Analyzer
	scorer   core.Scorer
	osv      map[core.Ref][]core.Advisory

	mu       sync.Mutex // guards what the workers add below
	notes    []string
	warnings []string
	onUpdate sync.Mutex
	target   string       // Report.Target.Path once resolved, for OnUpdate
	stopped  atomic.Bool  // the hard stop came: no more --jsonl lines
	ghPlan   atomic.Int64 // api.github.com requests the run plans
}

// githubRequestsPerArchive is what a Composer archive on GitHub costs
// from api.github.com: the zipball request (codeload is not counted).
const githubRequestsPerArchive = 1

// githubRequestsPerTagCheck is the most a git tag check sends: one
// request for each tag form it tries.
const githubRequestsPerTagCheck = 3

// expectGitHub adds n api.github.com requests to the run's plan and
// tells the Getter, so an anonymous run that can't finish stops before
// it spends GitHub's hourly allowance (E16).
func (r *reviewer) expectGitHub(n int) {
	total := r.ghPlan.Add(int64(n))
	if g, ok := r.env.Get.(interface{ ExpectGitHub(int) }); ok {
		g.ExpectGitHub(int(total))
	}
}

// Review runs one review (PRD section 13): it loads config and allow
// entries, resolves what to review, fetches, verifies, diffs and
// analyses both versions of every update on a pool of --jobs workers,
// runs every detector and the scorer and returns the report. The report
// is also saved under <cache>/runs/ for explain and watch.
//
// ctx is the soft stop: once it is done (the first Ctrl-C) no new
// package starts, the ones under way finish and the report says it was
// interrupted. Request.HardStop and --deadline end the run at once.
//
// The error is for what stops the whole run: a bad config (E12), a named
// package that isn't installed (E1), isn't published (E2, E3) or would be
// a downgrade (E19), an unreadable lockfile (E4, E8) or a stage that
// isn't linked. Problems with one package are recorded in the report.
func Review(ctx context.Context, req Request) (*core.Report, error) {
	started := req.now()
	r := &reviewer{req: req}
	if err := r.setup(); err != nil {
		return nil, err
	}

	work, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	deadline := cmp.Or(r.req.Deadline, DefaultDeadline)
	work, cancelDeadline := context.WithTimeout(work, deadline)
	defer cancelDeadline()
	hard := make(chan struct{})
	var hardOnce sync.Once
	stopHard := func() { hardOnce.Do(func() { close(hard) }) }
	if r.req.HardStop != nil {
		go func() {
			select {
			case <-r.req.HardStop:
				stopHard()
				cancel()
			case <-work.Done():
			}
		}()
	}

	rep := &core.Report{Kind: core.KindReview, Started: started.UTC()}
	targets, err := r.resolve(work, rep)
	if err != nil {
		return nil, err
	}
	r.target = rep.Target.Path
	r.packs(rep)

	picked, err := r.pickAll(ctx, work, hard, targets)
	if err != nil {
		return nil, err
	}
	r.advisories(work, picked, rep)
	composer := 0
	for _, t := range picked {
		if t.eco == core.Composer && t.failed == nil && t.picked {
			composer++
		}
	}
	if composer > 0 {
		// Both sides of each update may be a GitHub zipball.
		r.expectGitHub(2 * githubRequestsPerArchive * composer)
	}
	results := r.reviewAll(ctx, work, hard, picked)

	for i, res := range results {
		t := picked[i]
		if res == nil {
			rep.NotChecked = append(rep.NotChecked, notReviewed(t, stopReason(ctx, work, hard, deadline)))
			continue
		}
		if res.update != nil {
			rep.Updates = append(rep.Updates, *res.update)
		}
		rep.NotChecked = append(rep.NotChecked, res.notChecked...)
		rep.Errors = append(rep.Errors, res.errs...)
	}
	switch {
	case isClosed(hard) || ctx.Err() != nil:
		rep.StoppedBy = StoppedInterrupted
	case errors.Is(work.Err(), context.DeadlineExceeded):
		rep.StoppedBy = StoppedDeadline
	}
	r.mu.Lock()
	rep.Notes = append(rep.Notes, r.notes...)
	rep.Warnings = append(rep.Warnings, r.warnings...)
	r.mu.Unlock()
	finishReport(rep)
	rep.Duration = r.req.now().Sub(started)
	r.scorer.Summarise(rep)
	if _, err := saveRun(r.cache, rep, r.req.Version, started); err != nil {
		r.logf("runs: %v", err)
	}
	return rep, nil
}

// setup loads config, allow entries and the baseline and builds the
// Getter, the blob store and the source environment.
func (r *reviewer) setup() error {
	policy := core.GetPolicy()
	r.inv, r.differ, r.analyzer, r.scorer = core.GetInventory(), core.GetDiffer(), core.GetAnalyzer(), core.GetScorer()
	for name, ok := range map[string]bool{"policy": policy != nil, "differ": r.differ != nil, "analyzer": r.analyzer != nil, "scorer": r.scorer != nil} {
		if !ok {
			return fmt.Errorf("%s %w", name, core.ErrNotLinked)
		}
	}
	start := cmp.Or(r.req.ConfigStart, ".")
	// Config, allow and baseline errors are tool-wide (PRD 10, E12):
	// they name the file, not the command.
	cfg, cfgPath, err := policy.LoadConfig(start, r.req.ConfigFile, r.req.NoConfig)
	if err != nil {
		return err
	}
	r.cfg, r.cfgPath = cfg, cfgPath
	baseRef := r.prBaseRef()
	if baseRef != "" {
		// Before applyConfig and LoadAllow, so a flag still wins and the
		// allow files read are the ones the base config names.
		if err := r.configAtBase(policy, baseRef, start); err != nil {
			return err
		}
	}
	r.applyConfig()
	if r.req.NoSignalUpdates {
		if dp := core.GetDataPacks(); dp != nil {
			dp.UseEmbedded(true)
		}
	}

	if r.req.NoAllow {
		r.allow = noAllow{}
	} else if r.allow, err = policy.LoadAllow(r.cfg, r.cfgPath, baseRef); err != nil {
		// With baseRef set allow entries count from the base only, so a
		// pull request can't approve its own update (SR-9).
		return err
	}
	if r.req.Baseline != "" {
		if r.baseline, err = policy.LoadBaseline(r.req.Baseline); err != nil {
			return err
		}
		if baseRef != "" {
			if err := r.baselineAtBase(policy, baseRef); err != nil {
				return err
			}
		}
	}

	if r.cache = r.req.CacheDir; r.cache == "" {
		if r.cache, err = config.CacheDir("sightread"); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(r.cache, 0o700); err != nil {
		return fmt.Errorf("cache folder: %w", err)
	}
	if r.blobs, err = core.OpenBlobs(r.cache); err != nil {
		return err
	}
	gc := r.req.Getter
	gc.Bases = r.bases()
	gc.CacheDir = r.cache
	if gc.PerHost == 0 {
		gc.PerHost = min(r.jobs(), 4)
	}
	if r.req.Log != nil && gc.Debug == nil {
		gc.Debug = r.req.Log
	}
	get, err := core.NewGetter(gc)
	if err != nil {
		return err
	}
	r.env = &core.Env{Get: get, Blobs: r.blobs, Limits: r.limits(), Offline: gc.Offline, Bases: gc.Bases,
		Options: r.req.Options, Log: r.req.Log}
	return nil
}

// applyConfig fills what the flags left out from the config. A flag
// always wins; booleans use Request.Set to tell "not given" from false.
func (r *reviewer) applyConfig() {
	c, q := r.cfg, &r.req
	if !q.set("path") && c.Path != "" {
		p := c.Path
		if !filepath.IsAbs(p) && r.cfgPath != "" {
			// path is relative to the project, the folder holding .sightread/.
			p = filepath.Join(filepath.Dir(filepath.Dir(r.cfgPath)), p)
		}
		q.Inventory.Root = p
	}
	if !q.set("transitive") {
		q.Transitive = q.Transitive || c.Transitive
	}
	if !q.set("pre") {
		q.Pre = q.Pre || c.Pre
	}
	if !q.set("svn-check") {
		q.Options.SVNCheck = q.Options.SVNCheck || c.SVNCheck
	}
	q.Options.Pre = q.Pre
	if !q.set("no-osv") && c.OSV != nil && !*c.OSV {
		q.NoOSV = true
	}
	if q.Eco == "" && len(q.Inventory.Ecosystems) == 0 {
		q.Inventory.Ecosystems = c.Ecosystems
	}
	q.Inventory.Transitive = q.Transitive
	if q.FailOn != "" {
		c.FailOn = q.FailOn
	}
	if q.MinConfidence != "" {
		c.MinConfidence = q.MinConfidence
	}
	c.MinConfidence = cmp.Or(c.MinConfidence, string(core.Likely))
	if q.MinAge != "" {
		c.MinAge = q.MinAge
	}
	c.MinAge = cmp.Or(c.MinAge, DefaultMinAge)
	c.Signals.Dirs = append(c.Signals.Dirs, q.SignalDirs...)
	for _, s := range q.Sites {
		if s.AllowFile != "" {
			c.AllowFrom = append(c.AllowFrom, s.AllowFile)
		}
	}
}

// bases merges mirror URLs: config sources first, then the SIGHTREAD_*
// variables the command read, which win.
func (r *reviewer) bases() map[string]string {
	s := r.cfg.Sources
	b := map[string]string{}
	for k, v := range map[string]string{
		core.BaseWPOrgAPI: s.WPOrgAPI, core.BaseWPOrgDownloads: s.WPOrgDownloads, core.BaseWPOrgSVN: s.WPOrgSVN,
		core.BaseWPOrgThemeSVN: s.WPOrgThemeSVN, core.BasePackagist: s.Packagist, core.BasePackagistMeta: s.PackagistMeta,
		core.BaseGitHubAPI: s.GitHubAPI, core.BaseGitHubCodeload: s.GitHubCodeload, core.BaseNPM: s.NPM.Registry, core.BaseOSV: s.OSV,
	} {
		if v != "" {
			b[k] = v
		}
	}
	for scope, u := range s.NPM.Scopes {
		b[core.BaseNPMScope+scope] = u
	}
	for i, u := range s.Composer.Repositories {
		b[core.BaseComposerRepo+strconv.Itoa(i)] = u
	}
	for k, v := range r.req.Getter.Bases {
		if v != "" {
			b[k] = v
		}
	}
	return b
}

func (r *reviewer) limits() core.Limits {
	lim := core.DefaultLimits()
	if r.req.MaxSize > 0 {
		lim.Download = r.req.MaxSize
		lim.Uncompressed = min(4*r.req.MaxSize, MaxUncompressed)
	}
	return lim
}

func (r *reviewer) jobs() int { return max(cmp.Or(r.req.Jobs, DefaultJobs), 1) }

// packs records the data pack versions in the report header.
func (r *reviewer) packs(rep *core.Report) {
	rep.FailOn = r.cfg.FailOn
	rep.MinConfidence = r.cfg.MinConfidence
	dp := core.GetDataPacks()
	if dp == nil {
		return
	}
	for _, p := range dp.Packs() {
		switch p.Name {
		case "sightread-signals":
			rep.SignalPack = p.Version
		case "sightread-names":
			rep.NamesPack = p.Version
		}
	}
}

// logf writes one -v line. Errors can carry text from a registry or a
// package, so every line is secret-masked (SR-10).
func (r *reviewer) logf(format string, a ...any) {
	if r.req.Log != nil {
		fmt.Fprintln(r.req.Log, secrets.Redact("sightread: "+fmt.Sprintf(format, a...)))
	}
}

func (r *reviewer) note(s string) {
	r.mu.Lock()
	r.notes = append(r.notes, s)
	r.mu.Unlock()
}

func (r *reviewer) warn(s string) {
	r.mu.Lock()
	r.warnings = append(r.warnings, s)
	r.mu.Unlock()
}

// pickAll chooses the candidate of every target on the worker pool.
// Named packages are the user's own words, so their E2, E3 and E19 end
// the run; for packages found in an inventory they are recorded.
func (r *reviewer) pickAll(soft, work context.Context, hard <-chan struct{}, targets []*target) ([]*target, error) {
	var mu sync.Mutex
	errs := make([]error, len(targets))
	done := make(chan struct{})
	go func() {
		defer close(done)
		var g errgroup.Group
		g.SetLimit(r.jobs())
		for i, t := range targets {
			if soft.Err() != nil || work.Err() != nil {
				break
			}
			g.Go(func() error {
				err := r.pick(work, t)
				mu.Lock()
				errs[i] = err
				mu.Unlock()
				return nil
			})
		}
		_ = g.Wait()
	}()
	select {
	case <-done:
	case <-hard:
		// The second Ctrl-C: nothing more is picked or reviewed. Workers
		// still picking change their own targets, so the report gets
		// fresh copies that list every one as not reviewed.
		out := make([]*target, len(targets))
		for i, t := range targets {
			out[i] = &target{eco: t.eco, name: t.name, fromVersion: t.fromVersion}
		}
		return out, nil
	}
	var out []*target
	for i, t := range targets {
		if err := errs[i]; err != nil && !isStop(err) {
			if t.explicit {
				return nil, err
			}
			t.failed = r.failure(t, err)
		}
		if !t.skip {
			// Picked, failed with its entries, or never started (listed
			// as not reviewed).
			out = append(out, t)
		}
	}
	return out, nil
}

// reviewAll reviews every picked target on the pool and returns their
// results by index, so the report order never depends on timing. A nil
// result is a target the run stopped before.
func (r *reviewer) reviewAll(soft, work context.Context, hard <-chan struct{}, targets []*target) []*result {
	results := make([]*result, len(targets))
	var mu sync.Mutex
	var g errgroup.Group
	g.SetLimit(r.jobs())
	total := 0
	for _, t := range targets {
		if t.failed == nil && t.picked {
			total++
		}
	}
	var n atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i, t := range targets {
			if t.failed != nil {
				mu.Lock()
				results[i] = t.failed
				mu.Unlock()
				continue
			}
			if !t.picked || soft.Err() != nil || work.Err() != nil || isClosed(hard) {
				continue
			}
			g.Go(func() error {
				if soft.Err() != nil || work.Err() != nil {
					return nil
				}
				r.progress(int(n.Add(1)), total, t)
				res := r.review(work, t)
				if res == nil {
					return nil // cut short: listed as not reviewed
				}
				mu.Lock()
				results[i] = res
				mu.Unlock()
				return nil
			})
		}
		_ = g.Wait()
	}()
	select {
	case <-done:
	case <-hard:
		// The second Ctrl-C: report what finished and leave the rest.
		r.stopped.Store(true)
	}
	mu.Lock()
	defer mu.Unlock()
	return slices.Clone(results)
}

func (r *reviewer) progress(i, total int, t *target) {
	if r.req.Progress == nil {
		return
	}
	from := t.fromVersion
	if from == "" {
		from = "new"
	}
	fmt.Fprintf(r.req.Progress, "reviewing %d of %d: %s %s → %s\n", i, total, t.name, from, t.cand.Version)
}

// isClosed reports whether c is closed, without blocking.
func isClosed(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

func stopReason(soft, work context.Context, hard <-chan struct{}, deadline time.Duration) string {
	if isClosed(hard) || soft.Err() != nil {
		return "the run was interrupted before it"
	}
	if errors.Is(work.Err(), context.DeadlineExceeded) {
		return "--deadline " + deadline.String() + " passed before it"
	}
	return "the run stopped before it"
}

func notReviewed(t *target, why string) core.NotChecked {
	return core.NotChecked{Eco: t.eco, Name: t.name, Version: t.fromVersion, Reason: core.FetchFailed,
		Text: why + " was reviewed", Hint: "run again"}
}

// finishReport sorts the report so it reads the same on every run and
// drops duplicate Not checked entries (an inventory and the pipeline may
// both list a private package).
func finishReport(rep *core.Report) {
	ecoRank := func(e core.Ecosystem) int {
		if i := slices.Index(core.Ecosystems(), e); i >= 0 {
			return i
		}
		return len(core.Ecosystems())
	}
	slices.SortStableFunc(rep.Updates, func(a, b core.Update) int {
		return cmp.Or(cmp.Compare(ecoRank(a.Eco), ecoRank(b.Eco)), strings.Compare(a.Name, b.Name),
			strings.Compare(a.From.Version, b.From.Version), strings.Compare(a.To.Version, b.To.Version))
	})
	seen := map[string]bool{}
	nc := rep.NotChecked[:0]
	for _, n := range rep.NotChecked {
		k := string(n.Eco) + "\x00" + n.Name + "\x00" + string(n.Reason) + "\x00" + n.Text
		if !seen[k] {
			seen[k] = true
			nc = append(nc, n)
		}
	}
	rep.NotChecked = nc
	slices.SortStableFunc(rep.NotChecked, func(a, b core.NotChecked) int {
		return cmp.Or(cmp.Compare(ecoRank(a.Eco), ecoRank(b.Eco)), strings.Compare(a.Name, b.Name))
	})
	slices.SortStableFunc(rep.Errors, func(a, b core.ErrorEntry) int {
		return cmp.Or(cmp.Compare(ecoRank(a.Eco), ecoRank(b.Eco)), strings.Compare(a.Name, b.Name))
	})
}

// noAllow is the empty allow set of --no-allow.
type noAllow struct{}

func (noAllow) Match(core.Ecosystem, string, string, string) (*core.AllowEntry, bool, *core.AllowEntry) {
	return nil, false, nil
}

// hostOf returns the host of a URL, or "".
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

// firstLine is the first line of an error's text, the summary PRD 10
// shows without -v, secret-masked because it goes into the report.
func firstLine(err error) string {
	var e *core.Error
	if errors.As(err, &e) {
		return secrets.Redact(e.What)
	}
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return secrets.Redact(s)
}

// isStop reports whether err only says the run was stopped.
func isStop(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}
