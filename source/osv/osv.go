// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/fetch"
)

func init() {
	core.SetAdvisories(func(env *core.Env) core.Advisories { return New(env) })
}

// batchSize is the most queries one querybatch request carries (OSV's
// own limit is 1,000).
const batchSize = 1000

// maxPages caps the follow-up pages asked for one query: a version with
// more advisories than that is already a clear signal.
const maxPages = 5

// workers is how many vulnerability records are fetched at once.
const workers = 4

// maxSummary caps an advisory summary.
const maxSummary = 300

// ecosystems maps Sightread's ecosystems to OSV's. WordPress plugins and
// themes have no OSV ecosystem.
var ecosystems = map[core.Ecosystem]string{core.NPM: "npm", core.Composer: "Packagist"}

// Client is the OSV lookup: one batch query for every public reference,
// then each advisory's record (cached 6 hours). It implements
// core.Advisories.
type Client struct {
	env  *core.Env
	base string
}

// New returns the OSV lookup for env.
func New(env *core.Env) *Client {
	b := env.Bases[core.BaseOSV]
	if b == "" {
		b = fetch.DefaultBases()[core.BaseOSV]
	}
	return &Client{env: env, base: strings.TrimRight(b, "/")}
}

// query is one entry of a querybatch request.
type query struct {
	Package   pkg    `json:"package"`
	Version   string `json:"version"`
	PageToken string `json:"page_token,omitempty"`
}

type pkg struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// batchAnswer is a querybatch answer: one result per query, in order.
type batchAnswer struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
		NextPageToken string `json:"next_page_token"`
	} `json:"results"`
}

// Query returns the advisories of each reference that has any. Refs of a
// private registry (an npm scope configured in sources) are never sent:
// a private name must not leave the machine (run drops every
// Meta.Private ref before calling). Refs without a version, or of an
// ecosystem OSV does not cover, are skipped.
func (c *Client) Query(ctx context.Context, refs []core.Ref) (map[core.Ref][]core.Advisory, error) {
	var qs []query
	var keep []core.Ref
	seen := map[core.Ref]bool{}
	for _, r := range refs {
		eco, ok := ecosystems[r.Eco]
		if !ok || r.Version == "" || seen[r] || c.private(r) {
			continue
		}
		seen[r] = true
		name := r.Name
		if r.Eco == core.Composer {
			name = strings.ToLower(name)
		}
		qs = append(qs, query{Package: pkg{Name: name, Ecosystem: eco}, Version: r.Version})
		keep = append(keep, r)
	}
	ids := make([][]string, len(qs))
	for start := 0; start < len(qs); start += batchSize {
		end := min(start+batchSize, len(qs))
		if err := c.batch(ctx, qs[start:end], ids[start:end]); err != nil {
			return nil, err
		}
	}
	records, err := c.records(ctx, ids)
	if err != nil {
		return nil, err
	}
	out := map[core.Ref][]core.Advisory{}
	for i, r := range keep {
		q := qs[i].Package
		for _, id := range ids[i] {
			if rec, ok := records[id]; ok {
				out[r] = append(out[r], rec.advisory(q))
			}
		}
	}
	return out, nil
}

// private reports whether r belongs to a private npm scope.
func (c *Client) private(r core.Ref) bool {
	if r.Eco != core.NPM || !strings.HasPrefix(r.Name, "@") {
		return false
	}
	scope, _, _ := strings.Cut(r.Name, "/")
	for k := range c.env.Bases {
		if s, ok := strings.CutPrefix(k, core.BaseNPMScope); ok && strings.EqualFold(s, scope) {
			return true
		}
	}
	return false
}

// batch sends qs and fills ids, following page tokens up to maxPages.
func (c *Client) batch(ctx context.Context, qs []query, ids [][]string) error {
	pending := make([]int, len(qs))
	for i := range pending {
		pending[i] = i
	}
	cur := slices.Clone(qs)
	for page := 0; len(pending) > 0 && page < maxPages; page++ {
		send := make([]query, len(pending))
		for j, i := range pending {
			send[j] = cur[i]
		}
		ans, err := c.post(ctx, send)
		if err != nil {
			return err
		}
		if len(ans.Results) != len(send) {
			return fmt.Errorf("unexpected answer from %s: %d results for %d queries", c.host(), len(ans.Results), len(send))
		}
		var next []int
		for j, i := range pending {
			res := ans.Results[j]
			for _, v := range res.Vulns {
				if v.ID != "" && !slices.Contains(ids[i], v.ID) {
					ids[i] = append(ids[i], v.ID)
				}
			}
			if res.NextPageToken != "" {
				cur[i].PageToken = res.NextPageToken
				next = append(next, i)
			}
		}
		pending = next
	}
	return nil
}

func (c *Client) post(ctx context.Context, qs []query) (*batchAnswer, error) {
	body, err := json.Marshal(map[string]any{"queries": qs})
	if err != nil {
		return nil, err
	}
	lim := c.env.Limits.JSON
	if lim <= 0 {
		lim = core.DefaultLimits().JSON
	}
	raw, _, err := c.env.Get.Text(ctx, "POST", c.base+"/v1/querybatch", bytes.NewReader(body), lim)
	if err != nil {
		return nil, err
	}
	var ans batchAnswer
	if err := json.Unmarshal(raw, &ans); err != nil {
		return nil, fmt.Errorf("unexpected answer from %s: %w", c.host(), err)
	}
	return &ans, nil
}

func (c *Client) host() string {
	if u, err := url.Parse(c.base); err == nil && u.Host != "" {
		return u.Hostname()
	}
	return c.base
}

// records fetches each advisory once, a few at a time.
func (c *Client) records(ctx context.Context, ids [][]string) (map[string]*record, error) {
	var all []string
	for _, l := range ids {
		for _, id := range l {
			if !slices.Contains(all, id) {
				all = append(all, id)
			}
		}
	}
	out := map[string]*record{}
	var mu sync.Mutex
	var first error
	work := make(chan string)
	var wg sync.WaitGroup
	for range min(workers, len(all)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for id := range work {
				var rec record
				err := c.env.Get.JSON(ctx, c.base+"/v1/vulns/"+url.PathEscape(id), &rec, fetch.KindOSV)
				mu.Lock()
				if err != nil && first == nil {
					first = err
				}
				if err == nil {
					rec.ID = id
					out[id] = &rec
				}
				mu.Unlock()
			}
		}()
	}
	for _, id := range all {
		work <- id
	}
	close(work)
	wg.Wait()
	return out, first
}

// record is the part of an OSV vulnerability record Sightread reads.
type record struct {
	ID       string `json:"id"`
	Summary  string `json:"summary"`
	Details  string `json:"details"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Ranges []struct {
			Type   string `json:"type"`
			Events []struct {
				Fixed string `json:"fixed"`
			} `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
}

// advisory turns a record into the advisory for package p: FixedIn are
// the "fixed" events of p's ECOSYSTEM and SEMVER ranges (GIT ranges name
// commits, not versions).
func (r *record) advisory(p pkg) core.Advisory {
	a := core.Advisory{
		ID: r.ID, Malicious: strings.HasPrefix(r.ID, "MAL-"),
		URL: "https://osv.dev/vulnerability/" + url.PathEscape(r.ID),
	}
	a.Summary = r.Summary
	if a.Summary == "" {
		a.Summary, _, _ = strings.Cut(strings.TrimSpace(r.Details), "\n")
	}
	if len(a.Summary) > maxSummary {
		a.Summary = a.Summary[:maxSummary] + "..."
	}
	for _, af := range r.Affected {
		if !strings.EqualFold(af.Package.Name, p.Name) || af.Package.Ecosystem != p.Ecosystem {
			continue
		}
		for _, rg := range af.Ranges {
			if rg.Type != "ECOSYSTEM" && rg.Type != "SEMVER" {
				continue
			}
			for _, ev := range rg.Events {
				if ev.Fixed != "" && !slices.Contains(a.FixedIn, ev.Fixed) {
					a.FixedIn = append(a.FixedIn, ev.Fixed)
				}
			}
		}
	}
	slices.Sort(a.FixedIn)
	return a
}

// Client is a core.Advisories.
var _ core.Advisories = (*Client)(nil)
