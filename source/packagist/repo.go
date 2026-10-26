// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package packagist

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/fetch"
)

// repo is one private Composer repository from config. Its packages.json
// says which packages it has and where their metadata is; credentials
// come from COMPOSER_AUTH through the Getter, only for its own host.
type repo struct {
	base string // without a trailing slash
	host string

	once sync.Once
	idx  *repoIndex
	err  error
}

// repoIndex is what a packages.json answer says.
type repoIndex struct {
	metadataURL string          // absolute, with %package%; "" when the repository lists inline only
	listed      bool            // available-packages or patterns given: anything else is not here
	available   map[string]bool // lower-case names
	patterns    []string        // lower-case globs with *
	inline      map[string][]release
}

// repos reads the private Composer repositories of env, in the order
// config lists them (core.BaseComposerRepo + "<n>").
func repos(env *core.Env) []*repo {
	type keyed struct {
		n    int
		base string
	}
	var ks []keyed
	for k, v := range env.Bases {
		rest, ok := strings.CutPrefix(k, core.BaseComposerRepo)
		if !ok || strings.TrimSpace(v) == "" {
			continue
		}
		n, err := strconv.Atoi(rest)
		if err != nil {
			n = 1 << 30 // after the numbered ones, still in a stable order
		}
		ks = append(ks, keyed{n, strings.TrimRight(strings.TrimSpace(v), "/")})
	}
	slices.SortFunc(ks, func(a, b keyed) int {
		if a.n != b.n {
			return a.n - b.n
		}
		return strings.Compare(a.base, b.base)
	})
	out := make([]*repo, 0, len(ks))
	for _, k := range ks {
		u, err := url.Parse(k.base)
		if err != nil || u.Host == "" {
			continue
		}
		out = append(out, &repo{base: k.base, host: u.Hostname()})
	}
	return out
}

// index loads the repository's packages.json once per run.
func (r *repo) index(ctx context.Context, s *Source) (*repoIndex, error) {
	r.once.Do(func() { r.idx, r.err = r.loadIndex(ctx, s) })
	return r.idx, r.err
}

func (r *repo) loadIndex(ctx context.Context, s *Source) (*repoIndex, error) {
	var top struct {
		MetadataURL json.RawMessage `json:"metadata-url"`
		Available   []string        `json:"available-packages"`
		Patterns    []string        `json:"available-package-patterns"`
		Packages    json.RawMessage `json:"packages"`
	}
	if err := s.env.Get.JSON(ctx, r.base+"/packages.json", &top, fetch.KindVersions); err != nil {
		return nil, err
	}
	idx := &repoIndex{available: map[string]bool{}, inline: map[string][]release{}}
	if mu := str(top.MetadataURL); mu != "" && strings.Contains(mu, "%package%") {
		idx.metadataURL = r.resolve(mu)
	}
	for _, n := range top.Available {
		idx.available[strings.ToLower(n)] = true
	}
	for _, p := range top.Patterns {
		idx.patterns = append(idx.patterns, strings.ToLower(p))
	}
	idx.listed = len(top.Available) > 0 || len(top.Patterns) > 0
	// The inline form (Satis, Composer 1 repositories) maps each name to
	// its versions by version string. PHP writes an empty one as [].
	var inline map[string]map[string]map[string]json.RawMessage
	if json.Unmarshal(top.Packages, &inline) == nil {
		for name, byVersion := range inline {
			for _, m := range byVersion {
				if rel, ok := decodeRelease(m); ok {
					idx.inline[strings.ToLower(name)] = append(idx.inline[strings.ToLower(name)], rel)
				}
			}
		}
	}
	return idx, nil
}

// resolve makes a metadata-url absolute the way Composer does: a path
// from the repository's host root, a full URL, or a path under the
// repository. It is not parsed as a URL first, since %package% is not a
// valid escape.
func (r *repo) resolve(mu string) string {
	switch {
	case strings.HasPrefix(mu, "https://") || strings.HasPrefix(mu, "http://"):
		return mu
	case strings.HasPrefix(mu, "/"):
		u, _ := url.Parse(r.base) // parsed in repos
		return u.Scheme + "://" + u.Host + mu
	}
	return r.base + "/" + mu
}

// has reports whether the repository may have name, as its listing says.
func (x *repoIndex) has(name string) bool {
	if !x.listed {
		return x.metadataURL != ""
	}
	if x.available[name] {
		return true
	}
	for _, p := range x.patterns {
		if globMatch(p, name) {
			return true
		}
	}
	return false
}

// globMatch matches Composer's available-package-patterns, where * is
// any run of characters including "/".
func globMatch(pattern, name string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == name
	}
	if !strings.HasPrefix(name, parts[0]) {
		return false
	}
	name = name[len(parts[0]):]
	for i, p := range parts[1:] {
		last := i == len(parts)-2
		if last {
			return strings.HasSuffix(name, p)
		}
		j := strings.Index(name, p)
		if j < 0 {
			return false
		}
		name = name[j+len(p):]
	}
	return true
}

// lookup returns name's releases from the repository; found is false
// when it does not have the package.
func (r *repo) lookup(ctx context.Context, s *Source, name string) (rels []release, found bool, err error) {
	idx, err := r.index(ctx, s)
	if err != nil {
		return nil, false, err
	}
	if rels, ok := idx.inline[name]; ok {
		return rels, true, nil
	}
	if !idx.has(name) {
		return nil, false, nil
	}
	tagged, ok, err := s.p2(ctx, strings.ReplaceAll(idx.metadataURL, "%package%", escapeName(name)), name)
	if err != nil || !ok {
		return nil, false, err
	}
	dev, _, err := s.p2(ctx, strings.ReplaceAll(idx.metadataURL, "%package%", escapeName(name)+"~dev"), name)
	if err != nil {
		return nil, false, err
	}
	return append(tagged, dev...), true, nil
}

// p2 loads one p2 answer for name; ok is false on a 404.
func (s *Source) p2(ctx context.Context, u, name string) ([]release, bool, error) {
	var doc p2Doc
	err := s.env.Get.JSON(ctx, u, &doc, fetch.KindVersions)
	if fetch.StatusOf(err) == http.StatusNotFound {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return releases(&doc, name), true, nil
}

// noDist is E3 for a release Composer can only install from source.
func noDist(name, v, host string) *core.Error {
	return &core.Error{
		Code: core.EVersionMissing, Exit: cli.ExitUsage, Command: command,
		What: fmt.Sprintf("%s %s has no dist archive on %s", name, v, host),
		Hint: []string{"Sightread reviews the archive Composer downloads; a release installed only from source can't be reviewed"},
	}
}
