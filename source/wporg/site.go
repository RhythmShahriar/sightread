// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package wporg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/fetch"
	"github.com/RhythmShahriar/sightread/version"
)

// maxHistory is how many earlier releases Meta.History lists.
const maxHistory = 10

// site is what the plugin and theme sources share: one ecosystem of
// WordPress.org with its bases, limits and an info answer per slug.
type site struct {
	env     *core.Env
	eco     core.Ecosystem
	command string // "plugin" or "theme", as errors name the command
	api     string // the info API base
	dl      string // downloads.wordpress.org
	svn     string // plugins.svn or themes.svn
	lim     core.Limits

	mu    sync.Mutex
	infos map[string]*info // successful and not-found answers, per slug
}

func newSite(env *core.Env, eco core.Ecosystem) *site {
	s := &site{env: env, eco: eco, infos: map[string]*info{}, lim: limits(env.Limits)}
	s.command, s.svn = "plugin", base(env, core.BaseWPOrgSVN)
	if eco == core.WPTheme {
		s.command, s.svn = "theme", base(env, core.BaseWPOrgThemeSVN)
	}
	s.api, s.dl = base(env, core.BaseWPOrgAPI), base(env, core.BaseWPOrgDownloads)
	return s
}

// base is env's base for key, or the official one, without a trailing
// slash.
func base(env *core.Env, key string) string {
	b := env.Bases[key]
	if b == "" {
		b = fetch.DefaultBases()[key]
	}
	return strings.TrimRight(b, "/")
}

// limits fills the limits a caller left at zero, so a source never runs
// without one.
func limits(l core.Limits) core.Limits {
	d := core.DefaultLimits()
	if l.Download <= 0 {
		l.Download = d.Download
	}
	if l.Uncompressed <= 0 {
		l.Uncompressed = d.Uncompressed
	}
	if l.EntryStored <= 0 {
		l.EntryStored = d.EntryStored
	}
	if l.JSON <= 0 {
		l.JSON = d.JSON
	}
	if l.Entries <= 0 {
		l.Entries = d.Entries
	}
	if l.Ratio <= 0 {
		l.Ratio = d.Ratio
	}
	return l
}

// logf writes a -v note.
func (s *site) logf(format string, args ...any) {
	if s.env.Log != nil {
		_, _ = fmt.Fprintf(s.env.Log, "  %s: "+format+"\n", append([]any{s.command}, args...)...)
	}
}

// infoURL is the info API request for slug.
func (s *site) infoURL(slug string) string {
	if s.eco == core.WPTheme {
		return s.api + "/themes/info/1.2/?action=theme_information&request[slug]=" + url.QueryEscape(slug) +
			"&request[fields][versions]=1"
	}
	return s.api + "/plugins/info/1.2/?action=plugin_information&request[slug]=" + url.QueryEscape(slug) +
		"&request[fields][versions]=1&request[fields][contributors]=1"
}

// info returns the info API answer for slug. An unknown slug is E2. A
// closed plugin is an info with Closed set. Answers are kept for the
// run, so Versions, Meta and Tags ask once.
func (s *site) info(ctx context.Context, slug string) (*info, error) {
	s.mu.Lock()
	in, ok := s.infos[slug]
	s.mu.Unlock()
	if !ok {
		var err error
		if in, err = s.loadInfo(ctx, slug); err != nil {
			return nil, err
		}
		s.mu.Lock()
		s.infos[slug] = in
		s.mu.Unlock()
	}
	if in.NotFound {
		return nil, s.unknown(slug)
	}
	return in, nil
}

func (s *site) loadInfo(ctx context.Context, slug string) (*info, error) {
	var body json.RawMessage
	err := s.env.Get.JSON(ctx, s.infoURL(slug), &body, fetch.KindVersions)
	var se *fetch.StatusError
	switch {
	case errors.As(err, &se) && se.Status == http.StatusNotFound:
		// WordPress.org answers 404 for an unknown slug and for a closed
		// plugin; the JSON body says which.
		if se.Body == nil {
			return &info{NotFound: true}, nil
		}
		body = se.Body
	case err != nil:
		return nil, err
	}
	in, err := decodeInfo(body)
	if err != nil {
		return nil, fmt.Errorf("unexpected answer from wordpress.org for %s: %w", slug, err)
	}
	return in, nil
}

// versions lists the releases of in, oldest first: every key of the
// versions map WordPress can order (not "trunk") and the current version.
func versions(in *info) []string {
	out := make([]string, 0, len(in.Versions)+1)
	for v := range in.Versions {
		if version.WordPress.Valid(v) {
			out = append(out, v)
		}
	}
	if in.Version != "" && version.WordPress.Valid(in.Version) && !slices.Contains(out, in.Version) {
		out = append(out, in.Version)
	}
	slices.SortFunc(out, func(a, b string) int {
		if c := version.WordPress.Compare(a, b); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
	return out
}

// history lists up to maxHistory releases before v, newest first. The
// info API gives no release dates, so Published stays zero except for
// the current version (last_updated).
func history(in *info, all []string, v string) []core.Release {
	var out []core.Release
	for i := len(all) - 1; i >= 0 && len(out) < maxHistory; i-- {
		if version.WordPress.Compare(all[i], v) >= 0 {
			continue
		}
		r := core.Release{Version: all[i]}
		if all[i] == in.Version {
			r.Published = in.LastUpdated
		}
		out = append(out, r)
	}
	return out
}

// meta builds the Meta both sources share for slug at v. A version the
// API does not list is E3.
func (s *site) meta(ctx context.Context, ref core.Ref) (*core.Meta, *info, error) {
	in, err := s.info(ctx, ref.Name)
	if err != nil {
		return nil, nil, err
	}
	m := &core.Meta{
		Ref: ref, Homepage: in.Homepage, RequiresPHP: in.RequiresPHP,
		Latest: in.Version, Closed: in.Closed, ClosedReason: in.ClosedReason,
	}
	if ref.Version == "" && !in.Closed {
		m.Ref.Version = in.Version
	}
	v := m.Ref.Version
	if in.Closed || v == in.Version {
		// The info API describes the current release only. An older
		// version takes its contributors from its own readme
		// (metaFromTree) and its publisher from its SVN tag: given the
		// current list, a new committer would count as an old owner
		// and owner-change would never fire.
		m.Contributors = slices.Clone(in.Contributors)
		m.Author, m.AuthorProfile = in.Author, in.AuthorProfile
	}
	if in.Closed {
		// Nothing can be downloaded; run reports wporg-closed from this.
		return m, in, nil
	}
	all := versions(in)
	if !slices.Contains(all, v) {
		return nil, nil, s.noVersion(ref.Name, v, in.Version)
	}
	m.Archive.URL = s.archiveURL(ref.Name, v, in)
	m.History = history(in, all, v)
	if v == in.Version {
		m.Published = in.LastUpdated
	}
	if p, at := s.creator(ctx, ref.Name, v); p != nil {
		m.Publisher = p
		if !at.IsZero() {
			m.Published = at
		}
	}
	return m, in, nil
}

// archiveURL is the zip of slug at v. A current version missing from the
// versions map ("Stable tag: trunk") is served as <slug>.zip.
func (s *site) archiveURL(slug, v string, in *info) string {
	kind := "plugin"
	if s.eco == core.WPTheme {
		kind = "theme"
	}
	if _, ok := in.Versions[v]; !ok && v == in.Version {
		return s.dl + "/" + kind + "/" + url.PathEscape(slug) + ".zip"
	}
	return s.dl + "/" + kind + "/" + url.PathEscape(slug+"."+v) + ".zip"
}

// tags is {"latest": the info API version}: the release WordPress
// offers, whatever the readme's Stable tag says.
func (s *site) tags(ctx context.Context, slug string) (map[string]string, error) {
	in, err := s.info(ctx, slug)
	if err != nil {
		return nil, err
	}
	if in.Closed || in.Version == "" {
		return map[string]string{}, nil
	}
	return map[string]string{"latest": in.Version}, nil
}

// pkg names slug at v for fetch.Package.Wrap.
func (s *site) pkg(slug, v string) fetch.Package {
	return fetch.Package{Command: s.command, Name: slug, Version: v, Archive: "zip"}
}

// unknown is E2 for a slug WordPress.org does not know, with a near
// popular name from the names pack when there is one.
func (s *site) unknown(slug string) *core.Error {
	hint := "A premium " + s.command + " has no official source: use --to-file <zip>"
	if near := s.suggest(slug); near != "" {
		hint = "did you mean " + near + "? " + hint
	}
	return &core.Error{
		Code: core.EUnknownPackage, Exit: cli.ExitUsage, Command: s.command,
		What: fmt.Sprintf("wordpress.org has no %s %q", s.command, slug),
		Hint: []string{hint},
	}
}

func (s *site) suggest(slug string) string {
	packs := core.GetDataPacks()
	if packs == nil {
		return ""
	}
	names := packs.Names()
	if names == nil {
		return ""
	}
	return cli.Suggest(slug, names.Near(s.eco, slug))
}

// noVersion is E3.
func (s *site) noVersion(slug, v, newest string) *core.Error {
	list := "see them all: " + cli.Name() + " " + s.command + " " + slug + " --to list"
	hint := list
	if newest != "" {
		hint = "newest: " + newest + " · " + list
	}
	return &core.Error{
		Code: core.EVersionMissing, Exit: cli.ExitUsage, Command: s.command,
		What: fmt.Sprintf("%s has no version %s on wordpress.org", slug, v),
		Hint: []string{hint},
	}
}

// closedError is what Fetch says for a closed package. run reports
// wporg-closed from Meta and never asks for its archive.
func (s *site) closedError(m *core.Meta) *core.Error {
	return &core.Error{
		Code: core.EVersionMissing, Exit: cli.ExitUsage, Command: s.command,
		What: fmt.Sprintf("%s is closed on wordpress.org (%s); there is nothing to download", m.Ref.Name, m.ClosedReason),
		Hint: []string{"the wporg-closed finding says why; give a copy you trust with --to-file <zip>"},
	}
}

// propfind asks the SVN server for url's properties at depth, through
// the Getter's DAV support when it has it.
func (s *site) propfind(ctx context.Context, u string, depth int) ([]byte, error) {
	if d, ok := s.env.Get.(fetch.DAV); ok {
		return d.Propfind(ctx, u, depth, fetch.KindMeta, s.lim.JSON)
	}
	body, _, err := s.env.Get.Text(ctx, "PROPFIND", u, strings.NewReader(fetch.PropfindBody), s.lim.JSON)
	return body, err
}

// svnFolder is the URL of slug's folder for v: tags/<v>/ for a
// plugin, <v>/ for a theme.
func (s *site) svnFolder(slug, v string) string {
	if s.eco == core.WPTheme {
		return s.svn + "/" + url.PathEscape(slug) + "/" + url.PathEscape(v) + "/"
	}
	return s.svn + "/" + url.PathEscape(slug) + "/tags/" + url.PathEscape(v) + "/"
}
