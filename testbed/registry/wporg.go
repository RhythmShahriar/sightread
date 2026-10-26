// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"
)

// wporgMux routes the WordPress.org info API, the downloads host, the
// per-file checksums and the SVN endpoints, all under one listener.
func (r *Registry) wporgMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/plugins/info/1.2/", r.wpInfo("wp-plugin"))
	mux.HandleFunc("/themes/info/1.2/", r.wpInfo("wp-theme"))
	mux.HandleFunc("/plugin/", r.wpDownload("wp-plugin", "/plugin/"))
	mux.HandleFunc("/theme/", r.wpDownload("wp-theme", "/theme/"))
	mux.HandleFunc("/plugin-checksums/", r.wpChecksums)
	mux.HandleFunc("/svn/plugins/", r.svnPlugins)
	mux.HandleFunc("/svn/themes/", r.svnThemes)
	return mux
}

// baseURL is the external base of this request, e.g.
// "https://127.0.0.1:18900".
func (r *Registry) baseURL(req *http.Request) string {
	scheme := "https"
	if r.opts.PlainHTTP {
		scheme = "http"
	}
	return scheme + "://" + req.Host
}

// wpInfo serves the plugin or theme information API.
func (r *Registry) wpInfo(eco string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		slug := req.URL.Query().Get("request[slug]")
		p, ok := r.find(eco, slug)
		if !ok {
			writeJSON(w, http.StatusOK, map[string]any{"error": "Plugin not found."})
			return
		}
		if p.meta.Closed {
			writeJSON(w, http.StatusOK, map[string]any{
				"slug":   slug,
				"name":   slug,
				"closed": true,
				"reason": p.meta.ClosedReason,
				"error":  p.meta.ClosedReason,
			})
			return
		}
		latest := r.latestVersion(p)
		lv := p.versions[latest]
		versions := map[string]string{}
		for _, v := range r.publishedVersions(p) {
			versions[v] = fmt.Sprintf("%s/%s/%s.%s.zip", r.baseURL(req), strings.TrimPrefix(eco, "wp-"), slug, v)
		}
		contributors := map[string]any{}
		for _, c := range lv.meta.Contributors {
			contributors[c] = map[string]string{"profile": "https://profiles.wordpress.org/" + c}
		}
		resp := map[string]any{
			"name":           slug,
			"slug":           slug,
			"version":        latest,
			"author":         lv.meta.Author,
			"author_profile": "https://profiles.wordpress.org/" + lv.meta.Author,
			"contributors":   contributors,
			"requires":       "6.0",
			"tested":         "6.8",
			"requires_php":   "7.4",
			"last_updated":   lv.published.Format("2006-01-02 3:04pm MST"),
			"added":          p.versions[p.installed].published.Format("2006-01-02"),
			"download_link":  versions[latest],
			"versions":       versions,
			"sections":       map[string]string{"changelog": changelogHTML(p, r.publishedVersions(p))},
			"download_count": 12345,
		}
		writeJSON(w, http.StatusOK, resp)
	}
}

// changelogHTML renders a readme-style changelog block newest first.
func changelogHTML(p *builtPkg, versions []string) string {
	var b strings.Builder
	for i := len(versions) - 1; i >= 0; i-- {
		b.WriteString("<h4>" + versions[i] + "</h4>\n")
		b.WriteString("<ul><li>See the release notes.</li></ul>\n")
	}
	return b.String()
}

// wpDownload serves a plugin or theme zip from /plugin/<slug>.<v>.zip.
func (r *Registry) wpDownload(eco, prefix string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		name := strings.TrimPrefix(req.URL.Path, prefix)
		slug, version, ok := splitSlugVersion(name)
		if !ok {
			http.NotFound(w, req)
			return
		}
		p, ok := r.find(eco, slug)
		if !ok {
			http.NotFound(w, req)
			return
		}
		bv, ok := r.servedVersion(p, version)
		if !ok {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(r.servedArchive(p, bv))
	}
}

// servedVersion returns the built version offered for a version number
// in the current state. A republished version serves its fresh bytes in
// the bad state and its original bytes in the good state; an ordinary
// candidate is withheld in the good state.
func (r *Registry) servedVersion(p *builtPkg, version string) (*builtVersion, bool) {
	bv, ok := p.versions[version]
	if !ok {
		return nil, false
	}
	if p.republishAlt != nil && version == p.installed {
		if r.state(p.id) == StateBad {
			return p.republishAlt, true
		}
		return bv, true
	}
	if version == p.candidate && r.state(p.id) == StateGood {
		// Good state: the candidate number is not published.
		return nil, false
	}
	return bv, true
}

// servedArchive returns the archive bytes to serve for a version,
// substituting the tampered bytes in the bad state when the meta asks.
func (r *Registry) servedArchive(p *builtPkg, bv *builtVersion) []byte {
	if bv.meta.Tamper && bv.tampered != nil && r.state(p.id) == StateBad {
		return bv.tampered
	}
	return bv.archive
}

// splitSlugVersion splits "akismet.5.3.5.zip" into slug and version.
func splitSlugVersion(name string) (slug, version string, ok bool) {
	name = strings.TrimSuffix(name, ".zip")
	i := strings.IndexByte(name, '.')
	if i < 0 {
		return "", "", false
	}
	return name[:i], name[i+1:], true
}

// wpChecksums serves /plugin-checksums/<slug>/<v>.json.
func (r *Registry) wpChecksums(w http.ResponseWriter, req *http.Request) {
	rest := strings.TrimPrefix(req.URL.Path, "/plugin-checksums/")
	slug, file := path.Split(rest)
	slug = strings.Trim(slug, "/")
	version := strings.TrimSuffix(file, ".json")
	p, ok := r.find("wp-plugin", slug)
	if !ok {
		http.NotFound(w, req)
		return
	}
	bv, ok := r.servedVersion(p, version)
	if !ok {
		http.NotFound(w, req)
		return
	}
	files := map[string]map[string]string{}
	for pth, sum := range bv.checksums {
		files[pth] = map[string]string{"sha256": sum}
	}
	writeJSON(w, http.StatusOK, map[string]any{"plugin": slug, "version": version, "files": files})
}

// writeJSON writes v as JSON with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
