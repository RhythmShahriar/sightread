// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/RhythmShahriar/sightread/testbed/ports"
)

// CodeloadHost is the host name the zipball redirect points at. It is
// the second GitHub host name: the API is reached as 127.0.0.1 and
// codeload as localhost, both served on loopback and both covered by the
// per-run certificate.
const CodeloadHost = "localhost"

// githubMux routes the zipball redirect, the git ref lookup and the rate
// limit endpoint. The zipball itself is served by the codeload listener,
// one redirect hop away, as the real GitHub does.
func (r *Registry) githubMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/repos/", r.githubRepos)
	mux.HandleFunc("/rate_limit", r.rateLimit)
	return mux
}

// githubRepos handles /repos/<o>/<r>/zipball/<ref> and
// /repos/<o>/<r>/git/ref/tags/<t>.
func (r *Registry) githubRepos(w http.ResponseWriter, req *http.Request) {
	rest := strings.TrimPrefix(req.URL.Path, "/repos/")
	owner, after, ok := strings.Cut(rest, "/")
	if !ok {
		http.NotFound(w, req)
		return
	}
	repo, tail, ok := strings.Cut(after, "/")
	if !ok {
		http.NotFound(w, req)
		return
	}
	switch {
	case strings.HasPrefix(tail, "zipball/"):
		ref := strings.TrimPrefix(tail, "zipball/")
		scheme := "https"
		if r.opts.PlainHTTP {
			scheme = "http"
		}
		// The target names localhost, not the 127.0.0.1 the API is reached
		// on: a client copies Authorization across a redirect when the
		// host name matches whatever the port, so only a second host name
		// shows whether Sightread keeps GITHUB_TOKEN off codeload.
		loc := scheme + "://" + CodeloadHost + ":" + strconv.Itoa(r.Port(ports.Codeload)) + "/" + owner + "/" + repo + "/legacy.zip/" + ref
		http.Redirect(w, req, loc, http.StatusFound) //nolint:gosec // loopback testbed; the target is our own codeload listener
	case strings.HasPrefix(tail, "git/ref/tags/"):
		r.gitRef(w, req, owner, repo, strings.TrimPrefix(tail, "git/ref/tags/"))
	default:
		http.NotFound(w, req)
	}
}

// gitRef answers a tag lookup: 200 with the commit when the version has a
// matching tag, 404 otherwise.
func (r *Registry) gitRef(w http.ResponseWriter, req *http.Request, owner, repo, tag string) {
	p, ok := r.findGitHub(owner, repo)
	if !ok {
		http.NotFound(w, req)
		return
	}
	for _, v := range r.publishedVersions(p) {
		bv := p.versions[v]
		if bv.meta.GitTag != nil && !*bv.meta.GitTag {
			continue
		}
		for _, form := range []string{"v" + v, v, p.meta.Name + "@" + v} {
			if form == tag {
				writeJSON(w, http.StatusOK, map[string]any{
					"ref": "refs/tags/" + tag,
					"object": map[string]any{
						"sha":  bv.meta.Reference,
						"type": "commit",
					},
				})
				return
			}
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]any{"message": "Not Found"})
}

// rateLimit answers with a budget the testbed never exhausts.
func (r *Registry) rateLimit(w http.ResponseWriter, _ *http.Request) {
	core := map[string]any{"limit": 5000, "remaining": 4999, "reset": r.opts.Now.Add(time.Hour).Unix()}
	writeJSON(w, http.StatusOK, map[string]any{
		"resources": map[string]any{"core": core},
		"rate":      core,
	})
}

// codeloadMux serves the zip a zipball redirect points at.
func (r *Registry) codeloadMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", r.codeload)
	return mux
}

// codeload serves /<o>/<r>/legacy.zip/<ref> with the Composer archive.
func (r *Registry) codeload(w http.ResponseWriter, req *http.Request) {
	rest := strings.TrimPrefix(req.URL.Path, "/")
	owner, after, ok := strings.Cut(rest, "/")
	if !ok {
		http.NotFound(w, req)
		return
	}
	repo, tail, ok := strings.Cut(after, "/legacy.zip/")
	if !ok {
		http.NotFound(w, req)
		return
	}
	ref := tail
	p, ok := r.findGitHub(owner, repo)
	if !ok {
		http.NotFound(w, req)
		return
	}
	for _, v := range r.publishedVersions(p) {
		bv, ok := r.servedVersion(p, v)
		if !ok {
			continue
		}
		if bv.meta.Reference == ref {
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(r.servedArchive(p, bv))
			return
		}
	}
	http.NotFound(w, req)
}
