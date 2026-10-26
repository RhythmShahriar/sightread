// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

import (
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/RhythmShahriar/sightread/testbed/ports"
)

// packagistMux routes the p2 metadata and the maintainers endpoint.
func (r *Registry) packagistMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/p2/", r.p2)
	mux.HandleFunc("/packages/", r.pkgMeta)
	mux.HandleFunc("/packages.json", r.composerPackagesJSON)
	mux.HandleFunc("/api/security-advisories/", r.composerAdvisories)
	return mux
}

// p2 serves /p2/<vendor>/<name>.json (and ~dev.json) in the minified
// composer/2.0 format: versions newest first, each carrying only the
// fields that changed from the one before it.
func (r *Registry) p2(w http.ResponseWriter, req *http.Request) {
	rest := strings.TrimPrefix(req.URL.Path, "/p2/")
	rest = strings.TrimSuffix(rest, ".json")
	dev := strings.HasSuffix(rest, "~dev")
	rest = strings.TrimSuffix(rest, "~dev")
	p, ok := r.find("composer", rest)
	if !ok {
		http.NotFound(w, req)
		return
	}
	full := r.composerVersions(p, req, dev)
	writeJSON(w, http.StatusOK, map[string]any{
		"minified": "composer/2.0",
		"packages": map[string]any{rest: minify(full)},
	})
}

// composerVersions builds the full version objects newest first. The
// ~dev file carries dev branches; this testbed publishes only tagged
// versions, so ~dev is an empty list.
func (r *Registry) composerVersions(p *builtPkg, req *http.Request, dev bool) []map[string]any {
	if dev {
		return nil
	}
	owner, repo := ownerRepo(p.meta.Repository)
	var out []map[string]any
	versions := r.publishedVersions(p)
	for i := len(versions) - 1; i >= 0; i-- {
		v := versions[i]
		bv := p.versions[v]
		dist := map[string]any{
			"type":      "zip",
			"url":       r.githubBase(req) + "/repos/" + owner + "/" + repo + "/zipball/" + bv.meta.Reference,
			"reference": bv.meta.Reference,
		}
		if bv.meta.Shasum == nil || *bv.meta.Shasum {
			dist["shasum"] = bv.shasum
		} else {
			dist["shasum"] = ""
		}
		obj := map[string]any{
			"name":               p.meta.Name,
			"version":            v,
			"version_normalized": normalizeComposer(v),
			"source": map[string]any{
				"type":      "git",
				"url":       "https://" + p.meta.Repository + ".git",
				"reference": bv.meta.Reference,
			},
			"dist": dist,
			"time": bv.published.Format("2006-01-02T15:04:05-07:00"),
			"type": composerType(bv),
		}
		out = append(out, obj)
	}
	return out
}

// composerType returns the Composer package type of a version.
func composerType(bv *builtVersion) string {
	if bv.meta.ComposerType != "" {
		return bv.meta.ComposerType
	}
	return "library"
}

// githubBase is the configured GitHub API base this run uses. Composer
// dist URLs point at it; Sightread follows them through the
// allowlisted redirect to codeload.
func (r *Registry) githubBase(req *http.Request) string {
	scheme := "https"
	if r.opts.PlainHTTP {
		scheme = "http"
	}
	host, _, _ := strings.Cut(req.Host, ":")
	return scheme + "://" + host + ":" + strconv.Itoa(r.Port(ports.GitHub))
}

// normalizeComposer turns "1.2.3" into Composer's "1.2.3.0" normalized
// form, enough for the shape the fetch lane reads.
func normalizeComposer(v string) string {
	v = strings.TrimPrefix(v, "v")
	parts := strings.Split(v, ".")
	for len(parts) < 4 {
		parts = append(parts, "0")
	}
	return strings.Join(parts[:4], ".")
}

// pkgMeta serves /packages/<vendor>/<name>.json with maintainers and the
// abandoned flag.
func (r *Registry) pkgMeta(w http.ResponseWriter, req *http.Request) {
	rest := strings.TrimPrefix(req.URL.Path, "/packages/")
	rest = strings.TrimSuffix(rest, ".json")
	p, ok := r.find("composer", rest)
	if !ok {
		http.NotFound(w, req)
		return
	}
	cv, _ := p.meta.CandidateVersion()
	var maints []map[string]string
	for _, m := range cv.Maintainers {
		maints = append(maints, map[string]string{"name": m})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"package": map[string]any{
			"name":        rest,
			"maintainers": maints,
			"abandoned":   false,
			"repository":  "https://" + p.meta.Repository,
		},
	})
}

// minify turns full version objects (newest first) into the minified
// composer/2.0 form: each version lists only the fields that differ from
// the previous one, with "__unset" naming fields that were removed.
func minify(versions []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(versions))
	var prev map[string]any
	for _, v := range versions {
		if prev == nil {
			out = append(out, v)
			prev = v
			continue
		}
		delta := map[string]any{"version": v["version"]}
		var unset []string
		for k, val := range v {
			if k == "version" {
				continue
			}
			if pv, ok := prev[k]; !ok || !reflect.DeepEqual(pv, val) {
				delta[k] = val
			}
		}
		for k := range prev {
			if _, ok := v[k]; !ok {
				unset = append(unset, k)
			}
		}
		if len(unset) > 0 {
			delta["__unset"] = unset
		}
		out = append(out, delta)
		prev = v
	}
	return out
}
