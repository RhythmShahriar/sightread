// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

import (
	"net/http"
	"strings"
)

// npmMux routes the packuments, the per-version documents, the tarballs
// and the signing keys.
func (r *Registry) npmMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/-/npm/v1/keys", r.npmKeys)
	mux.HandleFunc("/", r.npmRoot)
	return mux
}

// npmKeys serves the per-run public signing key.
func (r *Registry) npmKeys(w http.ResponseWriter, _ *http.Request) {
	doc, err := r.npm.keysDoc()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, doc)
}

// npmRoot dispatches the packument, the per-version document and the
// tarball by path shape.
func (r *Registry) npmRoot(w http.ResponseWriter, req *http.Request) {
	rest := strings.TrimPrefix(req.URL.Path, "/")
	if rest == "" {
		http.NotFound(w, req)
		return
	}
	name, tail := npmNamePath(rest)
	p, ok := r.find("npm", name)
	if !ok {
		http.NotFound(w, req)
		return
	}
	switch {
	case tail == "":
		r.packument(w, req, p)
	case strings.HasPrefix(tail, "-/"):
		r.tarball(w, req, p, strings.TrimPrefix(tail, "-/"))
	default:
		r.npmVersion(w, req, p, tail)
	}
}

// npmNamePath splits an npm request path into the package name and the
// rest, allowing for a leading @scope.
func npmNamePath(rest string) (name, tail string) {
	if strings.HasPrefix(rest, "@") {
		scope, after, ok := strings.Cut(rest, "/")
		if !ok {
			return rest, ""
		}
		pkg, tail, ok := strings.Cut(after, "/")
		if !ok {
			return scope + "/" + after, ""
		}
		return scope + "/" + pkg, tail
	}
	name, tail, _ = strings.Cut(rest, "/")
	return name, tail
}

// packument serves the abbreviated or full packument. The abbreviated
// form (Accept vnd.npm.install-v1+json) carries dist, dependencies and
// scripts flags; the full form adds maintainers, _npmUser and the time
// map.
func (r *Registry) packument(w http.ResponseWriter, req *http.Request, p *builtPkg) {
	abbreviated := strings.Contains(req.Header.Get("Accept"), "install-v1")
	versions := map[string]any{}
	times := map[string]string{"created": p.versions[p.installed].published.Format(timeFmt)}
	for _, v := range r.publishedVersions(p) {
		bv := p.versions[v]
		versions[v] = r.versionDoc(req, p, bv, abbreviated)
		times[v] = bv.published.Format(timeFmt)
	}
	times["modified"] = p.versions[r.latestVersion(p)].published.Format(timeFmt)
	doc := map[string]any{
		"name":      p.meta.Name,
		"dist-tags": map[string]string{"latest": r.latestVersion(p)},
		"versions":  versions,
		"modified":  times["modified"],
	}
	if !abbreviated {
		doc["time"] = times
		doc["maintainers"] = npmPeople(p.versions[r.latestVersion(p)].meta.Maintainers)
	}
	writeJSON(w, http.StatusOK, doc)
}

// npmVersion serves /<name>/<version>: the full per-version document.
func (r *Registry) npmVersion(w http.ResponseWriter, req *http.Request, p *builtPkg, version string) {
	bv, ok := r.servedVersion(p, version)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "version not found: unpublished"})
		return
	}
	writeJSON(w, http.StatusOK, r.versionDoc(req, p, bv, false))
}

// versionDoc builds one version object. Abbreviated leaves out the owner
// facts (_npmUser, maintainers) that only the full document carries.
func (r *Registry) versionDoc(req *http.Request, p *builtPkg, bv *builtVersion, abbreviated bool) map[string]any {
	scheme := "https"
	if r.opts.PlainHTTP {
		scheme = "http"
	}
	tarball := scheme + "://" + req.Host + "/" + p.meta.Name + "/-/" + tarballName(p.meta.Name, bv.meta.Version)
	dist := map[string]any{
		"tarball":    tarball,
		"integrity":  bv.integrity,
		"shasum":     "",
		"signatures": []map[string]string{{"keyid": r.npm.keyID, "sig": bv.signature}},
	}
	if bv.meta.Provenance == "slsa" {
		dist["attestations"] = map[string]any{
			"url":        tarball + ".attestations",
			"provenance": map[string]string{"predicateType": "https://slsa.dev/provenance/v1"},
		}
	}
	doc := map[string]any{
		"name":    p.meta.Name,
		"version": bv.meta.Version,
		"dist":    dist,
	}
	if len(bv.meta.Scripts) > 0 {
		doc["scripts"] = bv.meta.Scripts
		for k := range bv.meta.Scripts {
			if k == "install" || k == "preinstall" || k == "postinstall" {
				doc["hasInstallScript"] = true
			}
		}
	}
	if !abbreviated {
		doc["_npmUser"] = oneNPMUser(bv.meta.Maintainers)
		doc["maintainers"] = npmPeople(bv.meta.Maintainers)
	}
	return doc
}

// tarball serves the tgz for /<name>/-/<file>.tgz.
func (r *Registry) tarball(w http.ResponseWriter, req *http.Request, p *builtPkg, file string) {
	for _, v := range r.publishedVersions(p) {
		if tarballName(p.meta.Name, v) == file {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(p.versions[v].archive)
			return
		}
	}
	http.NotFound(w, req)
}

// tarballName is the npm tarball file name: the unscoped name plus the
// version.
func tarballName(name, version string) string {
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	return name + "-" + version + ".tgz"
}

// npmPeople turns login names into npm maintainer objects.
func npmPeople(names []string) []map[string]string {
	out := make([]map[string]string, 0, len(names))
	for _, n := range names {
		out = append(out, map[string]string{"name": n, "email": n + "@users.noreply.npmjs.example"})
	}
	return out
}

// oneNPMUser returns the _npmUser (the publisher) of a version.
func oneNPMUser(names []string) map[string]string {
	if len(names) == 0 {
		return map[string]string{"name": "unknown"}
	}
	return map[string]string{"name": names[0], "email": names[0] + "@users.noreply.npmjs.example"}
}

// timeFmt is the npm packument time format.
const timeFmt = "2006-01-02T15:04:05.000Z"
