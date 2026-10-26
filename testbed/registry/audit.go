// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// The advisory endpoints the compared tools read: npm audit posts to the
// npm bulk endpoint and composer audit asks the Composer repository's
// security-advisories API. Both answer from the same meta.yaml
// advisories that OSV serves, so every tool sees the same published
// records. A fresh malicious update has none, which is the point the
// benchmark makes about advisory-only tools.

// maxAuditBody bounds what the bulk endpoint reads.
const maxAuditBody = 1 << 20

// npmAuditBulk answers POST /-/npm/v1/security/advisories/bulk: the body
// maps package names to the versions in the lockfile (npm gzips it); the
// answer maps each name to the advisories that affect one of them.
func (r *Registry) npmAuditBulk(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	body := io.LimitReader(req.Body, maxAuditBody)
	if strings.EqualFold(req.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(body)
		if err != nil {
			http.Error(w, "bad gzip body", http.StatusBadRequest)
			return
		}
		defer func() { _ = zr.Close() }()
		body = io.LimitReader(zr, maxAuditBody)
	}
	var asked map[string][]string
	if err := json.NewDecoder(body).Decode(&asked); err != nil {
		http.Error(w, "bad JSON body", http.StatusBadRequest)
		return
	}
	out := map[string][]map[string]any{}
	n := 0
	for name, versions := range asked {
		for _, v := range versions {
			for _, id := range r.advisoryHits("npm", name, v) {
				n++
				out[name] = append(out[name], map[string]any{
					"id":                  1000 + n,
					"url":                 "https://osv.dev/vulnerability/" + id,
					"title":               id,
					"severity":            "critical",
					"vulnerable_versions": "=" + v,
					"cwe":                 []string{"CWE-506"},
					"cvss":                map[string]any{"score": 0, "vectorString": nil},
				})
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// composerPackagesJSON serves the Composer repository root, which points
// Composer at the p2 metadata and the security-advisories API.
func (r *Registry) composerPackagesJSON(w http.ResponseWriter, req *http.Request) {
	scheme := "https"
	if r.opts.PlainHTTP {
		scheme = "http"
	}
	var names []string
	for _, p := range r.pkgs {
		if p.meta.Ecosystem == "composer" {
			names = append(names, p.meta.Name)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"packages":           []any{},
		"metadata-url":       "/p2/%package%.json",
		"available-packages": names,
		"security-advisories": map[string]any{
			"metadata": false,
			"api-url":  scheme + "://" + req.Host + "/api/security-advisories/",
		},
	})
}

// composerAdvisories answers the security-advisories API: packages[] in
// the query or the form names the packages; every advisory of any
// version of each is returned with its affected version, as Packagist
// does.
func (r *Registry) composerAdvisories(w http.ResponseWriter, req *http.Request) {
	if err := req.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	out := map[string][]map[string]any{}
	n := 0
	for _, name := range req.Form["packages[]"] {
		p, ok := r.find("composer", name)
		if !ok {
			continue
		}
		for _, v := range r.publishedVersions(p) {
			for _, id := range r.advisoryHits("composer", name, v) {
				n++
				out[name] = append(out[name], map[string]any{
					"advisoryId":         "PKSA-" + strconv.Itoa(1000+n),
					"packageName":        name,
					"remoteId":           id,
					"title":              id,
					"link":               "https://osv.dev/vulnerability/" + id,
					"cve":                nil,
					"affectedVersions":   fmt.Sprintf("==%s", v),
					"source":             "testbed",
					"reportedAt":         "2026-01-01 00:00:00",
					"composerRepository": "https://packagist.org",
					"severity":           "critical",
					"sources":            []map[string]string{{"name": "testbed", "remoteId": id}},
				})
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"advisories": out})
}
