// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

import (
	"encoding/json"
	"net/http"
	"strings"
)

// osvMux routes the OSV querybatch and vulns endpoints.
func (r *Registry) osvMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/querybatch", r.osvQueryBatch)
	mux.HandleFunc("/v1/vulns/", r.osvVuln)
	return mux
}

// osvEcosystem maps a Sightread ecosystem to the OSV ecosystem name.
func osvEcosystem(eco string) string {
	switch eco {
	case "npm":
		return "npm"
	case "composer":
		return "Packagist"
	}
	return ""
}

// advisoryHits returns the advisory ids that affect a package version in
// the current state. An id that starts with MAL- is a malicious record.
func (r *Registry) advisoryHits(eco, name, version string) []string {
	p, ok := r.find(eco, name)
	if !ok {
		return nil
	}
	bv, ok := r.servedVersion(p, version)
	if !ok {
		if b, present := p.versions[version]; present {
			bv = b
		} else {
			return nil
		}
	}
	return bv.meta.Advisories
}

// osvQueryBatch answers a batch of (package, version) queries with the
// matching vuln ids, in request order.
func (r *Registry) osvQueryBatch(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Queries []struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
			} `json:"package"`
			Version string `json:"version"`
		} `json:"queries"`
	}
	if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	results := make([]map[string]any, len(body.Queries))
	for i, q := range body.Queries {
		eco := sightreadEco(q.Package.Ecosystem)
		var vulns []map[string]string
		for _, id := range r.advisoryHits(eco, q.Package.Name, q.Version) {
			vulns = append(vulns, map[string]string{"id": id, "modified": r.opts.Now.Format(timeFmt)})
		}
		if len(vulns) == 0 {
			results[i] = map[string]any{}
			continue
		}
		results[i] = map[string]any{"vulns": vulns}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// sightreadEco maps an OSV ecosystem name back to a Sightread ecosystem.
func sightreadEco(osv string) string {
	switch osv {
	case "npm":
		return "npm"
	case "Packagist":
		return "composer"
	}
	return ""
}

// osvVuln serves one vuln record by id.
func (r *Registry) osvVuln(w http.ResponseWriter, req *http.Request) {
	id := strings.TrimPrefix(req.URL.Path, "/v1/vulns/")
	for _, p := range r.pkgs {
		eco := osvEcosystem(p.meta.Ecosystem)
		if eco == "" {
			continue
		}
		for _, v := range p.order {
			bv := p.versions[v]
			for _, a := range bv.meta.Advisories {
				if a != id {
					continue
				}
				writeJSON(w, http.StatusOK, r.vulnRecord(id, p, eco))
				return
			}
		}
	}
	writeJSON(w, http.StatusNotFound, map[string]any{"message": "not found"})
}

// vulnRecord builds an OSV record naming the affected versions.
func (r *Registry) vulnRecord(id string, p *builtPkg, eco string) map[string]any {
	var affectedVersions []string
	for _, v := range p.order {
		for _, a := range p.versions[v].meta.Advisories {
			if a == id {
				affectedVersions = append(affectedVersions, v)
			}
		}
	}
	summary := "Advisory " + id
	if strings.HasPrefix(id, "MAL-") {
		summary = "Malicious code in " + p.meta.Name
	}
	return map[string]any{
		"id":       id,
		"summary":  summary,
		"modified": r.opts.Now.Format(timeFmt),
		"affected": []map[string]any{{
			"package":  map[string]string{"name": p.meta.Name, "ecosystem": eco},
			"versions": affectedVersions,
		}},
	}
}
