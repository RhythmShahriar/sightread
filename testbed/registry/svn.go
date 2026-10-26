// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

import (
	"encoding/xml"
	"fmt"
	"net/http"
	"strings"
)

// svnPlugins answers a PROPFIND on
// /svn/plugins/<slug>/tags/<v>/ with the tag creator, the owner fact
// Sightread reads for the publisher of a WordPress.org plugin version.
func (r *Registry) svnPlugins(w http.ResponseWriter, req *http.Request) {
	rest := strings.TrimPrefix(req.URL.Path, "/svn/plugins/")
	slug, _, after, ok := cut3(rest, "/tags/")
	if !ok {
		http.NotFound(w, req)
		return
	}
	version := strings.Trim(after, "/")
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
	if req.Method != "PROPFIND" {
		http.Error(w, "use PROPFIND", http.StatusMethodNotAllowed)
		return
	}
	writeMultiStatus(w, []davEntry{{href: req.URL.Path, collection: true, creator: committer(bv)}})
}

// svnThemes answers PROPFIND and GET under /svn/themes/<slug>/<v>/ so the
// theme file list and each file can be checked against the download when
// --svn-check is on.
func (r *Registry) svnThemes(w http.ResponseWriter, req *http.Request) {
	rest := strings.TrimPrefix(req.URL.Path, "/svn/themes/")
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) < 2 {
		http.NotFound(w, req)
		return
	}
	slug, version := parts[0], parts[1]
	filePath := ""
	if len(parts) == 3 {
		filePath = parts[2]
	}
	p, ok := r.find("wp-theme", slug)
	if !ok {
		http.NotFound(w, req)
		return
	}
	bv, ok := r.servedVersion(p, version)
	if !ok {
		http.NotFound(w, req)
		return
	}
	if req.Method == "PROPFIND" {
		base := fmt.Sprintf("/svn/themes/%s/%s/", slug, version)
		entries := []davEntry{{href: base, collection: true, creator: committer(bv)}}
		for _, f := range bv.files {
			entries = append(entries, davEntry{href: base + f.Name, size: int64(len(f.Data))})
		}
		writeMultiStatus(w, entries)
		return
	}
	if filePath == "" {
		http.NotFound(w, req)
		return
	}
	for _, f := range bv.files {
		if f.Name == strings.TrimSuffix(filePath, "/") {
			_, _ = w.Write(f.Data)
			return
		}
	}
	http.NotFound(w, req)
}

// committer returns the SVN tag creator of a version, falling back to the
// author so a scenario that sets neither still answers.
func committer(bv *builtVersion) string {
	if bv.meta.Committer != "" {
		return bv.meta.Committer
	}
	return bv.meta.Author
}

// cut3 splits s at sep into before and after, also returning the first
// path segment of before.
func cut3(s, sep string) (first, before, after string, ok bool) {
	before, after, ok = strings.Cut(s, sep)
	if !ok {
		return "", "", "", false
	}
	first = before
	if i := strings.IndexByte(before, '/'); i >= 0 {
		first = before[:i]
	}
	return first, before, after, true
}

// davEntry is one entry of a WebDAV multistatus response.
type davEntry struct {
	href       string
	collection bool
	creator    string
	size       int64
}

// WebDAV multistatus XML, trimmed to the fields Sightread reads: the
// creator-displayname property and the resource type.
type multistatus struct {
	XMLName   xml.Name      `xml:"D:multistatus"`
	XMLNSD    string        `xml:"xmlns:D,attr"`
	Responses []davResponse `xml:"D:response"`
}

type davResponse struct {
	Href     string      `xml:"D:href"`
	Propstat davPropstat `xml:"D:propstat"`
}

type davPropstat struct {
	Prop   davProp `xml:"D:prop"`
	Status string  `xml:"D:status"`
}

type davProp struct {
	ResourceType *struct {
		Collection *struct{} `xml:"D:collection"`
	} `xml:"D:resourcetype,omitempty"`
	CreatorDisplayName string `xml:"D:creator-displayname,omitempty"`
	ContentLength      int64  `xml:"D:getcontentlength,omitempty"`
}

// writeMultiStatus renders entries as a 207 Multi-Status body.
func writeMultiStatus(w http.ResponseWriter, entries []davEntry) {
	ms := multistatus{XMLNSD: "DAV:"}
	for _, e := range entries {
		var prop davProp
		if e.collection {
			prop.ResourceType = &struct {
				Collection *struct{} `xml:"D:collection"`
			}{Collection: &struct{}{}}
			prop.CreatorDisplayName = e.creator
		} else {
			prop.ContentLength = e.size
		}
		ms.Responses = append(ms.Responses, davResponse{
			Href:     e.href,
			Propstat: davPropstat{Prop: prop, Status: "HTTP/1.1 200 OK"},
		})
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(ms)
}
