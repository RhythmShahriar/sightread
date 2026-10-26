// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package packagist

import (
	"bytes"
	"encoding/json"
	"maps"
	"strings"
	"time"
)

// minified is the "minified" value of a p2 answer whose versions inherit
// from the one before (https://packagist.org/apidoc).
const minified = "composer/2.0"

// unset is the value that removes an inherited key in a minified answer.
var unset = []byte(`"__unset"`)

// Expand turns the versions of a minified composer/2.0 answer into
// independent maps, as Composer's MetadataMinifier::expand does: the
// first version is complete, each later one lists only the keys that
// changed; a key set to "__unset" is dropped. Every returned map is
// its own copy, so changing one never changes another.
func Expand(versions []map[string]json.RawMessage) []map[string]json.RawMessage {
	out := make([]map[string]json.RawMessage, 0, len(versions))
	var cur map[string]json.RawMessage
	for _, v := range versions {
		if cur == nil {
			cur = map[string]json.RawMessage{}
		} else {
			cur = maps.Clone(cur)
		}
		for k, val := range v {
			if bytes.Equal(bytes.TrimSpace(val), unset) {
				delete(cur, k)
				continue
			}
			cur[k] = val
		}
		out = append(out, cur)
	}
	return out
}

// p2Doc is a p2 answer: the versions of each package by lower-case name.
type p2Doc struct {
	Packages map[string][]map[string]json.RawMessage `json:"packages"`
	Minified string                                  `json:"minified"`
}

// release is one version as a p2 answer describes it. Fields of an
// unexpected type are left empty: one odd field must not hide a
// release.
type release struct {
	Version     string
	Time        time.Time
	Type        string
	License     string
	Homepage    string
	Repository  string
	DistType    string
	DistURL     string
	Reference   string
	Shasum      string
	Require     map[string]string
	RequireDev  map[string]string
	BranchAlias map[string]string
	Abandoned   bool
}

// releases decodes the versions of name in doc, expanding them when the
// answer is minified. Entries without a version are skipped.
func releases(doc *p2Doc, name string) []release {
	raw := doc.Packages[strings.ToLower(name)]
	if doc.Minified == minified {
		raw = Expand(raw)
	}
	out := make([]release, 0, len(raw))
	for _, m := range raw {
		if r, ok := decodeRelease(m); ok {
			out = append(out, r)
		}
	}
	return out
}

// decodeRelease reads the fields Sightread uses from one expanded map.
func decodeRelease(m map[string]json.RawMessage) (release, bool) {
	r := release{Version: str(m["version"])}
	if r.Version == "" {
		return r, false
	}
	r.Type = str(m["type"])
	r.License = license(m["license"])
	r.Homepage = str(m["homepage"])
	if t, err := time.Parse(time.RFC3339, str(m["time"])); err == nil {
		r.Time = t.UTC()
	}
	var dist struct{ Type, URL, Reference, Shasum json.RawMessage }
	if json.Unmarshal(m["dist"], &dist) == nil {
		r.DistType, r.DistURL = str(dist.Type), str(dist.URL)
		r.Reference, r.Shasum = str(dist.Reference), str(dist.Shasum)
	}
	var src struct{ URL json.RawMessage }
	if json.Unmarshal(m["source"], &src) == nil {
		r.Repository = str(src.URL)
	}
	r.Require = strMap(m["require"])
	r.RequireDev = strMap(m["require-dev"])
	var extra struct {
		BranchAlias json.RawMessage `json:"branch-alias"`
	}
	if json.Unmarshal(m["extra"], &extra) == nil {
		r.BranchAlias = strMap(extra.BranchAlias)
	}
	r.Abandoned = abandoned(m["abandoned"])
	return r, true
}

// str is a JSON string, or "" for anything else.
func str(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// strMap is a JSON object of strings; other values are dropped.
func strMap(raw json.RawMessage) map[string]string {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		if s := str(v); s != "" {
			out[k] = s
		}
	}
	return out
}

// license is a Composer license: one SPDX string or a list, which
// Composer reads as a choice ("MIT OR GPL-2.0-or-later").
func license(raw json.RawMessage) string {
	if s := str(raw); s != "" {
		return s
	}
	var many []string
	if json.Unmarshal(raw, &many) != nil {
		return ""
	}
	var keep []string
	for _, s := range many {
		if s = strings.TrimSpace(s); s != "" {
			keep = append(keep, s)
		}
	}
	return strings.Join(keep, " OR ")
}

// abandoned reads Composer's abandoned field: true, or the name of the
// package to use instead.
func abandoned(raw json.RawMessage) bool {
	var b bool
	if json.Unmarshal(raw, &b) == nil {
		return b
	}
	return str(raw) != ""
}
