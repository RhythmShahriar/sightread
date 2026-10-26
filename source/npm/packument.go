// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package npm

import (
	"encoding/json"
	"fmt"
	"maps"
	"strings"
	"time"
)

// maxVersionKey caps a version key read from a packument.
const maxVersionKey = 256

// packument is what Sightread reads from the abbreviated packument
// (application/vnd.npm.install-v1+json): the version keys, dist-tags and
// when it last changed.
type packument struct {
	Versions []string
	DistTags map[string]string
	Modified time.Time
}

// decodePackument reads an abbreviated packument. A version whose value
// is not an object, or whose key is empty or too long, is left out; a
// dist-tag that is not a string is dropped. Only a document that is not
// a JSON object is an error.
func decodePackument(data []byte) (*packument, error) {
	var raw struct {
		Versions map[string]json.RawMessage `json:"versions"`
		DistTags map[string]json.RawMessage `json:"dist-tags"`
		Modified json.RawMessage            `json:"modified"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	p := &packument{DistTags: map[string]string{}}
	for v, body := range raw.Versions {
		b := strings.TrimSpace(string(body))
		if v == "" || len(v) > maxVersionKey || !strings.HasPrefix(b, "{") {
			continue
		}
		p.Versions = append(p.Versions, v)
	}
	for tag, v := range raw.DistTags {
		if s := str(v); s != "" {
			p.DistTags[tag] = s
		}
	}
	if t, err := time.Parse(time.RFC3339, str(raw.Modified)); err == nil {
		p.Modified = t.UTC()
	}
	return p, nil
}

// times is the time map of a full packument: publish dates by version,
// and whether the whole package was unpublished.
type times struct {
	At          map[string]time.Time
	Unpublished bool
}

// decodeTimes reads the "time" map of a full packument, ignoring every
// other field. "created" and "modified" are kept like versions; callers
// look versions up by name.
func decodeTimes(data []byte) (*times, error) {
	var raw struct {
		Time map[string]json.RawMessage `json:"time"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	t := &times{At: map[string]time.Time{}}
	for k, v := range raw.Time {
		if k == "unpublished" {
			t.Unpublished = true
			continue
		}
		if at, err := time.Parse(time.RFC3339, str(v)); err == nil {
			t.At[k] = at.UTC()
		}
	}
	return t, nil
}

// versionDoc is the part of a per-version document Sightread reads.
type versionDoc struct {
	Scripts          map[string]string
	NPMUser          *person
	Trusted          bool // _npmUser.trustedPublisher: published by a CI workflow without a token
	Maintainers      []person
	Tarball          string
	Integrity        string
	Shasum           string
	Signatures       []signature
	Attestations     bool
	License          string
	Deps, DevDeps    map[string]string
	Repository       string
	Homepage         string
	HasInstallScript bool
}

type person struct{ Name, Email string }

type signature struct{ KeyID, Sig string }

// decodeVersion reads a per-version document leniently: a field of an
// unexpected type is left empty, never an error, so one odd field can't
// hide the rest.
func decodeVersion(data []byte) (*versionDoc, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	if raw == nil {
		return nil, fmt.Errorf("not a JSON object")
	}
	d := &versionDoc{
		Scripts: strMap(raw["scripts"]), Deps: strMap(raw["dependencies"]), DevDeps: strMap(raw["devDependencies"]),
		License: typed(raw["license"]), Repository: repoURL(raw["repository"]), Homepage: str(raw["homepage"]),
	}
	var b bool
	if json.Unmarshal(raw["hasInstallScript"], &b) == nil {
		d.HasInstallScript = b
	}
	if p, ok := decodePerson(raw["_npmUser"]); ok {
		d.NPMUser = &p
		var tp struct {
			TrustedPublisher json.RawMessage `json:"trustedPublisher"`
		}
		if json.Unmarshal(raw["_npmUser"], &tp) == nil {
			s := strings.TrimSpace(string(tp.TrustedPublisher))
			d.Trusted = s != "" && s != "null" && s != "false"
		}
	}
	var ms []json.RawMessage
	if json.Unmarshal(raw["maintainers"], &ms) == nil {
		for _, m := range ms {
			if p, ok := decodePerson(m); ok {
				d.Maintainers = append(d.Maintainers, p)
			}
		}
	}
	var dist struct {
		Tarball, Integrity, Shasum json.RawMessage
		Signatures                 []struct{ Keyid, Sig json.RawMessage }
		Attestations               json.RawMessage
	}
	if json.Unmarshal(raw["dist"], &dist) == nil {
		d.Tarball, d.Integrity, d.Shasum = str(dist.Tarball), str(dist.Integrity), str(dist.Shasum)
		for _, s := range dist.Signatures {
			if id, sig := str(s.Keyid), str(s.Sig); id != "" && sig != "" {
				d.Signatures = append(d.Signatures, signature{KeyID: id, Sig: sig})
			}
		}
		a := strings.TrimSpace(string(dist.Attestations))
		d.Attestations = strings.HasPrefix(a, "{")
	}
	return d, nil
}

// decodePerson reads {"name", "email"} or the old "Name <email>" string.
func decodePerson(raw json.RawMessage) (person, bool) {
	if s := str(raw); s != "" {
		name, email, _ := strings.Cut(s, "<")
		return person{Name: strings.TrimSpace(name), Email: strings.TrimSuffix(strings.TrimSpace(email), ">")}, true
	}
	var p struct{ Name, Email json.RawMessage }
	if json.Unmarshal(raw, &p) != nil || str(p.Name) == "" {
		return person{}, false
	}
	return person{Name: str(p.Name), Email: str(p.Email)}, true
}

// typed reads a string or the old {"type": "MIT"} object.
func typed(raw json.RawMessage) string {
	if s := str(raw); s != "" {
		return s
	}
	var o struct{ Type json.RawMessage }
	if json.Unmarshal(raw, &o) == nil {
		return str(o.Type)
	}
	return ""
}

// repoURL reads repository as a string or {"type", "url"}.
func repoURL(raw json.RawMessage) string {
	if s := str(raw); s != "" {
		return s
	}
	var o struct{ URL json.RawMessage }
	if json.Unmarshal(raw, &o) == nil {
		return str(o.URL)
	}
	return ""
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
	if len(out) == 0 {
		return nil
	}
	return out
}

// cloneTags copies dist-tags for a caller.
func cloneTags(m map[string]string) map[string]string { return maps.Clone(m) }
