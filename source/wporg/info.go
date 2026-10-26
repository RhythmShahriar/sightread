// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package wporg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// info is what Sightread reads from the WordPress.org info API for one
// plugin or theme. The API's fields are undocumented and change (Meta
// Trac 8124), so decode is strict on the fields below and ignores
// everything else.
type info struct {
	Slug          string
	Version       string            // the current release, never "trunk"
	Versions      map[string]string // every listed release to its download link
	DownloadLink  string
	Contributors  []string // WordPress.org logins, sorted
	Author        string   // plain text
	AuthorProfile string
	Homepage      string
	RequiresPHP   string
	LastUpdated   time.Time
	Closed        bool
	ClosedReason  string
	// NotFound is the API's "Plugin not found." or "Theme not found".
	NotFound bool
}

// maxField caps the text kept from one field; WordPress.org's own
// values are far shorter.
const maxField = 1024

// decodeInfo reads an info API answer. A wrong type on a field Sightread
// relies on is an error naming it; an answer with an "error" field is a
// closed or unknown package, not an error.
func decodeInfo(body []byte) (*info, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("the answer is not a JSON object: %w", err)
	}
	if raw == nil {
		return nil, fmt.Errorf("the answer is not a JSON object")
	}
	d := decoder{raw: raw}
	in := &info{}
	in.Slug = d.str("slug", false)
	if msg := d.str("error", false); msg != "" {
		closed := d.flag("closed")
		if !closed && msg != "closed" {
			in.NotFound = true
			return in, d.err
		}
		in.Closed = true
		in.ClosedReason = firstOf(d.str("reason_text", false), d.str("reason", false), d.str("description", false), "closed")
		return in, d.err
	}
	in.Version = d.str("version", true)
	in.Versions = d.versions()
	in.DownloadLink = d.str("download_link", true)
	in.Contributors = d.contributors()
	var login string
	in.Author, in.AuthorProfile, login = d.author()
	if len(in.Contributors) == 0 && login != "" {
		// A theme has no contributors list; its author's login is the
		// account that can ship it.
		in.Contributors = []string{login}
	}
	in.Homepage = d.str("homepage", false)
	in.RequiresPHP = d.strOrFalse("requires_php")
	in.LastUpdated = parseDate(firstOf(d.str("last_updated_time", false), d.str("last_updated", false)))
	if in.Version == "trunk" {
		// "Stable tag: trunk" never names a release; the version field
		// always does, so this is an answer Sightread can't use.
		d.fail("version", "trunk")
	}
	return in, d.err
}

// decoder reads fields and keeps the first problem.
type decoder struct {
	raw map[string]json.RawMessage
	err error
}

func (d *decoder) fail(key, what string) {
	if d.err == nil {
		d.err = fmt.Errorf("field %q is %s", key, what)
	}
}

// kind names the JSON type of v for an error.
func kind(v json.RawMessage) string {
	switch b := bytes.TrimSpace(v); {
	case len(b) == 0:
		return "empty"
	case b[0] == '"':
		return "a string"
	case b[0] == '{':
		return "an object"
	case b[0] == '[':
		return "an array"
	case b[0] == 't' || b[0] == 'f':
		return "a boolean"
	case b[0] == 'n':
		return "null"
	}
	return "a number"
}

// str reads a string field. A missing or empty required field is a
// problem; so is a present field of another type.
func (d *decoder) str(key string, required bool) string {
	v, ok := d.raw[key]
	if !ok || isNull(v) {
		if required {
			d.fail(key, "missing")
		}
		return ""
	}
	var s string
	if err := json.Unmarshal(v, &s); err != nil {
		d.fail(key, kind(v)+", want a string")
		return ""
	}
	if required && s == "" {
		d.fail(key, "empty")
	}
	return clip(s)
}

// strOrFalse reads a field that is a string or false (requires_php
// when the readme says nothing).
func (d *decoder) strOrFalse(key string) string {
	v, ok := d.raw[key]
	if !ok || isNull(v) || bytes.Equal(bytes.TrimSpace(v), []byte("false")) {
		return ""
	}
	return d.str(key, false)
}

// flag reads a boolean field; absent is false.
func (d *decoder) flag(key string) bool {
	v, ok := d.raw[key]
	if !ok || isNull(v) {
		return false
	}
	var b bool
	if err := json.Unmarshal(v, &b); err != nil {
		d.fail(key, kind(v)+", want a boolean")
	}
	return b
}

// versions reads the versions map. PHP encodes an empty map as [].
func (d *decoder) versions() map[string]string {
	v, ok := d.raw["versions"]
	if !ok {
		d.fail("versions", "missing")
		return nil
	}
	if isEmptyArray(v) || isNull(v) {
		return map[string]string{}
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(v, &m); err != nil {
		d.fail("versions", kind(v)+", want an object")
		return nil
	}
	out := make(map[string]string, len(m))
	for ver, link := range m {
		var s string
		if err := json.Unmarshal(link, &s); err != nil && !isNull(link) {
			d.fail("versions", "an object holding "+kind(link)+", want strings")
			return nil
		}
		out[ver] = clip(s)
	}
	return out
}

// contributors reads the logins of the contributors map (1.2 gives
// objects, 1.0 gave profile URLs); [] means none.
func (d *decoder) contributors() []string {
	v, ok := d.raw["contributors"]
	if !ok || isNull(v) || isEmptyArray(v) {
		return nil
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(v, &m); err != nil {
		d.fail("contributors", kind(v)+", want an object")
		return nil
	}
	out := make([]string, 0, len(m))
	for login := range m {
		out = append(out, clip(login))
	}
	slices.Sort(out)
	return out
}

// author reads the author: plugins give HTML text and author_profile,
// themes an object with display_name, profile and the login.
func (d *decoder) author() (name, profile, login string) {
	v, ok := d.raw["author"]
	if !ok || isNull(v) {
		return "", d.str("author_profile", false), ""
	}
	if bytes.HasPrefix(bytes.TrimSpace(v), []byte("{")) {
		var a struct {
			Nicename    string `json:"user_nicename"`
			Profile     string `json:"profile"`
			DisplayName string `json:"display_name"`
			Author      string `json:"author"`
		}
		if err := json.Unmarshal(v, &a); err != nil {
			d.fail("author", "an object of unexpected fields")
			return "", "", ""
		}
		return clip(plain(firstOf(a.DisplayName, a.Author, a.Nicename))), clip(a.Profile), clip(a.Nicename)
	}
	return plain(d.str("author", false)), d.str("author_profile", false), ""
}

var tagRe = regexp.MustCompile(`<[^>]*>`)

// plain turns the API's HTML author text into plain text.
func plain(s string) string {
	return strings.TrimSpace(html.UnescapeString(tagRe.ReplaceAllString(s, "")))
}

// dateLayouts are the forms of last_updated seen in the API.
var dateLayouts = []string{"2006-01-02 3:04pm MST", "2006-01-02 15:04:05", "2006-01-02", time.RFC3339}

// parseDate reads a last_updated value; an unknown form is the zero
// time, since a date is a hint and never worth failing a review over.
func parseDate(s string) time.Time {
	for _, l := range dateLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func isNull(v json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(v), []byte("null")) }

func isEmptyArray(v json.RawMessage) bool {
	b := bytes.TrimSpace(v)
	return len(b) >= 2 && b[0] == '[' && b[len(b)-1] == ']' && len(bytes.TrimSpace(b[1:len(b)-1])) == 0
}

// clip caps s at maxField bytes on a rune boundary.
func clip(s string) string {
	if len(s) <= maxField {
		return s
	}
	cut := maxField
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func firstOf(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}
