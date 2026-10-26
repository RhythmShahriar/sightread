// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package wporg

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/RhythmShahriar/sightread/core"
)

// davEntry is one response of a PROPFIND multistatus answer.
type davEntry struct {
	Path    string // the href's path, unescaped
	Dir     bool
	Size    int64 // getcontentlength; -1 when absent
	Creator string
	Created time.Time
}

// multistatus is the subset of RFC 4918 Sightread reads. Element names
// match in any namespace: mod_dav_svn puts the live properties in DAV:
// under several prefixes.
type multistatus struct {
	Responses []struct {
		Href      string `xml:"href"`
		Propstats []struct {
			Status string `xml:"status"`
			Prop   struct {
				ResourceType struct {
					Collection *struct{} `xml:"collection"`
				} `xml:"resourcetype"`
				Length  string `xml:"getcontentlength"`
				Creator string `xml:"creator-displayname"`
				Created string `xml:"creationdate"`
			} `xml:"prop"`
		} `xml:"propstat"`
	} `xml:"response"`
}

// parseMultistatus reads a PROPFIND answer. Only properties in a 200
// propstat count; an entry whose href is not a path is an error, since
// a listing Sightread can't place must not be guessed at.
func parseMultistatus(body []byte) ([]davEntry, error) {
	var ms multistatus
	dec := xml.NewDecoder(bytes.NewReader(body))
	dec.Strict = true
	if err := dec.Decode(&ms); err != nil {
		return nil, fmt.Errorf("not a WebDAV multistatus answer: %w", err)
	}
	out := make([]davEntry, 0, len(ms.Responses))
	for _, r := range ms.Responses {
		u, err := url.Parse(strings.TrimSpace(r.Href))
		if err != nil || u.Path == "" {
			return nil, fmt.Errorf("the listing holds an href that is not a path")
		}
		e := davEntry{Path: u.Path, Size: -1}
		for _, ps := range r.Propstats {
			if ps.Status != "" && !strings.Contains(ps.Status, " 200") {
				continue
			}
			p := ps.Prop
			if p.ResourceType.Collection != nil {
				e.Dir = true
			}
			if n, err := strconv.ParseInt(strings.TrimSpace(p.Length), 10, 64); err == nil && n >= 0 {
				e.Size = n
			}
			if c := strings.TrimSpace(p.Creator); c != "" {
				e.Creator = clip(c)
			}
			if t, err := time.Parse(time.RFC3339, strings.TrimSpace(p.Created)); err == nil {
				e.Created = t.UTC()
			}
		}
		out = append(out, e)
	}
	return out, nil
}

// creator is who last committed slug's SVN folder for v and when, from
// a PROPFIND of depth 0. Any failure leaves the publisher unknown: it is
// a hint, never a reason to stop a review.
func (s *site) creator(ctx context.Context, slug, v string) (*core.Person, time.Time) {
	body, err := s.propfind(ctx, s.svnFolder(slug, v), 0)
	if err != nil {
		s.logf("no SVN creator for %s %s: %v", slug, v, short(err))
		return nil, time.Time{}
	}
	entries, err := parseMultistatus(body)
	if err != nil || len(entries) == 0 || entries[0].Creator == "" {
		s.logf("no SVN creator for %s %s in the answer", slug, v)
		return nil, time.Time{}
	}
	e := entries[0]
	return &core.Person{Name: e.Creator, Login: e.Creator}, e.Created
}

// short is the first line of err, for a -v note.
func short(err error) string {
	msg, _, _ := strings.Cut(err.Error(), "\n")
	return msg
}
