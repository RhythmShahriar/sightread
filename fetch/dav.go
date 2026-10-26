// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package fetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cache"
)

// DAV is the SVN listing request core.Getter has no room for: a PROPFIND
// with its Depth header, cached like JSON. *Client implements it; a
// source type-asserts its Getter and falls back to Getter.Text (which
// sends no Depth) for the fakes of other lanes' tests.
type DAV interface {
	// Propfind asks for the properties of url (depth 0) or of url and its
	// children (depth 1) and returns up to limit bytes of the 207 answer,
	// reusing a cached answer of kind while it is fresh.
	Propfind(ctx context.Context, url string, depth int, kind string, limit int64) ([]byte, error)
}

// propfindBody asks for only the properties Sightread reads, so a
// folder listing stays small.
const propfindBody = `<?xml version="1.0" encoding="utf-8"?>` +
	`<propfind xmlns="DAV:"><prop><resourcetype/><getcontentlength/>` +
	`<creator-displayname/><creationdate/></prop></propfind>`

// Propfind implements DAV. Only depths 0 and 1 are sent: SVN servers
// refuse an infinite one; a bounded walk is what keeps a hostile
// tree from costing more than the limits allow. Offline, only the cache
// is read.
func (c *Client) Propfind(ctx context.Context, rawURL string, depth int, kind string, limit int64) ([]byte, error) {
	if depth != 0 && depth != 1 {
		return nil, fmt.Errorf("fetch: PROPFIND depth %d: want 0 or 1", depth)
	}
	u, err := c.parse(rawURL)
	if err != nil {
		return nil, err
	}
	store, ok := c.stores[kind]
	if !ok {
		return nil, fmt.Errorf("fetch: unknown cache kind %q", kind)
	}
	key := "PROPFIND " + strconv.Itoa(depth) + " " + u.String()
	body, _, err := cache.Load(store, ctx, kind, key, func(ctx context.Context) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, "PROPFIND", u.String(), strings.NewReader(propfindBody)) //nolint:gosec // u passed the allowlist in parse
		if err != nil {
			return nil, err
		}
		req.Header.Set("Depth", strconv.Itoa(depth))
		req.Header.Set("Content-Type", `text/xml; charset="utf-8"`)
		resp, err := c.do(c.api, req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }()
		out, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return nil, c.netError(ctx, u, err)
		}
		if int64(len(out)) > limit {
			return nil, tooLargeError("the answer of "+u.Hostname(), &SizeError{Limit: limit})
		}
		return out, nil
	})
	if errors.Is(err, cache.ErrOffline) {
		return nil, networkError(u.Hostname(), "offline and not cached", hintOffline, err)
	}
	return body, err
}
