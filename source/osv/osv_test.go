// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/RhythmShahriar/sightread/blob"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/fetch"
)

// The ports this package's tests may listen on.
const firstPort, lastPort = 31000, 31019

// server plays api.osv.dev: vulns maps "<ecosystem>/<name>@<version>"
// to advisory ids, records maps an id to its record.
type server struct {
	mu        sync.Mutex
	vulns     map[string][]string
	records   map[string]string
	pageAfter int // when set, answer that many ids then a page token
	queries   []query
	posts     int
	types     []string
	gets      []string
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/v1/querybatch":
		s.posts++
		s.types = append(s.types, r.Header.Get("Content-Type"))
		var req struct{ Queries []query }
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad", 400)
			return
		}
		s.queries = append(s.queries, req.Queries...)
		var results []map[string]any
		for _, q := range req.Queries {
			ids := s.vulns[q.Package.Ecosystem+"/"+q.Package.Name+"@"+q.Version]
			res := map[string]any{}
			if s.pageAfter > 0 && q.PageToken == "" && len(ids) > s.pageAfter {
				ids = ids[:s.pageAfter]
				res["next_page_token"] = "page2"
			} else if q.PageToken != "" {
				ids = ids[s.pageAfter:]
			}
			var vs []map[string]string
			for _, id := range ids {
				vs = append(vs, map[string]string{"id": id, "modified": "2026-10-01T00:00:00Z"})
			}
			if vs != nil {
				res["vulns"] = vs
			}
			results = append(results, res)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"results": results})
	case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
		id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
		s.gets = append(s.gets, id)
		if rec, ok := s.records[id]; ok {
			_, _ = io.WriteString(w, rec)
			return
		}
		http.NotFound(w, r)
	default:
		http.NotFound(w, r)
	}
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	for p := firstPort; p <= lastPort; p++ {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			return l
		}
	}
	t.Fatalf("no free port in 127.0.0.1:%d-%d", firstPort, lastPort)
	return nil
}

func start(t *testing.T, s *server, extra map[string]string) *Client {
	t.Helper()
	srv := httptest.NewUnstartedServer(s)
	_ = srv.Listener.Close()
	srv.Listener = listen(t)
	srv.Start()
	t.Cleanup(srv.Close)
	bases := map[string]string{core.BaseOSV: srv.URL}
	for k, v := range extra {
		bases[k] = v
	}
	get, err := fetch.New(core.GetterConfig{Bases: bases, CacheDir: t.TempDir(), Retries: -1})
	if err != nil {
		t.Fatal(err)
	}
	return New(&core.Env{Get: get, Blobs: blob.Memory(), Bases: bases})
}

// Records in the shape api.osv.dev serves (copied by hand, cut short,
// values made up).
const malRecord = `{"id":"MAL-2026-1234","summary":"Malicious code in plain-crypto-js (npm)",
 "details":"The package drops a remote access tool from its postinstall script.",
 "affected":[{"package":{"ecosystem":"npm","name":"plain-crypto-js"},"versions":["4.2.1"]}],
 "database_specific":{"malicious-packages-origins":[{"source":"ghsa-malware"}]}}`

const ghsaRecord = `{"id":"GHSA-xxxx-yyyy-zzzz","summary":"Prototype pollution in lodash",
 "aliases":["CVE-2020-8203"],
 "affected":[
  {"package":{"ecosystem":"npm","name":"lodash"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"4.17.19"}]},
   {"type":"GIT","repo":"https://github.com/lodash/lodash","events":[{"introduced":"0"},{"fixed":"abc123"}]}]},
  {"package":{"ecosystem":"npm","name":"lodash-es"},"ranges":[{"type":"SEMVER","events":[{"fixed":"4.17.20"}]}]}]}`

const composerRecord = `{"id":"GHSA-aaaa-bbbb-cccc","details":"Remote code execution in guzzle\nMore text.",
 "affected":[{"package":{"ecosystem":"Packagist","name":"guzzlehttp/guzzle"},"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"7.0.0"},{"fixed":"7.4.5"},{"introduced":"6.0.0"},{"fixed":"6.5.8"}]}]}]}`

func TestQuery(t *testing.T) {
	s := &server{
		vulns: map[string][]string{
			"npm/plain-crypto-js@4.2.1":         {"MAL-2026-1234"},
			"npm/lodash@4.17.15":                {"GHSA-xxxx-yyyy-zzzz"},
			"Packagist/guzzlehttp/guzzle@7.4.4": {"GHSA-aaaa-bbbb-cccc"},
			"npm/@acme/billing@1.0.0":           {"MAL-2026-9999"},
		},
		records: map[string]string{"MAL-2026-1234": malRecord, "GHSA-xxxx-yyyy-zzzz": ghsaRecord, "GHSA-aaaa-bbbb-cccc": composerRecord},
	}
	c := start(t, s, map[string]string{core.BaseNPMScope + "@acme": "http://127.0.0.1:31019"})
	refs := []core.Ref{
		{Eco: core.NPM, Name: "plain-crypto-js", Version: "4.2.1"},
		{Eco: core.NPM, Name: "lodash", Version: "4.17.15"},
		{Eco: core.NPM, Name: "lodash", Version: "4.17.21"},
		{Eco: core.Composer, Name: "GuzzleHTTP/Guzzle", Version: "7.4.4"},
		{Eco: core.NPM, Name: "@acme/billing", Version: "1.0.0"},
		{Eco: core.WPPlugin, Name: "akismet", Version: "5.3.5"},
		{Eco: core.NPM, Name: "no-version"},
	}
	got, err := c.Query(context.Background(), refs)
	if err != nil {
		t.Fatal(err)
	}
	mal := got[refs[0]]
	if len(mal) != 1 || !mal[0].Malicious || mal[0].Summary != "Malicious code in plain-crypto-js (npm)" ||
		mal[0].URL != "https://osv.dev/vulnerability/MAL-2026-1234" {
		t.Errorf("MAL = %+v", mal)
	}
	lo := got[refs[1]]
	if len(lo) != 1 || lo[0].Malicious || !slices.Equal(lo[0].FixedIn, []string{"4.17.19"}) {
		t.Errorf("lodash = %+v", lo)
	}
	if _, ok := got[refs[2]]; ok {
		t.Error("a fixed version got an advisory")
	}
	gz := got[refs[3]]
	if len(gz) != 1 || gz[0].Summary != "Remote code execution in guzzle" || !slices.Equal(gz[0].FixedIn, []string{"6.5.8", "7.4.5"}) {
		t.Errorf("guzzle = %+v", gz)
	}
	if _, ok := got[refs[4]]; ok {
		t.Error("a private ref has advisories, so it was sent")
	}
	for _, q := range s.queries {
		if strings.Contains(q.Package.Name, "acme") || q.Package.Name == "akismet" || q.Version == "" {
			t.Errorf("sent %+v", q)
		}
	}
	if s.posts != 1 || len(s.queries) != 4 || s.types[0] != "application/json" {
		t.Errorf("%d posts, %d queries, types %v", s.posts, len(s.queries), s.types)
	}
	// Records are cached: a second query asks OSV again but not for them.
	before := len(s.gets)
	if _, err := c.Query(context.Background(), refs[:1]); err != nil {
		t.Fatal(err)
	}
	if len(s.gets) != before {
		t.Errorf("record fetched again: %v", s.gets)
	}
}

func TestQueryBatchesAndPages(t *testing.T) {
	s := &server{vulns: map[string][]string{"npm/p0@1.0.0": {"MAL-1", "MAL-2", "MAL-3"}}, pageAfter: 2,
		records: map[string]string{"MAL-1": `{"id":"MAL-1"}`, "MAL-2": `{"id":"MAL-2"}`, "MAL-3": `{"id":"MAL-3"}`}}
	c := start(t, s, nil)
	var refs []core.Ref
	for i := range 2500 {
		refs = append(refs, core.Ref{Eco: core.NPM, Name: fmt.Sprintf("p%d", i), Version: "1.0.0"})
	}
	got, err := c.Query(context.Background(), refs)
	if err != nil {
		t.Fatal(err)
	}
	if s.posts != 4 { // 1000 + 1000 + 500, then the second page of p0
		t.Errorf("%d posts", s.posts)
	}
	if len(got[refs[0]]) != 3 {
		t.Errorf("p0 = %+v", got[refs[0]])
	}
}

func TestQueryNothingToAsk(t *testing.T) {
	s := &server{}
	c := start(t, s, nil)
	got, err := c.Query(context.Background(), []core.Ref{{Eco: core.WPTheme, Name: "x", Version: "1"}})
	if err != nil || len(got) != 0 || s.posts != 0 {
		t.Errorf("got %v, %v, %d posts", got, err, s.posts)
	}
}

func TestQueryError(t *testing.T) {
	s := &server{vulns: map[string][]string{"npm/a@1.0.0": {"MAL-404"}}, records: map[string]string{}}
	c := start(t, s, nil)
	if _, err := c.Query(context.Background(), []core.Ref{{Eco: core.NPM, Name: "a", Version: "1.0.0"}}); err == nil {
		t.Error("a missing record should be an error (not checked)")
	}
}

func TestRegistered(t *testing.T) {
	if _, ok := core.AdvisoriesFor(&core.Env{}).(*Client); !ok {
		t.Error("OSV not registered")
	}
}
