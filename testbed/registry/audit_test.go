// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newUnstarted builds a registry over the fixture packages without
// binding any port; the tests call the muxes directly.
func newUnstarted(t *testing.T) *Registry {
	t.Helper()
	reg, err := New(Options{PackagesDir: fixtureDir(t), StateDir: t.TempDir(), PlainHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reg.Close() })
	return reg
}

func TestNPMAuditBulk(t *testing.T) {
	reg := newUnstarted(t)
	post := func(body map[string][]string, gz bool) map[string][]map[string]any {
		t.Helper()
		raw, _ := json.Marshal(body)
		var buf bytes.Buffer
		req := httptest.NewRequest(http.MethodPost, "/-/npm/v1/security/advisories/bulk", nil)
		if gz {
			zw := gzip.NewWriter(&buf)
			_, _ = zw.Write(raw)
			_ = zw.Close()
			req.Header.Set("Content-Encoding", "gzip")
		} else {
			buf.Write(raw)
		}
		req.Body = io.NopCloser(&buf)
		rec := httptest.NewRecorder()
		reg.npmMux().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("status %d: %s", rec.Code, rec.Body)
		}
		var out map[string][]map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// The candidate carries MAL-2026-0001 in meta.yaml.
	hit := post(map[string][]string{"example-pkg": {"2.0.0"}}, true)
	if len(hit["example-pkg"]) != 1 || hit["example-pkg"][0]["title"] != "MAL-2026-0001" {
		t.Errorf("advisory not reported for the affected version: %v", hit)
	}
	// The installed version has none, and an unknown package is quiet.
	if miss := post(map[string][]string{"example-pkg": {"1.0.0"}, "left-pad": {"1.0.0"}}, false); len(miss) != 0 {
		t.Errorf("advisories for clean versions: %v", miss)
	}

	rec := httptest.NewRecorder()
	reg.npmMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/-/npm/v1/security/advisories/bulk", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET answered %d, want 405", rec.Code)
	}
}

func TestComposerAdvisoriesAndRoot(t *testing.T) {
	reg := newUnstarted(t)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:18901/packages.json", nil)
	reg.packagistMux().ServeHTTP(rec, req)
	var root map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &root); err != nil {
		t.Fatal(err)
	}
	if root["metadata-url"] != "/p2/%package%.json" {
		t.Errorf("metadata-url %v", root["metadata-url"])
	}
	sa, _ := root["security-advisories"].(map[string]any)
	if api, _ := sa["api-url"].(string); !strings.HasSuffix(api, "/api/security-advisories/") || !strings.HasPrefix(api, "http://127.0.0.1:18901") {
		t.Errorf("api-url %v", sa["api-url"])
	}

	rec = httptest.NewRecorder()
	reg.packagistMux().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/security-advisories/?packages[]=vendor/example", nil))
	var body struct {
		Advisories map[string][]any `json:"advisories"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Advisories == nil || len(body.Advisories["vendor/example"]) != 0 {
		t.Errorf("a package without advisories got some: %s", rec.Body)
	}
}

func TestExports(t *testing.T) {
	reg := newUnstarted(t)
	if reg.TLSConfig() != nil {
		t.Error("plain HTTP registry has a TLS config")
	}
	ids := reg.IDs()
	if len(ids) != 4 || ids[0] != "example-pkg" {
		t.Errorf("IDs = %v", ids)
	}
	m, ok := reg.Meta("example-plugin")
	if !ok || m.Ecosystem != "wp-plugin" {
		t.Errorf("Meta(example-plugin) = %v, %v", m, ok)
	}
	if _, ok := reg.Meta("nope"); ok {
		t.Error("Meta found a missing folder")
	}
	zip, ok := reg.Archive("example-plugin", "1.3.0")
	if !ok || !bytes.HasPrefix(zip, []byte("PK")) {
		t.Errorf("Archive(example-plugin, 1.3.0) is not a zip (ok %v)", ok)
	}
	if _, ok := reg.Archive("example-plugin", "9.9.9"); ok {
		t.Error("Archive found a missing version")
	}
}
