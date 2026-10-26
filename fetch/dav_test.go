// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package fetch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
)

func TestPropfind(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	var mu sync.Mutex
	var depths []string
	h := &counter{h: func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Method != "PROPFIND" || !strings.Contains(string(body), "creator-displayname") {
			t.Errorf("got %s with %q", r.Method, body)
		}
		mu.Lock()
		depths = append(depths, r.Header.Get("Depth"))
		mu.Unlock()
		w.WriteHeader(http.StatusMultiStatus)
		_, _ = io.WriteString(w, "<multistatus/>")
	}}
	srv := serve(t, h, false)
	dir := t.TempDir()
	bases := map[string]string{core.BaseWPOrgSVN: srv.URL}
	c := client(t, core.GetterConfig{CacheDir: dir, Bases: bases}, srv)
	ctx := context.Background()
	for range 2 {
		out, err := c.Propfind(ctx, srv.URL+"/akismet/tags/5.3.5/", 0, KindMeta, 1<<10)
		if err != nil || string(out) != "<multistatus/>" {
			t.Fatalf("Propfind: %v %q", err, out)
		}
	}
	if _, err := c.Propfind(ctx, srv.URL+"/twentyten/1.0/", 1, KindMeta, 1<<10); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := strings.Join(depths, ",")
	mu.Unlock()
	if got != "0,1" {
		t.Errorf("depths %v, want 0 then 1 (the repeat from the cache)", depths)
	}
	if _, err := c.Propfind(ctx, srv.URL+"/x/", 2, KindMeta, 1<<10); err == nil || h.count() != 2 {
		t.Errorf("depth 2: %v after %d hits, want refused before sending", err, h.count())
	}
	if _, err := c.Propfind(ctx, srv.URL+"/y/", 0, KindMeta, 4); !errors.Is(err, core.ErrTooLarge) {
		t.Errorf("over the limit: %v", err)
	}

	off := client(t, core.GetterConfig{CacheDir: dir, Offline: true, Bases: bases}, srv)
	if out, err := off.Propfind(ctx, srv.URL+"/akismet/tags/5.3.5/", 0, KindMeta, 1<<10); err != nil || string(out) != "<multistatus/>" {
		t.Errorf("offline cached: %v %q", err, out)
	}
	_, err := off.Propfind(ctx, srv.URL+"/hello-dolly/tags/1.7.2/", 0, KindMeta, 1<<10)
	want := "rhythm sightread: can't reach 127.0.0.1 (offline and not cached)\n" +
		"  with --offline only cached data and archives are used; run once without it to fill the cache"
	if err == nil || err.Error() != want {
		t.Errorf("offline uncached\n%v\nwant\n%s", err, want)
	}
	if _, err := c.Propfind(ctx, "https://example.com/x/", 0, KindMeta, 1<<10); core.CodeOf(err) != core.ENetwork {
		t.Errorf("off the allowlist: %v", err)
	}
	if _, err := c.Propfind(ctx, srv.URL+"/x/", 0, "nope", 1<<10); err == nil {
		t.Error("unknown kind accepted")
	}
}

func TestStatusErrorBody(t *testing.T) {
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		if strings.HasSuffix(r.URL.Path, "/json") {
			_, _ = io.WriteString(w, `{"error":"closed","closed":true}`)
			return
		}
		_, _ = io.WriteString(w, "<html>not found</html>")
	}), false)
	c := client(t, core.GetterConfig{Bases: map[string]string{core.BaseWPOrgAPI: srv.URL}}, srv)
	var v any
	var se *StatusError
	err := c.JSON(context.Background(), srv.URL+"/json", &v, KindVersions)
	if !errors.As(err, &se) || string(se.Body) != `{"error":"closed","closed":true}` {
		t.Errorf("JSON 404: %v, body %q", err, bodyOf(se))
	}
	err = c.JSON(context.Background(), srv.URL+"/html", &v, KindVersions)
	if !errors.As(err, &se) || se.Body != nil {
		t.Errorf("HTML 404 kept a body: %v %q", err, bodyOf(se))
	}
}

func bodyOf(se *StatusError) []byte {
	if se == nil {
		return nil
	}
	return se.Body
}

func TestUnverifiedText(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	err := Unverified("plugin", "countdown-timer-ultimate", "2.6.8", "wordpress.org checksums answered 503")
	want := "rhythm sightread plugin: couldn't verify countdown-timer-ultimate 2.6.8: wordpress.org checksums answered 503\n" +
		"  not diffed; run again later, or --allow-unverified to review it anyway (the report marks it unverified)"
	if err.Error() != want || err.Code != core.EUnverifiable || err.ExitCode() != 3 {
		t.Errorf("E5\n%v\nwant\n%s", err, want)
	}
}
