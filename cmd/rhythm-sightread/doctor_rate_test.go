// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
	"github.com/RhythmShahriar/sightread/fetch"
)

// TestDoctorGitHubRate reads the rate left through the real fetch
// client from a fake api.github.com, with and without a token, twice:
// the answer is never cached, so the second doctor asks again.
func TestDoctorGitHubRate(t *testing.T) {
	for _, c := range []struct {
		name, token, want string
	}{
		// The fake is a mirror, so the token goes to it and the
		// api.github.com warning is left out.
		{"token", coretest.FakeKey(coretest.KeyGitHub), "ok    GitHub token: set (sent only to 127.0.0.1); 4321 of 5000 requests left this hour\n"},
		{"no token", "", "ok    GitHub token: not set; the mirror at 127.0.0.1 reports 57 of 60 requests left this hour\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			world(t)
			doctorWorld(t)
			var asked atomic.Int32
			ln := laneListener(t)
			srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/rate_limit" {
					http.NotFound(w, r)
					return
				}
				asked.Add(1)
				body := `{"resources":{"core":{"limit":60,"remaining":57}}}`
				if r.Header.Get("Authorization") != "" {
					body = `{"resources":{"core":{"limit":5000,"remaining":4321}}}`
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, body)
			})}
			go func() { _ = srv.Serve(ln) }()
			t.Cleanup(func() { _ = srv.Close() })
			t.Setenv("SIGHTREAD_GITHUB_API", "http://"+ln.Addr().String())
			t.Setenv("GITHUB_TOKEN", c.token)
			t.Cleanup(core.SwapGetter(func(cfg core.GetterConfig) (core.Getter, error) { return fetch.New(cfg) }))
			for range 2 {
				_, out, _ := execute(t, "doctor", "--plain")
				if !strings.Contains(out, c.want) {
					t.Errorf("missing %q in\n%s", c.want, out)
				}
			}
			if n := asked.Load(); n != 2 {
				t.Errorf("asked /rate_limit %d times, want 2 (never cached)", n)
			}
		})
	}
}
