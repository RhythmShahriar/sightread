// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package kitcheck

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cache"
	"github.com/RhythmShahriar/rhythm/kit/config"
	"github.com/RhythmShahriar/rhythm/kit/httpx"
	"github.com/RhythmShahriar/rhythm/kit/secrets"
	"github.com/RhythmShahriar/rhythm/kit/term"
)

// join builds credential-shaped fixtures at run time, so the source holds
// nothing a secret scanner would flag.
func join(parts ...string) string { return strings.Join(parts, "") }

// TestHTTPXRefusesLoopback: fetch builds its client without AllowPrivate,
// so a registry answer can't point Sightread at a local service.
func TestHTTPXRefusesLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{}") }))
	defer srv.Close()
	c := httpx.New(httpx.Options{Retries: 0})
	resp, err := c.Get(srv.URL)
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("reached a loopback server without AllowPrivate")
	}
	if !errors.Is(err, httpx.ErrPrivate) {
		t.Errorf("err %v, want ErrPrivate", err)
	}
}

func TestHTTPXBodyLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, strings.Repeat("x", 4096))
	}))
	defer srv.Close()
	c := httpx.New(httpx.Options{AllowPrivate: true, MaxBody: 100})
	resp, err := c.Get(srv.URL)
	if err == nil {
		defer func() { _ = resp.Body.Close() }()
		_, err = io.ReadAll(resp.Body)
	}
	if !errors.Is(err, httpx.ErrBodyTooLarge) {
		t.Errorf("err %v, want ErrBodyTooLarge", err)
	}
}

// TestHTTPXStripsAuthorization: GITHUB_TOKEN goes to api.github.com and
// never across the redirect to codeload. Here the two hosts are two
// loopback ports; Go's own client would keep the header when only the
// port changes.
func TestHTTPXStripsAuthorization(t *testing.T) {
	var got atomic.Value
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("Authorization") + "|")
		_, _ = io.WriteString(w, "zip")
	}))
	defer other.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/zipball", http.StatusFound)
	}))
	defer api.Close()
	target, _ := url.Parse(api.URL)
	c := httpx.New(httpx.Options{Target: target, AllowPrivate: true, OffSiteRedirects: true})
	req, _ := http.NewRequest(http.MethodGet, api.URL+"/repos/o/r/zipball/abc", nil)
	req.Header.Set("Authorization", "Bearer "+join("gh", "p_", strings.Repeat("A", 36)))
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if v, _ := got.Load().(string); v != "|" {
		t.Errorf("the other host got Authorization %q", strings.TrimSuffix(v, "|"))
	}
}

// TestCacheOfflineFallback: --offline answers from the cache however old
// it is and fails with ErrOffline when nothing is cached.
func TestCacheOfflineFallback(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	online := &cache.Store{Dir: dir, TTL: time.Nanosecond}
	v, _, err := cache.Load(online, ctx, "meta", "npm:left-pad", func(context.Context) (string, error) { return "1.3.0", nil })
	if err != nil || v != "1.3.0" {
		t.Fatalf("first load %q, %v", v, err)
	}
	time.Sleep(2 * time.Millisecond)
	offline := &cache.Store{Dir: dir, TTL: time.Nanosecond, Offline: true}
	fail := func(context.Context) (string, error) {
		t.Error("offline store fetched")
		return "", errors.New("no network")
	}
	v, stale, err := cache.Load(offline, ctx, "meta", "npm:left-pad", fail)
	if err != nil || v != "1.3.0" || !stale {
		t.Errorf("offline load %q, stale %v, %v", v, stale, err)
	}
	if _, _, err := cache.Load(offline, ctx, "meta", "npm:other", fail); !errors.Is(err, cache.ErrOffline) {
		t.Errorf("offline miss: %v, want ErrOffline", err)
	}
	// Online with the network down, stale data is better than none.
	down := &cache.Store{Dir: dir, TTL: time.Nanosecond}
	v, stale, err = cache.Load(down, ctx, "meta", "npm:left-pad", func(context.Context) (string, error) { return "", errors.New("down") })
	if err != nil || v != "1.3.0" || !stale {
		t.Errorf("fallback load %q, stale %v, %v", v, stale, err)
	}
}

// TestRedactPackageCredentials covers what a package, a lockfile or the
// user's config may hold: an npm token, a Composer http-basic password,
// a github-oauth token, a password in a URL and a wp-config.php key.
func TestRedactPackageCredentials(t *testing.T) {
	npm := join("npm", "_", "Zq9AbCdEf123GhIjKlMnOpQrStUvWxYz0123")
	pass := join("Zq9", "AbCdEf123GhIjK")
	gh := join("gh", "o_", "Zq9AbCdEf123GhIjKlMnOpQrStUvWxYz0123")
	authKey := join("p8&Zq9", "AbCdEf123!GhIjK)lMn")
	for _, c := range []struct{ name, in, gone string }{
		{"npm token", "//registry.npmjs.org/:_authToken=" + npm, npm},
		{"bare npm token", "token " + npm + " in a script", npm},
		{"composer http-basic", `{"http-basic": {"repo.acme.example": {"username": "ann", "password": "` + pass + `"}}}`, pass},
		{"github-oauth", `{"github-oauth": {"github.com": "` + gh + `"}}`, gh},
		{"url password", "https://deploy:" + pass + "@repo.acme.example/packages.json", pass},
		{"wp-config AUTH_KEY", "define( 'AUTH_KEY', '" + authKey + "' );", authKey},
	} {
		if out := secrets.Redact(c.in); strings.Contains(out, c.gone) {
			t.Errorf("%s: Redact(%q) = %q, the secret is still there", c.name, c.in, out)
		}
	}
	for _, in := range []string{"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", `{"name": "left-pad", "version": "1.3.0"}`} {
		if out := secrets.Redact(in); out != in {
			t.Errorf("Redact(%q) = %q, want it unchanged", in, out)
		}
	}
}

// TestTermSanitize: package text in a terminal shows escape bytes as
// \x1b and drops bidi overrides (Trojan Source), so neither moves the
// cursor nor reorders what the reader sees.
func TestTermSanitize(t *testing.T) {
	in := "ok\x1b[2J \u202eevil\u2066 \x07"
	out := term.Sanitize(in)
	if strings.ContainsAny(out, "\x1b\u202e\u2066\x07") {
		t.Errorf("Sanitize(%q) = %q, still holds control or bidi characters", in, out)
	}
	if !strings.Contains(out, `\x1b`) || !strings.Contains(out, `\x07`) {
		t.Errorf("Sanitize(%q) = %q, want the escapes shown", in, out)
	}
	if got := term.Sanitize("plain text\nnext line"); got != "plain text\nnext line" {
		t.Errorf("plain text changed: %q", got)
	}
	if got := term.EscapeMarkdown("@team [x](https://evil.example)"); strings.Contains(got, "](") && !strings.Contains(got, `\]`) {
		t.Errorf("EscapeMarkdown left a link: %q", got)
	}
}

// TestFirstRunOnce: the first-run note shows once per machine.
func TestFirstRunOnce(t *testing.T) {
	t.Setenv(config.EnvConfigDir, t.TempDir())
	if !config.FirstRun("sightread-first-run") {
		t.Fatal("first call isn't the first run")
	}
	if config.FirstRun("sightread-first-run") {
		t.Error("second call is a first run again")
	}
	if !config.FirstRun("other-tool-first-run") {
		t.Error("another key shares the marker")
	}
}
