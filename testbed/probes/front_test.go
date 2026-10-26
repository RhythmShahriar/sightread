// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package probes

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"strings"
	"testing"
	"time"
)

// Test ports for the fronts and the guard, outside the testbed's own
// ranges so a running testbed and the tests never collide.
const (
	testFrontRetry = 31120
	testFrontStall = 31121
	testGuard      = 31122
)

// upstream echoes the Host it received and the path.
func upstream(t *testing.T) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "%s %s", r.Host, r.URL.Path)
	}))
	t.Cleanup(s.Close)
	return s
}

func noProxyClient() *http.Client {
	return &http.Client{Transport: &http.Transport{Proxy: nil}, Timeout: 5 * time.Second}
}

func TestFrontRetry(t *testing.T) {
	f, err := StartFront(testFrontRetry, FrontModeRetry, upstream(t).URL, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c := noProxyClient()
	base := fmt.Sprintf("http://127.0.0.1:%d", testFrontRetry)

	resp, err := c.Get(base + "/retrylib")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("first request: %d Retry-After %q, want 429 and 1", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	resp, err = c.Get(base + "/retrylib")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	// The Host header is kept, so the registry builds URLs on the front.
	if resp.StatusCode != http.StatusOK || string(body) != fmt.Sprintf("127.0.0.1:%d /retrylib", testFrontRetry) {
		t.Fatalf("second request: %d %q", resp.StatusCode, body)
	}
	if f.Limited() != 1 || f.Requests() != 2 {
		t.Errorf("limited %d requests %d, want 1 and 2", f.Limited(), f.Requests())
	}
	f.Reset()
	resp, err = c.Get(base + "/retrylib")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("after Reset: %d, want 429 again", resp.StatusCode)
	}
}

func TestFrontStall(t *testing.T) {
	f, err := StartFront(testFrontStall, FrontModeStall, upstream(t).URL, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	c := noProxyClient()
	base := fmt.Sprintf("http://127.0.0.1:%d", testFrontStall)

	// Metadata passes through.
	resp, err := c.Get(base + "/stalllib")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metadata: %d", resp.StatusCode)
	}

	// The tarball body never comes; the client's deadline ends it.
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base+"/stalllib/-/stalllib-1.0.1.tgz", nil)
	start := time.Now()
	resp, err = c.Do(req)
	if err == nil {
		_, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("a stalled tarball finished")
	}
	if time.Since(start) > 3*time.Second {
		t.Errorf("the stall outlived the client deadline: %s", time.Since(start))
	}
	if f.Stalled() != 1 {
		t.Errorf("stalled %d, want 1", f.Stalled())
	}
}

func TestFrontRefusesUnknownMode(t *testing.T) {
	if _, err := StartFront(testFrontRetry, "flaky", "http://127.0.0.1:1", nil, nil); err == nil {
		t.Fatal("an unknown mode was accepted")
	}
}

func TestGuardCountsAndRefuses(t *testing.T) {
	g, err := StartGuard(testGuard)
	if err != nil {
		t.Fatal(err)
	}
	proxy, _ := neturl.Parse(fmt.Sprintf("http://127.0.0.1:%d", testGuard))
	c := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}, Timeout: 5 * time.Second}

	// Documentation addresses (RFC 5737): never contacted, the guard
	// answers first.
	for _, u := range []string{"https://192.0.2.1/x", "http://192.0.2.2/y"} {
		resp, err := c.Get(u)
		if err == nil {
			_ = resp.Body.Close()
			t.Errorf("%s went through the guard", u)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for g.Count() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	got := strings.Join(g.Attempts(), "\n")
	if g.Count() != 2 || !strings.Contains(got, "CONNECT 192.0.2.1:443") || !strings.Contains(got, "GET http://192.0.2.2/y") {
		t.Errorf("attempts %d:\n%s", g.Count(), got)
	}
	if err := g.Close(); err != nil {
		t.Error(err)
	}
}
