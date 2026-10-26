// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package probes

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/testbed/ports"
)

// start brings the probe set up once for the package's tests.
func start(t *testing.T) *Set {
	t.Helper()
	s, err := StartAnyPort()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func url(port int, path string) string { return fmt.Sprintf("http://127.0.0.1:%d%s", port, path) }

// noRedirect is a client that returns the redirect response itself.
func noRedirect() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func TestStallTimesOut(t *testing.T) {
	s := start(t)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url(s.Port(ports.ProbeStall), "/"), nil)
	resp, err := http.DefaultClient.Do(req)
	if err == nil {
		_, err = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal("stall probe should have timed out the body read")
	}
}

func TestRetryThen200(t *testing.T) {
	s := start(t)
	resp, err := http.Get(url(s.Port(ports.ProbeRetry), "/pkg")) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("first attempt: want 429, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("429 should carry Retry-After")
	}
	resp, err = http.Get(url(s.Port(ports.ProbeRetry), "/pkg")) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second attempt: want 200, got %d", resp.StatusCode)
	}
}

func TestSSRFRedirect(t *testing.T) {
	s := start(t)
	resp, err := noRedirect().Get(url(s.Port(ports.ProbeSSRF), "/")) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if loc := resp.Header.Get("Location"); loc != "http://169.254.169.254/latest/meta-data/" {
		t.Fatalf("unexpected redirect target: %q", loc)
	}
}

func TestRedirectLoopbackCounts(t *testing.T) {
	s := start(t)
	before := s.RedirectHits()
	resp, err := noRedirect().Get(url(s.Port(ports.ProbeRedirectLoopback), "/")) //nolint:noctx // test
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := fmt.Sprintf("http://127.0.0.1:%d/", s.Unconfigured()); resp.Header.Get("Location") != got {
		t.Fatalf("want redirect to %s, got %q", got, resp.Header.Get("Location"))
	}
	if s.RedirectHits() != before+1 {
		t.Fatalf("redirect hit counter did not advance: %d -> %d", before, s.RedirectHits())
	}
}

func TestSelfSignedTLSRejected(t *testing.T) {
	s := start(t)
	// A verifying client must reject the self-signed certificate.
	verifying := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12}}}
	resp, err := verifying.Get(fmt.Sprintf("https://127.0.0.1:%d/", s.Port(ports.ProbeSelfTLS))) //nolint:noctx // test
	if err == nil {
		_ = resp.Body.Close()
		t.Fatal("a verifying client should reject the self-signed probe")
	}
	var certErr *tls.CertificateVerificationError
	if !errors.As(err, &certErr) {
		t.Logf("rejected with: %v", err)
	}
}
