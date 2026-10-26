// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package coretest

import (
	"net/http"
	"os"
	"strings"
	"testing"
)

// Kinds of FakeKey.
const (
	KeyNPM    = "npm"
	KeyGitHub = "github"
	KeyStripe = "stripe"
	KeyAWS    = "aws"
	KeySlack  = "slack"
)

// FakeKeyKinds lists every kind FakeKey makes.
func FakeKeyKinds() []string { return []string{KeyNPM, KeyGitHub, KeyStripe, KeyAWS, KeySlack} }

// FakeKey returns a fake credential of kind, shaped so kit secrets
// finds it. Each is assembled at run time from parts: a literal key in
// the source would trip GitHub push protection and secret scanners.
func FakeKey(kind string) string {
	j := func(parts ...string) string { return strings.Join(parts, "") }
	switch kind {
	case KeyNPM:
		return j("npm", "_", "Fk3sightreadTEST", "0nly4Fixtures9xQ2wZa")
	case KeyGitHub:
		return j("gh", "p_", "Fk3sightreadTEST0nly", "4Fixtures9xQ2wZaB")
	case KeyStripe:
		return j("sk", "_live_", "Fk3sightreadTEST", "0nly4Fixtures")
	case KeyAWS:
		return j("AK", "IA", "FK3SIGHTREAD", "TEST")
	case KeySlack:
		return j("https://hooks.", "slack.com/services/", "T0FAKE0001/", "B0FAKE0002/", "Fk3sightreadTEST0nly4Fix")
	}
	panic("coretest.FakeKey: unknown kind " + kind)
}

// RequireLinkedEnv makes the Need* helpers fail instead of skip: make
// test-integrated, the nightly and the release checklist set it.
const RequireLinkedEnv = "SIGHTREAD_REQUIRE_LINKED"

// need skips (or fails when RequireLinkedEnv is 1) when ok is false.
func need(t testing.TB, ok bool, stage string) {
	t.Helper()
	if ok {
		return
	}
	if os.Getenv(RequireLinkedEnv) == "1" {
		t.Fatalf("%s not linked (%s=1)", stage, RequireLinkedEnv)
	}
	t.Skipf("%s not linked yet", stage)
}

// LoopbackOnly returns a transport that fails the test on any request
// whose host is not 127.0.0.1 or ::1 and otherwise sends it with a
// clone of http.DefaultTransport.
func LoopbackOnly(t testing.TB) http.RoundTripper {
	t.Helper()
	base := http.DefaultTransport.(*http.Transport).Clone()
	t.Cleanup(base.CloseIdleConnections)
	return loopback{t: t, base: base}
}

type loopback struct {
	t    testing.TB
	base http.RoundTripper
}

// errNotLoopback is what a refused request fails with.
type errNotLoopback struct{ host string }

func (e errNotLoopback) Error() string {
	return "coretest.LoopbackOnly: request to " + e.host + " refused; tests reach 127.0.0.1 only"
}

func (l loopback) RoundTrip(req *http.Request) (*http.Response, error) {
	if h := req.URL.Hostname(); h != "127.0.0.1" && h != "::1" {
		l.t.Errorf("request to %s: tests may reach only 127.0.0.1 or ::1", req.URL.Host)
		return nil, errNotLoopback{req.URL.Host}
	}
	return l.base.RoundTrip(req)
}
