// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build testbed

package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestForwardedCredentials reads a recorded request log: a codeload
// request with an Authorization header is a forwarded token, one without
// it is not; a token sent to the GitHub API is expected.
func TestForwardedCredentials(t *testing.T) {
	state := t.TempDir()
	log := `{"service":"github","host":"127.0.0.1:18902","method":"GET","path":"/repos/acme/lib/zipball/abc","auth":true}
{"service":"codeload","host":"localhost:18908","method":"GET","path":"/acme/lib/legacy.zip/abc"}
{"service":"codeload","host":"localhost:18908","method":"GET","path":"/acme/helper/legacy.zip/def","auth":true}
not json
`
	if err := os.WriteFile(filepath.Join(state, "requests.log"), []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &harness{state: state}
	got := h.forwardedCredentials()
	want := []string{"GET localhost:18908/acme/helper/legacy.zip/def"}
	if !slices.Equal(got, want) {
		t.Errorf("forwarded = %v, want %v", got, want)
	}
	if f := h.foreignRequests(); len(f) != 0 {
		t.Errorf("loopback requests counted as foreign: %v", f)
	}

	clean := `{"service":"codeload","host":"localhost:18908","method":"GET","path":"/acme/lib/legacy.zip/abc"}` + "\n"
	if err := os.WriteFile(filepath.Join(state, "requests.log"), []byte(clean), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := h.forwardedCredentials(); len(got) != 0 {
		t.Errorf("a codeload request without a token counted as forwarded: %v", got)
	}
}
