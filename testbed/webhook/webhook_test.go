// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package webhook

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestWebhookStoresDeliveries(t *testing.T) {
	r, err := NewOn(0)
	if err != nil {
		t.Fatal(err)
	}
	r.Start()
	defer r.Close()

	url := fmt.Sprintf("http://127.0.0.1:%d/notify", r.Port())
	// Give the listener a moment to accept.
	deadline := time.Now().Add(2 * time.Second)
	var resp *http.Response
	for time.Now().Before(deadline) {
		resp, err = http.Post(url, "application/json", strings.NewReader(`{"verdict":"hold"}`)) //nolint:noctx // test
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()

	deliveries := r.Deliveries()
	if len(deliveries) != 1 {
		t.Fatalf("want 1 delivery, got %d", len(deliveries))
	}
	if deliveries[0].Path != "/notify" || !strings.Contains(string(deliveries[0].Body), "hold") {
		t.Fatalf("unexpected delivery: %+v", deliveries[0])
	}
	r.Reset()
	if len(r.Deliveries()) != 0 {
		t.Fatal("Reset did not clear deliveries")
	}
}
