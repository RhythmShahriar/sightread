// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package webhook is the testbed's notification receiver. A watch run
// that is configured with a webhook+http notifier posts here; the
// notification tests read the deliveries back to check the grouping and
// the minimum severity.
package webhook

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/RhythmShahriar/sightread/testbed/ports"
)

// Delivery is one received request.
type Delivery struct {
	Received time.Time
	Path     string
	Body     []byte
}

// Receiver is the running webhook endpoint.
type Receiver struct {
	srv  *http.Server
	ln   net.Listener
	mu   sync.Mutex
	recv []Delivery
}

// New creates a receiver bound to the webhook port.
func New() (*Receiver, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", ports.Webhook))
	if err != nil {
		return nil, fmt.Errorf("webhook listen: %w", err)
	}
	r := &Receiver{ln: ln}
	r.srv = &http.Server{Handler: http.HandlerFunc(r.handle), ReadHeaderTimeout: 10 * time.Second}
	return r, nil
}

// Start serves in the background.
func (r *Receiver) Start() {
	go func() { _ = r.srv.Serve(r.ln) }()
}

// handle stores every request body.
func (r *Receiver) handle(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(req.Body, 1<<20))
	r.mu.Lock()
	r.recv = append(r.recv, Delivery{Received: time.Now().UTC(), Path: req.URL.Path, Body: body})
	r.mu.Unlock()
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"ok":true}`))
}

// Deliveries returns the received requests in order.
func (r *Receiver) Deliveries() []Delivery {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Delivery, len(r.recv))
	copy(out, r.recv)
	return out
}

// Reset clears the received requests.
func (r *Receiver) Reset() {
	r.mu.Lock()
	r.recv = nil
	r.mu.Unlock()
}

// Close stops the receiver.
func (r *Receiver) Close() error { return r.srv.Close() }
