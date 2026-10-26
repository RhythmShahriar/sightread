// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package fetch

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// The ports this package's tests may listen on.
const firstPort, lastPort = 31000, 31019

// listen takes the first free port of the range.
func listen(t *testing.T) net.Listener {
	t.Helper()
	for p := firstPort; p <= lastPort; p++ {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			return l
		}
	}
	t.Fatalf("no free port in 127.0.0.1:%d-%d", firstPort, lastPort)
	return nil
}

// serve starts h over TLS (or plain http) on a port of the range.
func serve(t *testing.T, h http.Handler, tls bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	_ = srv.Listener.Close()
	srv.Listener = listen(t)
	// The self-signed test makes the server log a failed handshake.
	srv.Config.ErrorLog = log.New(io.Discard, "", 0)
	if tls {
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	return srv
}

// counter is a handler that counts hits and answers with h.
type counter struct {
	mu   sync.Mutex
	hits int
	h    http.HandlerFunc
}

func (c *counter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.mu.Lock()
	c.hits++
	c.mu.Unlock()
	if c.h != nil {
		c.h(w, r)
	}
}

func (c *counter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits
}

// loopbackOnly fails the test on a request that leaves loopback and
// otherwise hands it to the client's own transport, so the dialers and
// TLS settings under test stay in the path (coretest.LoopbackOnly sends
// with a transport of its own).
type loopbackOnly struct {
	t    testing.TB
	next http.RoundTripper
}

func (l loopbackOnly) RoundTrip(req *http.Request) (*http.Response, error) {
	if h := req.URL.Hostname(); h != "127.0.0.1" && h != "::1" && h != "localhost" {
		l.t.Errorf("request to %s: tests may reach only 127.0.0.1", req.URL.Host)
		return nil, fmt.Errorf("test request to %s refused", req.URL.Host)
	}
	return l.next.RoundTrip(req)
}

// client builds a client that trusts the httptest certificate of srvs
// and may reach loopback only.
func client(t *testing.T, cfg core.GetterConfig, srvs ...*httptest.Server) *Client {
	t.Helper()
	roots := x509.NewCertPool()
	for _, s := range srvs {
		if s.Certificate() != nil {
			roots.AddCert(s.Certificate())
		}
	}
	c, err := newClient(cfg, testHooks{roots: roots, wrap: func(rt http.RoundTripper) http.RoundTripper {
		return loopbackOnly{t: t, next: rt}
	}})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// recordBlobs is a BlobStore that remembers what it stored.
type recordBlobs struct {
	core.BlobStore
	mu     sync.Mutex
	stored [][32]byte
}

func newRecordBlobs() *recordBlobs { return &recordBlobs{BlobStore: coretest.MemBlobs()} }

func (r *recordBlobs) Put(ctx context.Context, rd io.Reader, limit int64) ([32]byte, int64, error) {
	sum, n, err := r.BlobStore.Put(ctx, rd, limit)
	if err == nil {
		r.mu.Lock()
		r.stored = append(r.stored, sum)
		r.mu.Unlock()
	}
	return sum, n, err
}

func (r *recordBlobs) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.stored)
}

// read returns a stored blob.
func read(t *testing.T, b core.BlobStore, sum [32]byte) []byte {
	t.Helper()
	rc, err := b.Open(sum)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	data, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(data) != sum {
		t.Fatal("blob does not match its hash")
	}
	return data
}

// endless writes x forever until the client goes away.
func endless(w http.ResponseWriter, r *http.Request) {
	chunk := bytes.Repeat([]byte("x"), 32<<10)
	for r.Context().Err() == nil {
		if _, err := w.Write(chunk); err != nil {
			return
		}
	}
}
