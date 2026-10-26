// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package probes

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	neturl "net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Front modes: how a Front misbehaves before it passes a request on.
const (
	// FrontModeRetry answers 429 with Retry-After: 1 to the first request
	// for each path, then proxies.
	FrontModeRetry = "retry"
	// FrontModeStall proxies metadata but never sends a tarball body:
	// the headers promise one, then nothing comes until the client gives
	// up.
	FrontModeStall = "stall"
)

// Front is a reverse proxy in front of the fixture registry on another
// loopback port that misbehaves in one way. It keeps the Host header,
// so the documents the registry builds (tarball URLs) point back at the
// front and the fault reaches the download too.
type Front struct {
	mode     string
	srv      *http.Server
	mu       sync.Mutex
	seen     map[string]int
	limited  atomic.Int32
	stalled  atomic.Int32
	requests atomic.Int32
	port     int
}

// StartFront serves mode on 127.0.0.1:port (0 picks a free port; see
// Port), proxying to upstream (for
// example https://127.0.0.1:18903). serverTLS is the registry's TLS
// configuration so the front presents a certificate of the same CA; nil
// serves plain HTTP. caPEM verifies the upstream; nil trusts the system
// pool.
func StartFront(port int, mode, upstream string, serverTLS *tls.Config, caPEM []byte) (*Front, error) {
	if mode != FrontModeRetry && mode != FrontModeStall {
		return nil, fmt.Errorf("front mode %q: want %s or %s", mode, FrontModeRetry, FrontModeStall)
	}
	target, err := neturl.Parse(upstream)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil // loopback to loopback; never through the guard
	if caPEM != nil {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("front: the CA PEM holds no certificate")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(target)
			pr.Out.Host = pr.In.Host
		},
		Transport: transport,
	}
	f := &Front{mode: mode, seen: map[string]int{}}
	f.srv = &http.Server{Handler: f.handler(rp), ReadHeaderTimeout: 10 * time.Second}

	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("front listen %d: %w", port, err)
	}
	f.port = ln.Addr().(*net.TCPAddr).Port
	if serverTLS != nil {
		ln = tls.NewListener(ln, serverTLS)
	}
	go func() { _ = f.srv.Serve(ln) }()
	return f, nil
}

// handler wraps the proxy with the front's fault.
func (f *Front) handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		f.requests.Add(1)
		switch f.mode {
		case FrontModeRetry:
			f.mu.Lock()
			f.seen[req.URL.Path]++
			first := f.seen[req.URL.Path] == 1
			f.mu.Unlock()
			if first {
				f.limited.Add(1)
				w.Header().Set("Retry-After", "1")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
		case FrontModeStall:
			if strings.Contains(req.URL.Path, "/-/") && strings.HasSuffix(req.URL.Path, ".tgz") {
				f.stalled.Add(1)
				w.Header().Set("Content-Length", "1048576")
				w.WriteHeader(http.StatusOK)
				if fl, ok := w.(http.Flusher); ok {
					fl.Flush()
				}
				<-req.Context().Done()
				return
			}
		}
		next.ServeHTTP(w, req)
	})
}

// Port returns the port the front listens on.
func (f *Front) Port() int { return f.port }

// Limited counts the 429 answers given.
func (f *Front) Limited() int { return int(f.limited.Load()) }

// Stalled counts the tarball downloads held open.
func (f *Front) Stalled() int { return int(f.stalled.Load()) }

// Requests counts every request the front received.
func (f *Front) Requests() int { return int(f.requests.Load()) }

// Reset forgets which paths were already answered with 429 and zeroes
// the counters, so a second run sees the same fault.
func (f *Front) Reset() {
	f.mu.Lock()
	f.seen = map[string]int{}
	f.mu.Unlock()
	f.limited.Store(0)
	f.stalled.Store(0)
	f.requests.Store(0)
}

// Close stops the front, ending any stalled body.
func (f *Front) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := f.srv.Shutdown(ctx); err != nil {
		return f.srv.Close()
	}
	return nil
}
