// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package probes serves the hostile and broken endpoints the environment
// scenarios need, on loopback and without any Docker. Each probe stands
// in for one way a server can misbehave: a body that never finishes, an
// endless body, a rate limit, a redirect to the cloud metadata address,
// a redirect to an unconfigured port and a self-signed certificate.
package probes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RhythmShahriar/sightread/testbed/ports"
)

// Set is the running probe set.
type Set struct {
	servers      []*http.Server
	listeners    []net.Listener
	retryState   sync.Map // path -> *int32 attempts
	redirectHits int32
	// anyPort binds free ports; bound maps each documented port to the
	// bound one and unconfigured is where the loopback redirect points.
	anyPort      bool
	bound        map[int]int
	unconfigured int
}

// Start binds every probe on its documented port and serves in the
// background.
func Start() (*Set, error) { return startSet(false) }

// StartAnyPort binds every probe on a free loopback port, so unit tests
// run beside make up or a bench; Port maps a documented port to the
// bound one.
func StartAnyPort() (*Set, error) { return startSet(true) }

func startSet(anyPort bool) (*Set, error) {
	s := &Set{anyPort: anyPort, bound: map[int]int{}, unconfigured: ports.ProbeUnconfigured}
	if anyPort {
		// A port that was free a moment ago and has nothing on it now.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, err
		}
		s.unconfigured = ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
	}
	plain := map[int]http.HandlerFunc{
		ports.ProbeStall:            s.stall,
		ports.ProbeEndless:          s.endless,
		ports.ProbeRetry:            s.retry,
		ports.ProbeSSRF:             s.ssrf,
		ports.ProbeRedirectLoopback: s.redirectLoopback,
	}
	for port, h := range plain {
		if err := s.serve(port, h, nil); err != nil {
			_ = s.Close()
			return nil, err
		}
	}
	tlsConf, err := selfSigned()
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	if err := s.serve(ports.ProbeSelfTLS, s.ok, tlsConf); err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}

// Port returns the port the probe documented as port is bound to.
func (s *Set) Port(port int) int {
	if p, ok := s.bound[port]; ok {
		return p
	}
	return port
}

// Unconfigured is the loopback port the redirect probe points at, where
// nothing listens: ports.ProbeUnconfigured unless started on any port.
func (s *Set) Unconfigured() int { return s.unconfigured }

// serve binds one probe on 127.0.0.1:port, or on a free port.
func (s *Set) serve(port int, h http.HandlerFunc, tlsConf *tls.Config) error {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if s.anyPort {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("probe listen %d: %w", port, err)
	}
	s.bound[port] = ln.Addr().(*net.TCPAddr).Port
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	if tlsConf != nil {
		srv.TLSConfig = tlsConf
		ln = tls.NewListener(ln, tlsConf)
	}
	s.servers = append(s.servers, srv)
	s.listeners = append(s.listeners, ln)
	go func() { _ = srv.Serve(ln) }()
	return nil
}

// ok answers 200, used behind the self-signed TLS probe.
func (s *Set) ok(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }

// stall sends a Content-Length header promising a body, then never sends
// it until the client gives up, which exercises the per-request timeout.
func (s *Set) stall(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Length", "1024")
	w.WriteHeader(http.StatusOK)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	<-req.Context().Done()
}

// endless streams forever until the client gives up, which exercises the
// uncompressed streaming cap.
func (s *Set) endless(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	flush, _ := w.(http.Flusher)
	buf := make([]byte, 32*1024)
	for {
		select {
		case <-req.Context().Done():
			return
		default:
			if _, err := w.Write(buf); err != nil {
				return
			}
			if flush != nil {
				flush.Flush()
			}
		}
	}
}

// retry answers 429 with Retry-After on the first attempt for a path and
// 200 after that, so a client that respects Retry-After succeeds.
func (s *Set) retry(w http.ResponseWriter, req *http.Request) {
	v, _ := s.retryState.LoadOrStore(req.URL.Path, new(int32))
	n := atomic.AddInt32(v.(*int32), 1)
	if n == 1 {
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	_, _ = w.Write([]byte("ok"))
}

// ssrf redirects to the cloud metadata address, which the client must
// refuse (it is neither loopback nor an allowlisted host).
func (s *Set) ssrf(w http.ResponseWriter, req *http.Request) {
	http.Redirect(w, req, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
}

// redirectLoopback redirects to an unconfigured loopback port and counts
// how often it is reached, so a test can prove an off-allowlist loopback
// hop is refused (the counter stays at the redirects issued; nothing
// reaches the dead port).
func (s *Set) redirectLoopback(w http.ResponseWriter, req *http.Request) {
	atomic.AddInt32(&s.redirectHits, 1)
	http.Redirect(w, req, fmt.Sprintf("http://127.0.0.1:%d/", s.unconfigured), http.StatusFound)
}

// RedirectHits returns how often the loopback-redirect probe was reached.
func (s *Set) RedirectHits() int { return int(atomic.LoadInt32(&s.redirectHits)) }

// Close stops every probe.
func (s *Set) Close() error {
	var err error
	for _, srv := range s.servers {
		if e := srv.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

// selfSigned builds a TLS config with a certificate signed by no known
// authority, so a verifying client rejects it.
func selfSigned() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "probe self-signed"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MinVersion:   tls.VersionTLS12,
	}, nil
}
