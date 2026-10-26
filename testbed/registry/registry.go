// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/RhythmShahriar/sightread/testbed/ports"
)

// Options configure a Registry.
type Options struct {
	// PackagesDir holds the scenario folders (testbed/packages).
	PackagesDir string
	// StateDir holds scenario state, the CA and the request log
	// (testbed/state).
	StateDir string
	// PlainHTTP serves plain HTTP instead of TLS, for the loopback
	// mirror tests. The default is TLS with the generated CA.
	PlainHTTP bool
	// AnyPort binds every listener to a free loopback port instead of
	// the documented one, so unit tests run beside make up or a bench.
	// Port maps a documented port to the bound one.
	AnyPort bool
	// Now is the run start, against which relative publish times resolve.
	// The zero value means time.Now at New.
	Now time.Time
}

// Registry is the running fixture registry: the built packages, the
// per-run CA and npm key, the request log and the listeners.
type Registry struct {
	opts    Options
	ca      *certAuthority
	npm     *npmSigner
	log     *reqLog
	pkgs    []*builtPkg
	servers []*http.Server
	// bound maps a documented port to the one a listener got. It is
	// empty until Start and identical unless AnyPort is set.
	bound map[int]int
}

// New loads every scenario, builds its archives, generates the CA and
// npm signing key and prepares the request log. It does not listen yet;
// call Start.
func New(opts Options) (*Registry, error) {
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	if err := os.MkdirAll(opts.StateDir, 0o755); err != nil { //nolint:gosec // testbed state
		return nil, err
	}
	r := &Registry{opts: opts}

	ids, err := scenarioIDs(opts.PackagesDir)
	if err != nil {
		return nil, fmt.Errorf("read packages: %w", err)
	}
	for _, id := range ids {
		m, err := loadMeta(scenarioMetaPath(opts.PackagesDir, id))
		if err != nil {
			return nil, err
		}
		bp, err := build(opts.PackagesDir, id, m, opts.Now)
		if err != nil {
			return nil, err
		}
		r.pkgs = append(r.pkgs, bp)
	}

	if r.npm, err = newNPMSigner(); err != nil {
		return nil, err
	}
	if err := r.signNPM(); err != nil {
		return nil, err
	}
	if err := r.npm.writeKeys(filepath.Join(opts.StateDir, "npm-keys.json")); err != nil {
		return nil, err
	}

	if !opts.PlainHTTP {
		if r.ca, err = newCA(); err != nil {
			return nil, err
		}
		if err := r.ca.writePEM(filepath.Join(opts.StateDir, "ca.pem")); err != nil {
			return nil, err
		}
	}

	if r.log, err = openReqLog(filepath.Join(opts.StateDir, "requests.log")); err != nil {
		return nil, err
	}
	return r, nil
}

// signNPM signs every npm version with the per-run key.
func (r *Registry) signNPM() error {
	for _, p := range r.pkgs {
		if p.meta.Ecosystem != "npm" {
			continue
		}
		for _, bv := range p.versions {
			sig, err := r.npm.sign(p.meta.Name, bv.meta.Version, bv.integrity)
			if err != nil {
				return err
			}
			bv.signature = sig
		}
	}
	return nil
}

// Start binds every listener and serves in the background. The caller
// closes the registry with Close.
func (r *Registry) Start() error {
	routes := []struct {
		port    int
		service string
		mux     *http.ServeMux
	}{
		{ports.WPOrg, "wporg", r.wporgMux()},
		{ports.Packagist, "packagist", r.packagistMux()},
		{ports.GitHub, "github", r.githubMux()},
		{ports.NPM, "npm", r.npmMux()},
		{ports.OSV, "osv", r.osvMux()},
		{ports.Codeload, ServiceCodeload, r.codeloadMux()},
	}
	r.bound = map[int]int{}
	for _, rt := range routes {
		if err := r.serve(rt.port, rt.service, rt.mux); err != nil {
			_ = r.Close()
			return err
		}
	}
	return nil
}

// Port returns the port the listener documented as port is bound to:
// port itself unless Options.AnyPort is set.
func (r *Registry) Port(port int) int {
	if p, ok := r.bound[port]; ok {
		return p
	}
	return port
}

// serve starts one listener on 127.0.0.1:port, or on a free port with
// AnyPort.
func (r *Registry) serve(port int, service string, mux *http.ServeMux) error {
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	if r.opts.AnyPort {
		addr = "127.0.0.1:0"
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	r.bound[port] = ln.Addr().(*net.TCPAddr).Port
	srv := &http.Server{
		Handler:           r.logging(service, mux),
		ReadHeaderTimeout: 10 * time.Second,
	}
	if !r.opts.PlainHTTP {
		srv.TLSConfig = r.ca.tlsConfig()
		ln = tls.NewListener(ln, srv.TLSConfig)
	}
	r.servers = append(r.servers, srv)
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintf(os.Stderr, "registry: serve %s: %v\n", addr, err)
		}
	}()
	return nil
}

// ServiceCodeload is the service name the request log gives the codeload
// listener. No request there may carry an Authorization header.
const ServiceCodeload = "codeload"

// logging records every request before handing it to the mux.
func (r *Registry) logging(service string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		r.log.record(service, req.Host, req.Method, req.URL.Path, req.URL.RawQuery, req.Header.Get("Authorization") != "")
		next.ServeHTTP(w, req)
	})
}

// Close shuts every listener down and closes the request log.
func (r *Registry) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var err error
	for _, s := range r.servers {
		if e := s.Shutdown(ctx); e != nil {
			err = errors.Join(err, e)
		}
	}
	if r.log != nil {
		err = errors.Join(err, r.log.Close())
	}
	return err
}

// CACertPEM returns the PEM of the per-run CA, or nil in plain HTTP mode.
func (r *Registry) CACertPEM() []byte {
	if r.ca == nil {
		return nil
	}
	return r.ca.certPEM
}

// NPMKeyID returns the key id of the per-run npm signing key.
func (r *Registry) NPMKeyID() string { return r.npm.keyID }

// state reads the current state of a scenario.
func (r *Registry) state(id string) string { return readState(r.opts.StateDir, id) }

// publishedVersions returns the version numbers a package offers in its
// current state, oldest first. In the good state the candidate is
// withheld, so the newest offered version is the installed one.
func (r *Registry) publishedVersions(p *builtPkg) []string {
	// A republished version keeps its number in both states; only its
	// bytes change, so it is always published.
	if r.state(p.id) == StateBad || p.republishAlt != nil {
		return p.order
	}
	out := make([]string, 0, len(p.order))
	for _, v := range p.order {
		if v == p.candidate {
			continue
		}
		out = append(out, v)
	}
	return out
}

// latestVersion returns the newest offered version in the current state.
func (r *Registry) latestVersion(p *builtPkg) string {
	vs := r.publishedVersions(p)
	if len(vs) == 0 {
		return ""
	}
	return vs[len(vs)-1]
}

// lookups by ecosystem and name.

func (r *Registry) find(eco, name string) (*builtPkg, bool) {
	for _, p := range r.pkgs {
		if p.meta.Ecosystem == eco && p.meta.Name == name {
			return p, true
		}
	}
	return nil, false
}

func (r *Registry) findGitHub(owner, repo string) (*builtPkg, bool) {
	for _, p := range r.pkgs {
		if p.meta.Ecosystem != "composer" {
			continue
		}
		o, n := ownerRepo(p.meta.Repository)
		if o == owner && n == repo {
			return p, true
		}
	}
	return nil, false
}
