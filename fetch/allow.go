// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package fetch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/httpx"

	"github.com/RhythmShahriar/sightread/core"
)

// allowlist is every host:port the Getter may reach. A hop is allowed
// when its scheme and canonical address are listed: official hosts and
// configured https mirrors under https, loopback mirrors under the
// scheme their base names.
type allowlist struct {
	https map[string]bool
	http  map[string]bool
	// loop are the loopback mirrors. Only these are dialed on a loopback
	// address, by a transport that can reach nothing else.
	loop map[string]bool
}

// canonical is u's host:port, lower case, without a trailing dot and with
// the scheme's default port.
func canonical(u *url.URL) string {
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	port := u.Port()
	if port == "" {
		switch strings.ToLower(u.Scheme) {
		case "http":
			port = "80"
		default:
			port = "443"
		}
	}
	return net.JoinHostPort(host, port)
}

// hostAddr is a configured host ("gitlab.example" or "mirror:8443") as an
// https host:port.
func hostAddr(h string) string {
	return canonical(&url.URL{Scheme: "https", Host: strings.TrimSpace(h)})
}

// loopbackHost reports whether a base may use plain http: its host is
// exactly 127.0.0.1, ::1 or localhost.
func loopbackHost(host string) bool {
	switch strings.ToLower(host) {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return false
}

// IsLoopbackBase reports whether base is a URL on 127.0.0.1, ::1 or
// localhost: a mirror on this machine (the testbed and the demo).
func IsLoopbackBase(base string) bool {
	u, err := url.Parse(base)
	return err == nil && u.Host != "" && loopbackHost(u.Hostname())
}

// newAllowlist builds the allowlist from the defaults, cfg.Hosts and
// cfg.Bases. A base that is not an https URL, or an http one off
// loopback, is an E12 error naming where it came from.
func newAllowlist(cfg core.GetterConfig) (*allowlist, error) {
	a := &allowlist{https: map[string]bool{}, http: map[string]bool{}, loop: map[string]bool{}}
	for _, h := range DefaultHosts() {
		a.https[hostAddr(h)] = true
	}
	for _, h := range cfg.Hosts {
		if strings.TrimSpace(h) == "" || strings.ContainsAny(h, "/?#@") {
			return nil, configError(fmt.Sprintf("allowed host %q is not a host name", h), "give a bare host such as repo.example.com")
		}
		addr := hostAddr(h)
		if host, _, _ := net.SplitHostPort(addr); loopbackHost(host) || isLoopbackAddr(addr) {
			return nil, configError(fmt.Sprintf("allowed host %q is a loopback address", h), "name a loopback mirror by its base URL (SIGHTREAD_* variables) instead")
		}
		a.https[addr] = true
	}
	for _, key := range slices.Sorted(maps.Keys(cfg.Bases)) {
		raw := cfg.Bases[key]
		u, err := parseBase(key, raw)
		if err != nil {
			return nil, err
		}
		addr := canonical(u)
		if loopbackHost(u.Hostname()) {
			a.loop[addr] = true
			if u.Scheme == "http" {
				a.http[addr] = true
				continue
			}
		}
		a.https[addr] = true
	}
	return a, nil
}

// isLoopbackAddr reports whether host:port has a loopback IP literal.
func isLoopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback()
}

// parseBase checks one configured base URL.
func parseBase(key, raw string) (*url.URL, error) {
	where := baseName(key)
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, configError(fmt.Sprintf("%s %q is not a base URL", where, raw), "give one like https://mirror.example.com/npm")
	}
	switch {
	case u.Scheme == "https":
	case u.Scheme == "http" && loopbackHost(u.Hostname()):
	default:
		return nil, configError(fmt.Sprintf("%s %q must use https", where, raw), "plain http is allowed only for a mirror on 127.0.0.1, ::1 or localhost")
	}
	return u, nil
}

// baseName says where a base came from, for messages.
func baseName(key string) string {
	switch {
	case baseEnv[key] != "":
		return baseEnv[key]
	case strings.HasPrefix(key, core.BaseNPMScope):
		return "the registry of " + strings.TrimPrefix(key, core.BaseNPMScope)
	case strings.HasPrefix(key, core.BaseComposerRepo):
		return "Composer repository " + strings.TrimPrefix(key, core.BaseComposerRepo)
	}
	return "base " + key
}

// configError is E12.
func configError(what, hint string) *core.Error {
	return &core.Error{Code: core.EBadConfig, Exit: cli.ExitUsage, What: what, Hint: []string{hint}}
}

// check refuses a hop that is off the allowlist or not https.
func (a *allowlist) check(u *url.URL) error {
	addr := canonical(u)
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "https":
		if a.https[addr] {
			return nil
		}
	case "http":
		if a.http[addr] {
			return nil
		}
	}
	switch {
	case (scheme == "http" || scheme == "https") && loopbackHost(u.Hostname()):
		// A loopback port that isn't one of the mirrors: the scheme is
		// not why it was refused, so the message must not say so.
		return &refusal{host: addr, err: ErrUnconfiguredMirror}
	case scheme == "http":
		return &refusal{host: u.Hostname(), err: ErrInsecureScheme}
	case scheme == "https":
		return &refusal{host: u.Hostname(), err: ErrOffAllowlist}
	}
	return &refusal{host: u.Hostname(), err: ErrInsecureScheme}
}

// tlsConfig is TLS 1.2 or newer with Go's verification. roots nil means
// the system pool, which reads SSL_CERT_FILE and SSL_CERT_DIR.
func tlsConfig(roots *x509.CertPool) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots}
}

// publicDialer connects to public addresses only, except the proxy the
// user configured, which it dials as is.
type publicDialer struct {
	proxies sync.Map // host:port of a proxy in use
}

func (d *publicDialer) proxy(fixed *url.URL) func(*http.Request) (*url.URL, error) {
	return func(req *http.Request) (*url.URL, error) {
		p := fixed
		if p == nil {
			var err error
			if p, err = http.ProxyFromEnvironment(req); err != nil || p == nil {
				return p, err
			}
		}
		d.proxies.Store(canonicalProxy(p), true)
		return p, nil
	}
}

// canonicalProxy is the host:port the transport dials for proxy p.
func canonicalProxy(p *url.URL) string {
	port := p.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443", "socks5": "1080", "socks5h": "1080"}[p.Scheme]
	}
	return net.JoinHostPort(p.Hostname(), port)
}

func (d *publicDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	nd := net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	if _, ok := d.proxies.Load(addr); !ok {
		// Control runs on every resolved address just before connect, so
		// an allowlisted name that resolves to the metadata service or
		// the LAN is refused too.
		nd.ControlContext = func(_ context.Context, _, address string, _ syscall.RawConn) error {
			ip, err := addrIP(address)
			if err != nil {
				return err
			}
			if class := httpx.AddrClass(ip); class != "" {
				return fmt.Errorf("refusing to connect to %s (%s): %w", ip, class, httpx.ErrPrivate)
			}
			return nil
		}
	}
	return nd.DialContext(ctx, network, addr)
}

// loopDialer connects only to the loopback mirrors and only on a
// loopback address.
type loopDialer struct{ allowed map[string]bool }

func (d loopDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if !d.allowed[net.JoinHostPort(strings.ToLower(host), port)] {
		return nil, fmt.Errorf("refusing to connect to %s: not a configured mirror: %w", addr, httpx.ErrPrivate)
	}
	nd := net.Dialer{Timeout: 10 * time.Second}
	nd.ControlContext = func(_ context.Context, _, address string, _ syscall.RawConn) error {
		ip, err := addrIP(address)
		if err != nil {
			return err
		}
		_, p, _ := net.SplitHostPort(address)
		if !ip.IsLoopback() || p != port {
			return fmt.Errorf("refusing to connect to %s: %w", address, httpx.ErrPrivate)
		}
		return nil
	}
	return nd.DialContext(ctx, network, addr)
}

func addrIP(address string) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return netip.Addr{}, err
	}
	return netip.ParseAddr(host)
}

// newTransports builds the transport for public hosts and the one for
// loopback mirrors. The loopback one never uses a proxy.
func newTransports(a *allowlist, proxy string, roots *x509.CertPool) (public, loop *http.Transport, err error) {
	var fixed *url.URL
	if proxy != "" {
		if fixed, err = url.Parse(proxy); err != nil || fixed.Host == "" {
			return nil, nil, configError(fmt.Sprintf("proxy %q is not a URL", proxy), "give one like http://proxy.example:3128")
		}
	}
	base := func() *http.Transport {
		t := &http.Transport{}
		if dt, ok := http.DefaultTransport.(*http.Transport); ok {
			t = dt.Clone()
		}
		t.TLSClientConfig = tlsConfig(roots)
		return t
	}
	pd := &publicDialer{}
	public = base()
	public.Proxy = pd.proxy(fixed)
	public.DialContext = pd.DialContext
	loop = base()
	loop.Proxy = nil
	loop.DialContext = loopDialer{allowed: a.loop}.DialContext
	return public, loop, nil
}
