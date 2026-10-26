// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package stage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// maxSoundcheckConfig bounds the .soundcheck/config.yaml read: only its
// production list matters here.
const maxSoundcheckConfig = 1 << 20

// production is one production entry and where it came from, for E14.
type production struct {
	entry, from string
}

// hostOf reads a site the way production lists name them: a URL, a bare
// host or *.host. It returns the lower-case host without port, or "".
func hostOf(entry string) string {
	e := strings.TrimSpace(entry)
	if e == "" {
		return ""
	}
	if !strings.Contains(e, "://") {
		e = "https://" + e
	}
	u, err := url.Parse(e)
	if err != nil {
		return ""
	}
	return strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
}

// matches reports whether host is the production entry: the same host,
// or a subdomain of a *.example.com entry.
func (p production) matches(host string) bool {
	h := hostOf(p.entry)
	if strings.HasPrefix(h, "*.") {
		return strings.HasSuffix(host, h[1:])
	}
	return h != "" && h == host
}

// soundcheckProduction reads the production list of the nearest
// .soundcheck/config.yaml at or above dir. Only the production key is
// read; Soundcheck owns the rest of the file.
func soundcheckProduction(dir string) ([]production, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	for d := abs; ; d = filepath.Dir(d) {
		p := filepath.Join(d, ".soundcheck", "config.yaml")
		f, err := os.Open(p) //nolint:gosec // the user's own Soundcheck config, found by name
		if err == nil {
			defer func() { _ = f.Close() }()
			b, err := io.ReadAll(io.LimitReader(f, maxSoundcheckConfig))
			if err != nil {
				return nil, fmt.Errorf("%s: can't be read (%w)", p, err)
			}
			return parseProduction(b, p)
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		if filepath.Dir(d) == d {
			return nil, nil
		}
	}
}

// parseProduction reads the production key of the Soundcheck config at
// path p.
func parseProduction(b []byte, p string) ([]production, error) {
	var cfg struct {
		Production []string `yaml:"production"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("%s: not YAML Sightread can read (%w)", p, err)
	}
	out := make([]production, 0, len(cfg.Production))
	for _, e := range cfg.Production {
		out = append(out, production{entry: e, from: shownPath(p)})
	}
	return out, nil
}

// shownPath is p relative to the working folder when it is inside it.
func shownPath(p string) string {
	wd, err := os.Getwd()
	if err == nil {
		if rel, err := filepath.Rel(wd, p); err == nil && !strings.HasPrefix(rel, "..") {
			return filepath.ToSlash(rel)
		}
	}
	return filepath.ToSlash(p)
}

// Resolver looks up a host's addresses. Stage asks only about the
// staging host and the production hosts the user named, never about a
// domain found in a package (SR-15).
type Resolver func(ctx context.Context, host string) ([]net.IP, error)

// defaultResolver uses the system resolver.
func defaultResolver(ctx context.Context, host string) ([]net.IP, error) {
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		ips = append(ips, a.IP)
	}
	return ips, nil
}

// sameAddress returns the first production entry whose host resolves to
// an address the staging host also has, with that address. Wildcard
// entries and hosts that don't resolve are skipped: a lookup failure is
// no evidence either way and the name checks already ran.
func sameAddress(ctx context.Context, lookup Resolver, staging string, prods []production) (production, net.IP, bool) {
	if staging == "" {
		return production{}, nil, false
	}
	stagingIPs := resolve(ctx, lookup, staging)
	if len(stagingIPs) == 0 {
		return production{}, nil, false
	}
	for _, p := range prods {
		h := hostOf(p.entry)
		if h == "" || strings.HasPrefix(h, "*.") {
			continue
		}
		for _, ip := range resolve(ctx, lookup, h) {
			if slices.ContainsFunc(stagingIPs, ip.Equal) {
				return p, ip, true
			}
		}
	}
	return production{}, nil, false
}

// resolve returns host's addresses: the host itself when it is an IP.
func resolve(ctx context.Context, lookup Resolver, host string) []net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}
	}
	ips, err := lookup(ctx, host)
	if err != nil {
		return nil
	}
	return ips
}
