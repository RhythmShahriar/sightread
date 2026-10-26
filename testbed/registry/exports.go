// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

import (
	"crypto/tls"
	"sort"
)

// TLSConfig returns the server TLS configuration of the per-run CA, for
// the benchmark's misbehaving fronts that stand in front of the registry
// on other loopback ports. It is nil in plain HTTP mode.
func (r *Registry) TLSConfig() *tls.Config {
	if r.ca == nil {
		return nil
	}
	return r.ca.tlsConfig()
}

// IDs returns every scenario folder the registry built, sorted.
func (r *Registry) IDs() []string {
	out := make([]string, 0, len(r.pkgs))
	for _, p := range r.pkgs {
		out = append(out, p.id)
	}
	sort.Strings(out)
	return out
}

// Meta returns the meta.yaml of a scenario folder.
func (r *Registry) Meta(id string) (*PackageMeta, bool) {
	for _, p := range r.pkgs {
		if p.id == id {
			return p.meta, true
		}
	}
	return nil, false
}

// Archive returns the archive the registry built for a version of a
// scenario folder (a zip for WordPress and GitHub, a tgz for npm), with
// fake keys expanded. It is the honest build, never the tampered or
// republished bytes, so the compared tools and the --from-file scenario
// see what the author released.
func (r *Registry) Archive(id, version string) ([]byte, bool) {
	for _, p := range r.pkgs {
		if p.id != id {
			continue
		}
		if bv, ok := p.versions[version]; ok {
			return bv.archive, true
		}
	}
	return nil, false
}
