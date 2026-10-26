// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package fetch is Sightread's only way onto the network. Its Getter
// enforces HTTPS on every hop, a fixed host allowlist per source, per-
// host credentials, size caps counted on bytes read and the kit cache,
// and it registers itself with core.SetGetter.
//
// Errors come back as the *core.Error cases of PRD section 10: E7 for a
// network failure, a refused hop or a cache miss offline, E9 for a host
// that kept answering 429, E10 for a host that wants credentials, E11 for
// a body past its cap and E16 for an anonymous run out of GitHub
// requests. Package.Wrap names the package in them once a source knows
// it. Any other non-2xx answer is a *StatusError for the source to map.
package fetch
