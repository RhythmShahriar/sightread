// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package fetch is Sightread's only way onto the network. Its Getter
// enforces HTTPS on every hop, a fixed host allowlist per source, per-
// host credentials, size caps counted on bytes read and the kit cache,
// and it registers itself with core.SetGetter.
//
// The skeleton created this package empty; the fetch lane builds it.
package fetch
