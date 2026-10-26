// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package blob is the content-addressed store under the cache folder:
// every file of every archive is kept by its sha256 and re-hashed on
// read. It registers itself with core.SetBlobStore.
//
// The skeleton created this package empty; the fetch lane builds it.
package blob
