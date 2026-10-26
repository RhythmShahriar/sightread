// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package blob is the content-addressed store under the cache folder:
// every file of every archive is kept by its sha256 and re-hashed on
// read. It registers itself with core.SetBlobStore: core.OpenBlobs(root)
// opens the Disk store under root/blobs. Memory is the same contract in
// memory, for tests and the demo.
package blob
