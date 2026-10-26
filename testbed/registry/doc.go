// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package registry is the testbed's fixture registry: one process that
// plays WordPress.org, Packagist, GitHub, npm and OSV on loopback so
// Sightread can be reviewed against known updates without ever reaching
// a real service.
//
// It is both a library the benchmark imports (New then Start) and the
// core of the standalone command in cmd/registry. At start it reads
// every scenario under testbed/packages, builds a deterministic archive
// for each version (a zip for WordPress and GitHub, a tgz for npm),
// computes the checksums each ecosystem publishes and signs every npm
// version with an ECDSA P-256 key generated for this run. The archives
// are built in memory and never written to the repository.
//
// Every request is logged as one JSON line to testbed/state/requests.log
// so the privacy and egress tests can prove Sightread sends only package
// names and versions and reaches nothing outside the fixture set.
package registry
