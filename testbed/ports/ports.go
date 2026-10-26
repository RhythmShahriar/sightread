// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package ports is the single source of truth for every TCP port the
// testbed uses. The fixture registry, the canary, the webhook receiver,
// the probes, the benchmark and the README ports table all read these
// constants; a test greps this file so the table can never drift
// from the code.
package ports

// The fixture registry listeners (127.0.0.1). Each plays one real
// service so Sightread can be pointed at it with the matching
// SIGHTREAD_* base URL and never reaches a real host.
const (
	// WPOrg serves the WordPress.org info API, the downloads host, the
	// per-file checksums and the SVN PROPFIND and GET routes, all under
	// path prefixes (SIGHTREAD_WPORG_API, SIGHTREAD_WPDL_API,
	// SIGHTREAD_WPSVN, SIGHTREAD_WPTHEMESVN).
	WPOrg = 18900
	// Packagist serves the p2 metadata and the maintainers endpoint
	// (SIGHTREAD_PACKAGIST, SIGHTREAD_PACKAGIST_META).
	Packagist = 18901
	// GitHub serves the zipball redirect, the git ref lookup and the
	// rate limit endpoint (SIGHTREAD_GITHUB_API).
	GitHub = 18902
	// NPM serves abbreviated and full packuments, per-version documents,
	// tarballs and the signing keys (SIGHTREAD_NPM_REGISTRY).
	NPM = 18903
	// OSV serves the querybatch and vulns endpoints (SIGHTREAD_OSV_API).
	OSV = 18904
	// Canary is the TCP sink every bad payload would connect to if its
	// code ever ran. It must stay silent for the whole benchmark.
	Canary = 18905
	// Webhook receives watch notifications for the notification tests.
	Webhook = 18906
	// WPDocker publishes the Docker WordPress for the --soundcheck end to
	// end scenario (e15).
	WPDocker = 18907
	// Codeload is the second GitHub host name, the target of the zipball
	// redirect, served by its own listener (SIGHTREAD_GITHUB_CODELOAD).
	Codeload = 18908
)

// The probe ports for the environment scenarios (127.0.0.1). They stand
// in for a hostile or broken server without any Docker.
const (
	// ProbeBase and ProbeTop bound the range reserved for probes.
	ProbeBase = 23300
	ProbeTop  = 23339

	// ProbeStall never finishes sending a response body (e03 timeout).
	ProbeStall = 23301
	// ProbeEndless streams an endless body (the uncompressed cap).
	ProbeEndless = 23302
	// ProbeRetry answers 429 with Retry-After, then 200 (e02).
	ProbeRetry = 23303
	// ProbeSSRF redirects to the cloud metadata address, which must be
	// refused (e11 egress guard).
	ProbeSSRF = 23304
	// ProbeSelfTLS serves a self-signed certificate (TLS is verified).
	ProbeSelfTLS = 23305
	// ProbeRedirectLoopback redirects to an unconfigured loopback port
	// and counts hits, to prove an off-allowlist loopback hop is refused.
	ProbeRedirectLoopback = 23310
	// ProbeUnconfigured is the loopback port ProbeRedirectLoopback points
	// at; nothing listens there, so a reached redirect fails loudly.
	ProbeUnconfigured = 23311
	// FrontRetry stands in front of the npm fixture registry and answers
	// 429 with Retry-After to the first request for each path (e02).
	FrontRetry = 23320
	// FrontStall stands in front of the npm fixture registry and stalls
	// every tarball body (e03 timeout, e08 Ctrl-C during a fetch).
	FrontStall = 23321
)

// ClosedProxy is the port the benchmark sets HTTPS_PROXY and HTTP_PROXY
// to. The benchmark's proxy guard listens there and closes every
// connection at once, so a request that forgets a configured loopback
// base fails instead of reaching the internet; the guard counts it
// as an egress attempt.
const ClosedProxy = 23399
