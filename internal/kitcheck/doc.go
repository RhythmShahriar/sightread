// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package kitcheck holds contract tests for what Sightread relies on in
// the rhythm kit: cli.Main's exit codes and help, the --fail-on error
// text, httpx refusing loopback and stripping credentials off another
// host, the cache's offline fallback, secrets masking the credentials a
// package or a config may hold, term escaping control and bidi
// characters and config.FirstRun. It also checks the license of every
// module the build links. It has no code of its own. A kit upgrade that
// breaks one of these promises fails here, before it reaches a review.
package kitcheck
