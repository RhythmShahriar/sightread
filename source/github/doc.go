// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package github checks whether a GitHub repository has a tag for a
// version (v1.2.3, 1.2.3 or name@1.2.3), within the same api.github.com
// budget as Composer zipballs. It registers with core.SetTagChecker.
package github
