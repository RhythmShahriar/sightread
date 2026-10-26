// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package stage is the --soundcheck flow of PRD 15: once a review is
// done it installs the reviewed update on a staging copy, where its code
// runs; rhythm-soundcheck then compares the site before and after.
//
// Every step can refuse before anything changes on the copy: an update
// on HOLD (E17), a staging URL that is production or resolves to the
// same address (E14), a missing rhythm-soundcheck or rhythm-roadie, a
// copy that fails rhythm-roadie verify (E15) and a remote wp command
// that can't see a local file (E21). The update is installed from the
// exact archive the review read, re-hashed against the reviewed sha256
// first (SR-71), never downloaded again. Every program runs through
// internal/proc as an argv, never a shell; Ctrl-C stops it with its
// whole process tree.
package stage
