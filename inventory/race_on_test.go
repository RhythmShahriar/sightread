// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build race

package inventory

// raceSlowdown scales wall-clock bounds in tests: the race detector
// makes the byte scanners several times slower.
const raceSlowdown = 8
