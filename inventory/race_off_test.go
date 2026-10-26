// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build !race

package inventory

// raceSlowdown scales wall-clock bounds in tests; 1 without the race
// detector.
const raceSlowdown = 1
