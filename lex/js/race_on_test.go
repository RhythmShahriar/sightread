// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build race

package js

// raceSlowdown widens time budgets: the race detector makes code run
// several times slower.
const raceSlowdown = 8
