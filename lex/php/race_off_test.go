// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build !race

package php

// raceSlowdown widens time budgets under the race detector; 1 without it.
const raceSlowdown = 1
