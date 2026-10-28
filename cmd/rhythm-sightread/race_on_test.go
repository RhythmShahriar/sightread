// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build race

package main

// raceEnabled is true under the race detector, which makes code run
// several times slower: wall-clock targets are left to plain runs.
const raceEnabled = true
