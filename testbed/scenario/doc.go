// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package scenario reads testbed/scenarios.yaml, evaluates a recorded
// Sightread review against a scenario's expectation and renders the
// scoreboard. It holds no Docker and starts no process, so the
// evaluation and the scoreboard can be tested on recorded JSON alone;
// the benchmark (testbed/bench) drives the real binary and feeds the
// results through here.
package scenario
