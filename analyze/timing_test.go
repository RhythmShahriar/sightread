// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"runtime"
	"time"
)

// timeLimit scales a wall-clock bound for the machine: by the race
// detector's slowdown, and twice on macOS and Windows, whose CI runners
// are slower. The bounds catch a missing limit or a quadratic scan, not
// speed; make perf holds the speed targets.
func timeLimit(d time.Duration) time.Duration {
	d *= time.Duration(raceSlowdown)
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		d *= 2
	}
	return d
}

// fasterOfTwo runs f, which returns how long its timed part took, and runs it
// once more when that is over limit: a machine busy with other jobs for
// a moment must not fail the bound. It returns the faster time.
func fasterOfTwo(limit time.Duration, f func() time.Duration) time.Duration {
	d := f()
	if d <= limit {
		return d
	}
	return min(d, f())
}
