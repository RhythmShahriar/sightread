// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package watch reviews a fleet of sites on a schedule (PRD 6.7) and
// tells people what is new: a candidate version with findings at or
// above --notify-min, a finding a newer signal data pack raises on a
// version a site already runs, an owner change or a WordPress.org
// closure of an installed package.
//
// Each run executes this binary again as a child process (all --sites
// <file> -o <dir>/<stamp>.json) instead of reviewing in this one. A
// review's memory goes back to the OS when the child exits, so a watch
// that runs for months doesn't grow. state.json in the watch folder
// records what was already counted, so a version is notified once.
package watch
