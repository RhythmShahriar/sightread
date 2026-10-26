// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package report writes reports as terminal text, JSON, JSONL, SARIF,
// Markdown and HTML, renders `explain`, signs and verifies report JSON
// and reads saved reports back. It registers with core.RegisterWriter
// and the other report setters.
//
// The skeleton created this package empty; the output lane builds it.
package report
