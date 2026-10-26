// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package benchdoc

import "strings"

// The real-release section is written by the owner-run corpus tool
// (testbed/corpus) between these markers. The benchmark regenerates the
// rest of the page and keeps whatever sits between them.
const (
	CorpusStart = "<!-- corpus:start -->"
	CorpusEnd   = "<!-- corpus:end -->"
)

// corpusPlaceholder stands in until the owner first runs make corpus.
const corpusPlaceholder = "## Real releases (owner-run)\n\n" +
	"Not run yet. The owner runs `make -C testbed corpus` with network access: it fetches the " +
	"releases pinned by hash in `testbed/corpus/corpus.lock` and writes this section. It is never " +
	"part of `make bench` or CI.\n"

// CorpusBlock returns the real-release block of an existing page,
// markers included, or the placeholder block when it has none.
func CorpusBlock(page string) string {
	i := strings.Index(page, CorpusStart)
	j := strings.Index(page, CorpusEnd)
	if i < 0 || j < i {
		return CorpusStart + "\n" + corpusPlaceholder + CorpusEnd + "\n"
	}
	return page[i:j+len(CorpusEnd)] + "\n"
}

// SpliceCorpus puts section (without markers) between the markers of
// page, appending the block when the page has none.
func SpliceCorpus(page, section string) string {
	block := CorpusStart + "\n" + strings.TrimRight(section, "\n") + "\n" + CorpusEnd
	i := strings.Index(page, CorpusStart)
	j := strings.Index(page, CorpusEnd)
	if i < 0 || j < i {
		return strings.TrimRight(page, "\n") + "\n\n" + block + "\n"
	}
	return page[:i] + block + page[j+len(CorpusEnd):]
}
