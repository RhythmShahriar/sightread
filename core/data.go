// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import (
	"context"
	"io"

	"github.com/RhythmShahriar/rhythm/kit/cli"
)

// NameIndex answers typosquat questions from the names pack.
type NameIndex interface {
	Popular(eco Ecosystem, name string) bool
	// Near returns popular names close to name.
	Near(eco Ecosystem, name string) []string
}

// DataPacks are the signal and name data Sightread ships embedded and
// refreshes with `update` (package data).
type DataPacks interface {
	Names() NameIndex
	DomainsOK() []string
	Packs() []cli.DataPack
	Update(ctx context.Context, w io.Writer) ([]cli.DataPack, error)
	UpdatePinned(ctx context.Context, w io.Writer, pins map[string]string) ([]cli.DataPack, error)
	// UseEmbedded makes the packs ignore newer ones in the cache
	// (--no-signal-updates).
	UseEmbedded(on bool)
}
