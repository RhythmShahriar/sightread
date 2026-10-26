// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package report

import (
	"testing"

	"github.com/RhythmShahriar/sightread/internal/schematest"
)

// The validator lives in internal/schematest so cmd can check the
// documents its commands print against the same schema.

func loadSchema(t testing.TB, path string) map[string]any { return schematest.Load(t, path) }

func validate(schema map[string]any, doc []byte) []string { return schematest.Validate(schema, doc) }

func validateStrict(schema map[string]any, doc []byte) []string {
	return schematest.ValidateStrict(schema, doc)
}
