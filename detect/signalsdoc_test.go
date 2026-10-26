// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package detect

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
)

// TestSignalsDocCurrent fails when docs/signals.md differs from what
// go run ./detect/cmd/signalsdoc writes now.
func TestSignalsDocCurrent(t *testing.T) {
	got, err := os.ReadFile(filepath.Join("..", filepath.FromSlash(SignalsDocPath)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, SignalsDoc()) {
		t.Errorf("%s is stale; run go run ./detect/cmd/signalsdoc and commit it", SignalsDocPath)
	}
}

func TestSignalsDocHasEverySignal(t *testing.T) {
	doc := string(SignalsDoc())
	for _, s := range core.Catalog {
		if !strings.Contains(doc, "\n## "+s.ID+"\n") || !strings.Contains(doc, "[`"+s.ID+"`](#"+s.ID+")") {
			t.Errorf("%s has no section or table row", s.ID)
		}
	}
	if !strings.Contains(doc, "- Severity: critical (never ignored, allowed or lowered)") {
		t.Error("unignorable signals are not marked")
	}
	if !strings.Contains(doc, "| [`local-drift`](#local-drift) | info | confirmed | wp-plugin, wp-theme, composer |") {
		t.Error("the ecosystems column is wrong")
	}
}
