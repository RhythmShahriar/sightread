// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/sigverify/sigverifytest"
)

// Positive: a checksums.txt the shared release workflow signed for
// Sightread's tag verifies. Negative: one signed for another repository,
// or for another tag, does not; nor does a bundle that isn't one.
func TestPackVerifier(t *testing.T) {
	ca, err := sigverifytest.New()
	if err != nil {
		t.Fatal(err)
	}
	p := &packVerifier{options: ca.Options}
	const repo = "RhythmShahriar/sightread"
	sums := []byte("0123  sightread-names.json\n")
	good, err := ca.Sign(sigverifytest.Shared(repo, "1.0.1"), sums)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.VerifyChecksums(context.Background(), repo, "1.0.1", sums, good); err != nil {
		t.Errorf("a good bundle: %v", err)
	}
	other, err := ca.Sign(sigverifytest.Shared("RhythmShahriar/tuner", "1.0.1"), sums)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		version string
		bundle  []byte
	}{"other repository": {"1.0.1", other}, "other tag": {"1.0.2", good}, "not a bundle": {"1.0.1", []byte("{}")}} {
		if _, err := p.VerifyChecksums(context.Background(), repo, c.version, sums, c.bundle); err == nil {
			t.Errorf("%s verified", name)
		}
	}
}

// The binary's verifier trusts the public-good root: with RHYTHM_OFFLINE
// it loads the root embedded in the kit and refuses a test CA's bundle.
func TestPackVerifierPublicRoot(t *testing.T) {
	t.Setenv("RHYTHM_OFFLINE", "1")
	ca, err := sigverifytest.New()
	if err != nil {
		t.Fatal(err)
	}
	sums := []byte("0123  sightread-names.json\n")
	b, err := ca.Sign(sigverifytest.Shared("RhythmShahriar/sightread", "1.0.1"), sums)
	if err != nil {
		t.Fatal(err)
	}
	p := &packVerifier{options: defaultVerifyOptions}
	if _, err := p.VerifyChecksums(context.Background(), "RhythmShahriar/sightread", "1.0.1", sums, b); err == nil {
		t.Error("the public root accepted a test CA's signature")
	}
	if !defaultVerifyOptions().Offline {
		t.Error("RHYTHM_OFFLINE did not make the root the embedded one")
	}
}
