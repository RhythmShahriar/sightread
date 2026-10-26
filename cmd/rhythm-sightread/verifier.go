// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"os"
	"sync"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/sigverify"

	"github.com/RhythmShahriar/sightread/data"
)

func init() { data.SetVerifier(&packVerifier{options: defaultVerifyOptions}) }

// defaultVerifyOptions trusts Sigstore's public-good root, refreshed
// through TUF unless RHYTHM_OFFLINE is set.
func defaultVerifyOptions() sigverify.Options {
	return sigverify.Options{Offline: os.Getenv(cli.OfflineEnv) != ""}
}

// packVerifier checks the Sigstore bundle over a release's checksums.txt
// before `update` trusts a data pack from it: signed by the shared
// release workflow for Sightread's repository and the release tag
// (kit/sigverify). The trusted root loads on first use, so a run that
// never updates never reads it; with RHYTHM_OFFLINE it is the root
// embedded in the kit instead of a TUF refresh.
type packVerifier struct {
	options func() sigverify.Options // what to trust; tests use their own CA

	once sync.Once
	v    *sigverify.Verifier
	err  error
}

// VerifyChecksums implements update.Verifier.
func (p *packVerifier) VerifyChecksums(ctx context.Context, repo, version string, checksums, bundle []byte) (string, error) {
	p.once.Do(func() {
		p.v, p.err = sigverify.New(p.options())
	})
	if p.err != nil {
		return "", p.err
	}
	return p.v.VerifyChecksums(ctx, repo, version, checksums, bundle)
}
