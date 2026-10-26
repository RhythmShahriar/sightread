// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package npm

import (
	"encoding/base64"
	"strings"
)

// Hash is one entry of a Subresource Integrity string.
type Hash struct {
	Algo   string // sha1, sha256, sha384 or sha512
	Digest []byte
}

// digestSize is the digest length of each algorithm SRI may name.
var digestSize = map[string]int{"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}

// maxSRI caps the integrity text read; real ones are under 200 bytes.
const maxSRI = 4096

// ParseSRI reads an SRI string ("sha512-<base64> sha1-<base64>"):
// whitespace separated entries, each "<algo>-<base64>" with optional
// "?options" after it. Entries with an unknown algorithm, bad base64 or
// a digest of the wrong length are skipped, as browsers and npm's ssri
// do, so a string with no usable entry gives none.
func ParseSRI(s string) []Hash {
	if len(s) > maxSRI {
		return nil
	}
	var out []Hash
	for _, tok := range strings.Fields(s) {
		tok, _, _ = strings.Cut(tok, "?")
		algo, b64, ok := strings.Cut(tok, "-")
		if !ok {
			continue
		}
		algo = strings.ToLower(algo)
		size, known := digestSize[algo]
		if !known {
			continue
		}
		d, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			if d, err = base64.RawStdEncoding.DecodeString(b64); err != nil {
				continue
			}
		}
		if len(d) != size {
			continue
		}
		out = append(out, Hash{Algo: algo, Digest: d})
	}
	return out
}

// strongest returns the entries of the strongest algorithm in hs that
// a download is hashed with (sha512, sha256, then sha1), as ssri picks one.
func strongest(hs []Hash) (algo string, digests [][]byte) {
	for _, a := range []string{"sha512", "sha256", "sha1"} {
		for _, h := range hs {
			if h.Algo == a {
				digests = append(digests, h.Digest)
			}
		}
		if len(digests) > 0 {
			return a, digests
		}
	}
	return "", nil
}
