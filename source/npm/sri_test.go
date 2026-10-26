// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package npm

import (
	"crypto/sha1" //nolint:gosec // the old npm shasum is SHA-1
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func sha1Hex(b []byte) string {
	sum := sha1.Sum(b) //nolint:gosec // the old npm shasum is SHA-1
	return hex.EncodeToString(sum[:])
}

func TestParseSRI(t *testing.T) {
	s512 := sri([]byte("x"))
	tests := []struct {
		in   string
		want []string
	}{
		{s512, []string{"sha512"}},
		{"sha1-" + strings.Repeat("A", 27) + "= " + s512 + "?foo", []string{"sha1", "sha512"}},
		{"sha512-notbase64!!", nil},
		{"md5-AAAA", nil},
		{"sha512-AAAA", nil}, // wrong length
		{"", nil},
		{"SHA512-" + strings.TrimPrefix(s512, "sha512-"), []string{"sha512"}},
	}
	for _, tt := range tests {
		got := ParseSRI(tt.in)
		var algos []string
		for _, h := range got {
			algos = append(algos, h.Algo)
		}
		if strings.Join(algos, ",") != strings.Join(tt.want, ",") {
			t.Errorf("ParseSRI(%q) = %v, want %v", tt.in, algos, tt.want)
		}
	}
	if a, d := strongest(ParseSRI("sha1-" + strings.Repeat("A", 27) + "= " + s512)); a != "sha512" || len(d) != 1 {
		t.Errorf("strongest = %s", a)
	}
}

func FuzzSRI(f *testing.F) {
	f.Add(sri([]byte("x")))
	f.Add("sha1-AAAAAAAAAAAAAAAAAAAAAAAAAAA= sha512-x?y")
	f.Add("")
	f.Fuzz(func(t *testing.T, s string) {
		for _, h := range ParseSRI(s) {
			if len(h.Digest) != digestSize[h.Algo] {
				t.Fatalf("%s digest of %d bytes", h.Algo, len(h.Digest))
			}
		}
	})
}

func FuzzPackument(f *testing.F) {
	f.Add(`{"name":"a","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{"dist":{"tarball":"x"}},"2.0.0":{}}}`)
	f.Add(`{"versions":{"1.0.0":null,"":{},"x":"y"},"dist-tags":{"latest":1}}`)
	f.Add(`{"versions":` + `{"` + strings.Repeat("9", 300) + `":{}}}`)
	f.Add(`[]`)
	f.Fuzz(func(t *testing.T, data string) {
		p, err := decodePackument([]byte(data))
		if err != nil {
			return
		}
		var raw struct {
			Versions map[string]json.RawMessage `json:"versions"`
		}
		_ = json.Unmarshal([]byte(data), &raw)
		if len(p.Versions) > len(raw.Versions) {
			t.Fatalf("%d versions out of %d", len(p.Versions), len(raw.Versions))
		}
		for _, v := range p.Versions {
			if v == "" || len(v) > maxVersionKey {
				t.Fatalf("version key %q kept", v)
			}
		}
		_, _ = decodeVersion([]byte(data))
		_, _ = decodeTimes([]byte(data))
	})
}
