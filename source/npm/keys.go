// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package npm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	_ "embed" // the pinned keys
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/RhythmShahriar/sightread/fetch"
)

// pinnedJSON is a copy of https://registry.npmjs.org/-/npm/v1/keys,
// committed by hand and checked against real registry signatures. A key
// the registry serves must also be here (SR-17), so a registry or
// mirror that starts serving a key of its own can't sign for npm.
//
//go:embed keys.json
var pinnedJSON []byte

// ExtraKeysEnv names a keys file in the /-/npm/v1/keys shape whose keys
// join the pinned set when the npm base is a loopback mirror (the
// testbed and the demo sign with their own key).
const ExtraKeysEnv = "SIGHTREAD_NPM_EXTRA_KEYS"

// keysDoc is the /-/npm/v1/keys answer.
type keysDoc struct {
	Keys []keyEntry `json:"keys"`
}

// keyEntry is one registry key.
type keyEntry struct {
	Expires *string `json:"expires"`
	KeyID   string  `json:"keyid"`
	KeyType string  `json:"keytype"`
	Scheme  string  `json:"scheme"`
	Key     string  `json:"key"`
}

// key is a usable P-256 key with its expiry (zero: none).
type key struct {
	pub     *ecdsa.PublicKey
	der     string // the SPKI bytes, to compare the two sets
	expires time.Time
}

// parseKeys reads a keys document into usable keys by key id. Keys that
// are not ECDSA P-256 or can't be read are left out.
func parseKeys(data []byte) (map[string]key, error) {
	var doc keysDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	return usable(doc), nil
}

func usable(doc keysDoc) map[string]key {
	out := map[string]key{}
	for _, k := range doc.Keys {
		if k.KeyID == "" || k.KeyType != "ecdsa-sha2-nistp256" {
			continue
		}
		der, err := base64.StdEncoding.DecodeString(k.Key)
		if err != nil {
			continue
		}
		pub, err := x509.ParsePKIXPublicKey(der)
		ec, ok := pub.(*ecdsa.PublicKey)
		if err != nil || !ok || ec.Curve != elliptic.P256() {
			continue
		}
		var exp time.Time
		if k.Expires != nil && *k.Expires != "" {
			if exp, err = time.Parse(time.RFC3339, *k.Expires); err != nil {
				continue // an expiry we can't read must not mean "never"
			}
		}
		out[k.KeyID] = key{pub: ec, der: string(der), expires: exp}
	}
	return out
}

// pinned returns the keys built into Sightread, plus the extra keys
// file when the npm base is a loopback mirror. note gets the -v line
// when the file is set but ignored or unreadable.
func pinned(npmBase string, note func(string, ...any)) map[string]key {
	keys, err := parseKeys(pinnedJSON)
	if err != nil {
		panic("npm: keys.json: " + err.Error())
	}
	path := os.Getenv(ExtraKeysEnv)
	if path == "" {
		return keys
	}
	if !fetch.IsLoopbackBase(npmBase) {
		note("%s ignored: it applies only when the npm registry is a mirror on 127.0.0.1, ::1 or localhost", ExtraKeysEnv)
		return keys
	}
	data, err := os.ReadFile(path) //nolint:gosec // a file the user named for a loopback mirror
	if err == nil {
		var extra map[string]key
		if extra, err = parseKeys(data); err == nil {
			for id, k := range extra {
				keys[id] = k
			}
			return keys
		}
	}
	note("%s ignored: %v", ExtraKeysEnv, err)
	return keys
}

// registryKeys loads the registry's keys (cached 24 hours) and keeps
// those that are also pinned with the same key material.
func (s *Source) registryKeys(ctx context.Context, reg string) (map[string]key, error) {
	var doc keysDoc
	if err := s.env.Get.JSON(ctx, reg+"/-/npm/v1/keys", &doc, fetch.KindKeys); err != nil {
		return nil, err
	}
	served := usable(doc)
	out := map[string]key{}
	for id, k := range served {
		if p, ok := s.pinned[id]; ok && p.der == k.der {
			out[id] = k
		}
	}
	return out, nil
}

// errUndated is a signature by a key that has since expired on a
// version whose publish date is unknown (a time map too large to read):
// it can't be judged either way.
var errUndated = errors.New("signed with a key that has expired and the publish date is unknown")

// verifySig checks one signature over "<name>@<version>:<integrity>"
// with k. A key that expires must have been valid when the version
// was published.
func verifySig(k key, name, version, integrity, sig string, published time.Time) error {
	if !k.expires.IsZero() {
		if published.IsZero() {
			return errUndated
		}
		if !published.Before(k.expires) {
			return fmt.Errorf("the key expired on %s, before this version was published", k.expires.Format("2006-01-02"))
		}
	}
	raw, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		return fmt.Errorf("the signature is not base64")
	}
	h := sha256.Sum256([]byte(name + "@" + version + ":" + integrity))
	if !ecdsa.VerifyASN1(k.pub, h[:], raw) {
		return fmt.Errorf("the signature does not verify")
	}
	return nil
}
