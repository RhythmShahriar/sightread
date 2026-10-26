// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
)

// npmSigner holds the ECDSA P-256 key the registry signs npm versions
// with. The key is generated for one run, so the public key must be
// handed to Sightread through SIGHTREAD_NPM_EXTRA_KEYS (which the fetch
// lane applies only for a loopback mirror); it is never one of the keys
// pinned in the binary.
type npmSigner struct {
	key   *ecdsa.PrivateKey
	keyID string
}

// npmKey is one entry of the /-/npm/v1/keys response and of
// testbed/state/npm-keys.json, in npm's own shape.
type npmKey struct {
	Expires *string `json:"expires"`
	KeyID   string  `json:"keyid"`
	KeyType string  `json:"keytype"`
	Scheme  string  `json:"scheme"`
	Key     string  `json:"key"`
}

// npmKeysDoc is the /-/npm/v1/keys body.
type npmKeysDoc struct {
	Keys []npmKey `json:"keys"`
}

// newNPMSigner generates the signing key and derives its npm key id.
func newNPMSigner() (*npmSigner, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(spki)
	return &npmSigner{key: key, keyID: "SHA256:" + base64.StdEncoding.EncodeToString(sum[:])}, nil
}

// sign signs the npm registry message "<name>@<version>:<integrity>" and
// returns the base64 DER ECDSA signature.
func (s *npmSigner) sign(name, version, integrity string) (string, error) {
	msg := fmt.Sprintf("%s@%s:%s", name, version, integrity)
	digest := sha256.Sum256([]byte(msg))
	der, err := ecdsa.SignASN1(rand.Reader, s.key, digest[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// keysDoc returns the public key in npm's /-/npm/v1/keys shape.
func (s *npmSigner) keysDoc() (npmKeysDoc, error) {
	spki, err := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
	if err != nil {
		return npmKeysDoc{}, err
	}
	return npmKeysDoc{Keys: []npmKey{{
		KeyID:   s.keyID,
		KeyType: "ecdsa-sha2-nistp256",
		Scheme:  "ecdsa-sha2-nistp256",
		Key:     base64.StdEncoding.EncodeToString(spki),
	}}}, nil
}

// writeKeys writes the public key to path in the keys shape.
func (s *npmSigner) writeKeys(path string) error {
	doc, err := s.keysDoc()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, b, 0o644); err != nil { //nolint:gosec // a public key, not a secret
		return fmt.Errorf("write npm-keys.json: %w", err)
	}
	return nil
}
