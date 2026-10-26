// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package report

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/config"
	"github.com/RhythmShahriar/sightread/core"
)

func init() { core.SetSigner(Signer{}) }

// Signer signs report JSON with Ed25519 and verifies it (SR-62). The
// signature covers the exact bytes of the JSON file, so any change to
// the file, a space included, fails verification. A local key proves
// only "this machine": trust comes from listing its public key.
type Signer struct{}

var _ core.Signer = Signer{}

// SigSuffix is added to a report's path to name its signature file.
const SigSuffix = ".sig"

// KeyPrefix starts a key ID: "ed25519:" and the base64 public key. The
// .sig file, verify-report and trusted_keys all write keys this way.
const KeyPrefix = "ed25519:"

// The ways verification fails. Verify wraps one of them with the
// details, so cmd can tell them apart with errors.Is.
var (
	ErrChanged      = errors.New("the report changed after it was signed")
	ErrBadSignature = errors.New("the signature does not match the report")
	ErrUntrusted    = errors.New("the report was signed by a key that is not trusted")
	ErrMalformed    = errors.New("not a rhythm-sightread signature")
)

// Signature is the content of a .sig file.
type Signature struct {
	Key    string `json:"key"`    // KeyPrefix + base64 public key
	Sig    string `json:"sig"`    // base64 Ed25519 signature over the JSON bytes
	SHA256 string `json:"sha256"` // hex SHA-256 of the JSON bytes, for footers and a quick check
}

// DefaultKeyPath is where the local signing key lives:
// <config dir>/sightread/report-key, its public key beside it with .pub.
func DefaultKeyPath() (string, error) {
	dir, err := config.Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "sightread", "report-key"), nil
}

// Sign signs the JSON file at jsonPath with the key at keyPath (the
// default key when empty, created on first use) and writes
// <jsonPath>.sig. It returns the signature's path.
func (Signer) Sign(jsonPath, keyPath string) (string, error) {
	data, err := os.ReadFile(jsonPath) //nolint:gosec // the report this run just wrote
	if err != nil {
		return "", fmt.Errorf("can't read %s to sign it: %w", filepath.Base(jsonPath), cause(err))
	}
	if keyPath == "" {
		if keyPath, err = DefaultKeyPath(); err != nil {
			return "", err
		}
	}
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return "", err
	}
	sig := SignBytes(data, key)
	out, err := json.MarshalIndent(sig, "", "  ")
	if err != nil {
		return "", err
	}
	sigPath := jsonPath + SigSuffix
	if err := writeFileAtomic(sigPath, append(out, '\n'), 0o600); err != nil {
		return "", err
	}
	return sigPath, nil
}

// SignBytes signs data with key.
func SignBytes(data []byte, key ed25519.PrivateKey) Signature {
	sum := sha256.Sum256(data)
	pub, _ := key.Public().(ed25519.PublicKey)
	return Signature{Key: KeyID(pub), Sig: base64.StdEncoding.EncodeToString(ed25519.Sign(key, data)), SHA256: hex.EncodeToString(sum[:])}
}

// DigestHex is the hex SHA-256 of a report's bytes, as the .sig file and
// the Markdown and HTML footers (WriteOptions.Signed) carry it.
func DigestHex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// KeyID writes a public key the way the .sig file and trusted_keys do.
func KeyID(pub ed25519.PublicKey) string {
	return KeyPrefix + base64.StdEncoding.EncodeToString(pub)
}

// Verify checks sig against the JSON bytes and returns the signing key's
// ID. The content must hash to the signed sha256 (else ErrChanged), the
// signature must verify with the key it names (else ErrBadSignature)
// and that key must be one of trusted (else ErrUntrusted, with the key
// ID still returned so a caller can show it). Each trusted entry is a
// key ID, a bare base64 key or a PEM public key file's content.
func (Signer) Verify(jsonBytes, sigBytes []byte, trusted [][]byte) (string, error) {
	var sig Signature
	dec := json.NewDecoder(bytes.NewReader(sigBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&sig); err != nil {
		return "", fmt.Errorf("%w (%s)", ErrMalformed, jsonProblem(err))
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("%w (more than one JSON value)", ErrMalformed)
	}
	pub, err := ParsePublicKey([]byte(sig.Key))
	if err != nil {
		return "", fmt.Errorf("%w (key: %s)", ErrMalformed, err.Error())
	}
	raw, err := base64.StdEncoding.DecodeString(sig.Sig)
	if err != nil || len(raw) != ed25519.SignatureSize {
		return "", fmt.Errorf("%w (sig is not a base64 Ed25519 signature)", ErrMalformed)
	}
	id := KeyID(pub)
	if got := DigestHex(jsonBytes); !strings.EqualFold(got, sig.SHA256) {
		return id, fmt.Errorf("%w (sha256 %s now, %s when signed)", ErrChanged, short(got), short(text(sig.SHA256)))
	}
	if !ed25519.Verify(pub, jsonBytes, raw) {
		return id, fmt.Errorf("%w and key %s", ErrBadSignature, id)
	}
	for _, t := range trusted {
		k, err := ParsePublicKey(t)
		if err == nil && subtle.ConstantTimeCompare(k, pub) == 1 {
			return id, nil
		}
	}
	return id, fmt.Errorf("%w (%s); add it to trusted_keys if you trust it", ErrUntrusted, id)
}

// cause is the reason inside a path error, so a message names the file
// once: "permission denied", not "open /x/y: permission denied".
func cause(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}

// short is the first 12 characters of a hash, as messages show it.
func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// ParsePublicKey reads an Ed25519 public key written as a key ID
// ("ed25519:<base64>"), as bare base64 or as a PEM "PUBLIC KEY" block.
func ParsePublicKey(b []byte) (ed25519.PublicKey, error) {
	s := strings.TrimSpace(string(b))
	if strings.HasPrefix(s, "-----BEGIN") {
		block, _ := pem.Decode([]byte(s))
		if block == nil || block.Type != "PUBLIC KEY" {
			return nil, errors.New("not a PEM public key")
		}
		k, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, errors.New("not a PEM public key")
		}
		pub, ok := k.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("not an Ed25519 key")
		}
		return pub, nil
	}
	s = strings.TrimPrefix(s, KeyPrefix)
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("want %s and the base64 of a 32-byte key", KeyPrefix)
	}
	return ed25519.PublicKey(raw), nil
}

// loadOrCreateKey reads the PEM PKCS #8 key at path, creating it (0600)
// and its public key (path + ".pub", 0644) when it doesn't exist.
func loadOrCreateKey(path string) (ed25519.PrivateKey, error) {
	b, err := os.ReadFile(path) //nolint:gosec // the user's own key file
	switch {
	case err == nil:
		return parsePrivateKey(path, b)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("can't read the signing key %s: %w", path, cause(err))
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("can't create the folder for the signing key: %w", cause(err))
	}
	// The key is written in full to a temp file, then hard linked into
	// place. A link never replaces a file, so when two runs sign at once
	// one wins and the other reads the winner's key, which is already
	// complete. A plain O_EXCL create would let the loser read it while
	// it is still empty and call a good key broken.
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*") // mode 0600
	if err != nil {
		return nil, fmt.Errorf("can't create the signing key %s: %w", path, cause(err))
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // the link keeps the key
	if err := pem.Encode(tmp, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	err = os.Link(tmp.Name(), path)
	if errors.Is(err, fs.ErrExist) {
		return loadOrCreateKey(path)
	}
	if err != nil {
		return nil, fmt.Errorf("can't create the signing key %s: %w", path, cause(err))
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := writeFileAtomic(path+".pub", pubPEM, 0o644); err != nil {
		return nil, err
	}
	return key, nil
}

// parsePrivateKey reads a PEM PKCS #8 Ed25519 key.
func parsePrivateKey(path string, b []byte) (ed25519.PrivateKey, error) {
	bad := fmt.Errorf("%s is not a PEM Ed25519 private key; move it away and a new key is made on the next --sign", path)
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, bad
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, bad
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, bad
	}
	return key, nil
}

// writeFileAtomic writes data to path through a temp file and rename,
// so a reader never sees half a file.
func writeFileAtomic(path string, data []byte, mode fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) //nolint:errcheck // gone after the rename
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
