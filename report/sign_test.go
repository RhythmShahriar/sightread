// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package report

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/config"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// signed writes the sample report as JSON into a temp folder, signs it
// with a key in that folder and returns the paths.
func signed(t *testing.T) (jsonPath, sigPath, keyPath string) {
	t.Helper()
	dir := t.TempDir()
	jsonPath = filepath.Join(dir, "sightread.json")
	if err := os.WriteFile(jsonPath, writeWith(t, core.FormatJSON, coretest.SampleReport(), testOpts), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath = filepath.Join(dir, "keys", "report-key")
	signer := core.GetSigner()
	if signer == nil {
		t.Fatal("no signer registered")
	}
	sigPath, err := signer.Sign(jsonPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if sigPath != jsonPath+".sig" {
		t.Errorf("signature at %s, want %s.sig", sigPath, jsonPath)
	}
	return jsonPath, sigPath, keyPath
}

func readAll(t *testing.T, paths ...string) [][]byte {
	t.Helper()
	out := make([][]byte, len(paths))
	for i, p := range paths {
		b, err := os.ReadFile(p) //nolint:gosec // a file of the test's temp folder
		if err != nil {
			t.Fatal(err)
		}
		out[i] = b
	}
	return out
}

func TestSignThenVerify(t *testing.T) {
	jsonPath, sigPath, keyPath := signed(t)
	b := readAll(t, jsonPath, sigPath, keyPath+".pub")
	data, sig, pub := b[0], b[1], b[2]

	var s Signature
	dec := json.NewDecoder(bytes.NewReader(sig))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		t.Fatalf("the .sig file is not {key, sig, sha256}: %v\n%s", err, sig)
	}
	if !strings.HasPrefix(s.Key, KeyPrefix) || s.SHA256 != DigestHex(data) || len(s.SHA256) != 64 {
		t.Errorf("signature fields: %+v", s)
	}

	// The PEM public key beside the key and the key ID both trust it.
	id, err := Signer{}.Verify(data, sig, [][]byte{pub})
	if err != nil || id != s.Key {
		t.Fatalf("Verify with the PEM key = %q, %v", id, err)
	}
	if _, err := (Signer{}).Verify(data, sig, [][]byte{[]byte("  " + s.Key + "\n")}); err != nil {
		t.Errorf("Verify with the key ID: %v", err)
	}

	// Signing again reuses the key.
	if _, err := (Signer{}).Sign(jsonPath, keyPath); err != nil {
		t.Fatal(err)
	}
	again := readAll(t, sigPath)[0]
	var s2 Signature
	_ = json.Unmarshal(again, &s2)
	if s2.Key != s.Key {
		t.Error("a second Sign made a new key")
	}
}

// TestVerifyFlippedByte is T-62: one changed byte fails, whether the
// sha256 in the signature is left alone or forged to match.
func TestVerifyFlippedByte(t *testing.T) {
	jsonPath, sigPath, keyPath := signed(t)
	b := readAll(t, jsonPath, sigPath, keyPath+".pub")
	data, sig, pub := b[0], b[1], b[2]
	for _, i := range []int{0, len(data) / 2, len(data) - 2} {
		changed := bytes.Clone(data)
		changed[i] ^= 0x01
		id, err := Signer{}.Verify(changed, sig, [][]byte{pub})
		if !errors.Is(err, ErrChanged) || id == "" {
			t.Errorf("byte %d flipped: %q, %v; want ErrChanged", i, id, err)
		}
		var s Signature
		_ = json.Unmarshal(sig, &s)
		s.SHA256 = DigestHex(changed)
		forged, _ := json.Marshal(s)
		if _, err := (Signer{}).Verify(changed, forged, [][]byte{pub}); !errors.Is(err, ErrBadSignature) {
			t.Errorf("byte %d flipped with a forged sha256: %v; want ErrBadSignature", i, err)
		}
	}
	if _, err := (Signer{}).Verify(append(bytes.Clone(data), ' '), sig, [][]byte{pub}); !errors.Is(err, ErrChanged) {
		t.Errorf("a trailing space: %v", err)
	}
}

// TestVerifyUntrusted: a valid signature by another key fails until that
// key is trusted.
func TestVerifyUntrusted(t *testing.T) {
	jsonPath, sigPath, _ := signed(t)
	b := readAll(t, jsonPath, sigPath)
	data, sig := b[0], b[1]
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := Signer{}.Verify(data, sig, [][]byte{[]byte(KeyID(other))})
	if !errors.Is(err, ErrUntrusted) || !strings.HasPrefix(id, KeyPrefix) {
		t.Fatalf("an untrusted key: %q, %v", id, err)
	}
	if !strings.Contains(err.Error(), id) || !strings.Contains(err.Error(), "trusted_keys") {
		t.Errorf("the message does not name the key and trusted_keys: %v", err)
	}
	if _, err := (Signer{}).Verify(data, sig, nil); !errors.Is(err, ErrUntrusted) {
		t.Errorf("no trusted keys: %v", err)
	}
	if got, err := (Signer{}).Verify(data, sig, [][]byte{[]byte(KeyID(other)), []byte(id)}); err != nil || got != id {
		t.Errorf("trusted among others: %q, %v", got, err)
	}
	// A signature by another key over the same bytes, presented with the
	// first key's ID, does not verify.
	_, key2, _ := ed25519.GenerateKey(rand.Reader)
	s2 := SignBytes(data, key2)
	var s Signature
	_ = json.Unmarshal(sig, &s)
	s2.Key = s.Key
	swapped, _ := json.Marshal(s2)
	if _, err := (Signer{}).Verify(data, swapped, [][]byte{[]byte(id)}); !errors.Is(err, ErrBadSignature) {
		t.Errorf("a signature by another key under this key's ID: %v", err)
	}
}

func TestVerifyMalformed(t *testing.T) {
	data := []byte("{}\n")
	_, key, _ := ed25519.GenerateKey(rand.Reader)
	good, _ := json.Marshal(SignBytes(data, key))
	for name, sig := range map[string]string{
		"not JSON":      "nope",
		"extra field":   strings.Replace(string(good), "{", `{"x":1,`, 1),
		"bad key":       strings.Replace(string(good), KeyPrefix, "rsa:", 1),
		"short sig":     `{"key":"` + KeyID(key.Public().(ed25519.PublicKey)) + `","sig":"AAAA","sha256":"00"}`,
		"empty":         "",
		"key not b64":   `{"key":"ed25519:!!","sig":"","sha256":""}`,
		"two documents": string(good) + string(good),
	} {
		_, err := Signer{}.Verify(data, []byte(sig), nil)
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: %v, want ErrMalformed", name, err)
		}
	}
}

func TestKeyFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file modes are a Unix check")
	}
	_, _, keyPath := signed(t)
	for path, want := range map[string]os.FileMode{keyPath: 0o600, keyPath + ".pub": 0o644, filepath.Dir(keyPath): 0o700 | os.ModeDir} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode() & (os.ModePerm | os.ModeDir); got != want {
			t.Errorf("%s mode %v, want %v", filepath.Base(path), got, want)
		}
	}
	b := readAll(t, keyPath)[0]
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatal("the key is not a PEM PRIVATE KEY")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		t.Errorf("the key is not PKCS #8: %v", err)
	}
}

// TestSignDefaultKey creates the key under the config folder.
func TestSignDefaultKey(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(config.EnvConfigDir, dir)
	want := filepath.Join(dir, "sightread", "report-key")
	if got, err := DefaultKeyPath(); err != nil || got != want {
		t.Fatalf("DefaultKeyPath = %q, %v; want %q", got, err, want)
	}
	jsonPath := filepath.Join(dir, "r.json")
	if err := os.WriteFile(jsonPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Signer{}).Sign(jsonPath, ""); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{want, want + ".pub"} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("no %s: %v", filepath.Base(p), err)
		}
	}
}

func TestSignErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := (Signer{}).Sign(filepath.Join(dir, "missing.json"), filepath.Join(dir, "k")); err == nil ||
		!strings.Contains(err.Error(), "can't read missing.json to sign it") {
		t.Errorf("missing report: %v", err)
	}
	jsonPath := filepath.Join(dir, "r.json")
	keyPath := filepath.Join(dir, "bad-key")
	if err := os.WriteFile(jsonPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (Signer{}).Sign(jsonPath, keyPath); err == nil || !strings.Contains(err.Error(), "is not a PEM Ed25519 private key") {
		t.Errorf("bad key: %v", err)
	}
	if _, err := os.Stat(jsonPath + SigSuffix); err == nil {
		t.Error("a signature was written with a bad key")
	}
}

func TestParsePublicKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	der, _ := x509.MarshalPKIXPublicKey(pub)
	for name, in := range map[string]string{
		"key ID": KeyID(pub), "bare": strings.TrimPrefix(KeyID(pub), KeyPrefix),
		"PEM": string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
	} {
		if got, err := ParsePublicKey([]byte(in)); err != nil || !got.Equal(pub) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, in := range []string{"", "ed25519:", "ed25519:AAAA", "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n", "rsa:abc"} {
		if _, err := ParsePublicKey([]byte(in)); err == nil {
			t.Errorf("%q parsed", in)
		}
	}
}

// TestSignedFooterHash: the hash the footers carry is the one in the
// .sig file, so an HTML or Markdown report can be matched to the JSON.
func TestSignedFooterHash(t *testing.T) {
	jsonPath, sigPath, _ := signed(t)
	b := readAll(t, jsonPath, sigPath)
	var s Signature
	if err := json.Unmarshal(b[1], &s); err != nil {
		t.Fatal(err)
	}
	o := testOpts
	o.Signed = DigestHex(b[0])
	if o.Signed != s.SHA256 {
		t.Fatalf("DigestHex %s, signature %s", o.Signed, s.SHA256)
	}
	md := string(writeWith(t, core.FormatMarkdown, coretest.SampleReport(), o))
	html := string(writeWith(t, core.FormatHTML, coretest.SampleReport(), o))
	if !strings.Contains(md, "Signed JSON report sha256: `"+s.SHA256+"`") {
		t.Error("the Markdown footer does not carry the signed hash")
	}
	if !strings.Contains(html, "<code>"+s.SHA256+"</code>") {
		t.Error("the HTML footer does not carry the signed hash")
	}
}
