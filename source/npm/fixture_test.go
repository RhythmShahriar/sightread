// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package npm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/RhythmShahriar/sightread/blob"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/fetch"
)

// The ports this package's tests may listen on.
const firstPort, lastPort = 31000, 31019

// registry plays an npm registry on 127.0.0.1. A packument path answers
// the abbreviated form when the request asks for it and the full one
// otherwise, as registry.npmjs.org does.
type registry struct {
	mu     sync.Mutex
	abbr   map[string]string // "/<name>" to the abbreviated packument
	full   map[string]string // "/<name>" to the full packument
	body   map[string][]byte // any other path
	status map[string]int
	log    []string
	auth   map[string]string
	url    string
}

func newRegistry(t *testing.T) *registry {
	t.Helper()
	r := &registry{abbr: map[string]string{}, full: map[string]string{}, body: map[string][]byte{}, status: map[string]int{}, auth: map[string]string{}}
	srv := httptest.NewUnstartedServer(r)
	_ = srv.Listener.Close()
	srv.Listener = listen(t)
	srv.Start()
	t.Cleanup(srv.Close)
	r.url = srv.URL
	return r
}

func (r *registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := req.URL.EscapedPath()
	r.log = append(r.log, req.Method+" "+p)
	r.auth[p] = req.Header.Get("Authorization")
	if st := r.status[p]; st != 0 {
		w.WriteHeader(st)
		return
	}
	if strings.Contains(req.Header.Get("Accept"), "application/vnd.npm.install-v1+json") {
		if b, ok := r.abbr[p]; ok {
			_, _ = w.Write([]byte(b))
			return
		}
	} else if b, ok := r.full[p]; ok {
		_, _ = w.Write([]byte(b))
		return
	}
	if b, ok := r.body[p]; ok {
		_, _ = w.Write(b)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_, _ = w.Write([]byte(`{"error":"Not found"}`))
}

func (r *registry) requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.log...)
}

func listen(t *testing.T) net.Listener {
	t.Helper()
	for p := firstPort; p <= lastPort; p++ {
		l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err == nil {
			return l
		}
	}
	t.Fatalf("no free port in 127.0.0.1:%d-%d", firstPort, lastPort)
	return nil
}

// env builds an Env on pub with private scopes and a real fetch client.
func env(t *testing.T, pub *registry, scopes map[string]*registry, tokens map[string]string) *core.Env {
	t.Helper()
	bases := map[string]string{core.BaseNPM: pub.url}
	for scope, r := range scopes {
		bases[core.BaseNPMScope+scope] = r.url
	}
	get, err := fetch.New(core.GetterConfig{Bases: bases, CacheDir: t.TempDir(), Retries: -1, ScopeTokens: tokens})
	if err != nil {
		t.Fatal(err)
	}
	return &core.Env{Get: get, Blobs: blob.Memory(), Bases: bases}
}

// signer is a P-256 key made for one test, served and pinned.
type signer struct {
	id   string
	priv *ecdsa.PrivateKey
}

func newSigner(t *testing.T, id string) signer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer{id: id, priv: k}
}

func (s signer) entry(t *testing.T, expires string) map[string]any {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&s.priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	var exp any
	if expires != "" {
		exp = expires
	}
	return map[string]any{"expires": exp, "keyid": s.id, "keytype": "ecdsa-sha2-nistp256", "scheme": "ecdsa-sha2-nistp256",
		"key": base64.StdEncoding.EncodeToString(der)}
}

func (s signer) sign(t *testing.T, msg string) string {
	t.Helper()
	h := sha256.Sum256([]byte(msg))
	sig, err := ecdsa.SignASN1(rand.Reader, s.priv, h[:])
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig)
}

// keysJSON is a /-/npm/v1/keys answer.
func keysJSON(t *testing.T, entries ...map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"keys": entries})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// pinExtra writes entries as the extra keys file the loopback registry
// may add to the pinned set.
func pinExtra(t *testing.T, entries ...map[string]any) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "keys.json")
	if err := os.WriteFile(p, []byte(keysJSON(t, entries...)), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(ExtraKeysEnv, p)
}

// makeTgz builds an npm tarball with files under package/.
func makeTgz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := tw.WriteHeader(&tar.Header{Name: "package/" + n, Mode: 0o644, Size: int64(len(files[n])), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(files[n]))
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// sri is the sha512 SRI of b.
func sri(b []byte) string {
	sum := sha512.Sum512(b)
	return "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
}

// wantErr checks err's code and its full text.
func wantErr(t *testing.T, err error, code core.ErrorCode, text string) {
	t.Helper()
	if err == nil {
		t.Fatalf("no error, want %s", code)
	}
	if got := core.CodeOf(err); got != code {
		t.Errorf("code %q, want %q (%v)", got, code, err)
	}
	if err.Error() != text {
		t.Errorf("error text:\n%s\nwant:\n%s", err.Error(), text)
	}
}
