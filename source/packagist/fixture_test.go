// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package packagist

import (
	"archive/zip"
	"bytes"
	"crypto/sha1" //nolint:gosec // Packagist's dist.shasum is SHA-1
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"testing"

	"github.com/RhythmShahriar/sightread/blob"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/fetch"
)

// The ports this package's tests may listen on.
const firstPort, lastPort = 31000, 31019

// server answers from a map of paths, with optional redirects and
// statuses; it logs every request.
type server struct {
	mu       sync.Mutex
	body     map[string][]byte
	status   map[string]int
	redirect map[string]string
	log      []string
	auth     map[string]string // the Authorization header per path, last seen
	url      string
}

func newServer(t *testing.T) *server {
	t.Helper()
	s := &server{body: map[string][]byte{}, status: map[string]int{}, redirect: map[string]string{}, auth: map[string]string{}}
	srv := httptest.NewUnstartedServer(s)
	_ = srv.Listener.Close()
	srv.Listener = listen(t)
	srv.Start()
	t.Cleanup(srv.Close)
	s.url = srv.URL
	return s
}

func (s *server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p := req.URL.Path
	s.log = append(s.log, req.Method+" "+p)
	s.auth[p] = req.Header.Get("Authorization")
	if st := s.status[p]; st != 0 {
		w.WriteHeader(st)
		return
	}
	if to, ok := s.redirect[p]; ok {
		http.Redirect(w, req, to, http.StatusFound)
		return
	}
	if b, ok := s.body[p]; ok {
		_, _ = w.Write(b)
		return
	}
	http.NotFound(w, req)
}

func (s *server) set(path, body string)          { s.mu.Lock(); s.body[path] = []byte(body); s.mu.Unlock() }
func (s *server) setBytes(path string, b []byte) { s.mu.Lock(); s.body[path] = b; s.mu.Unlock() }

func (s *server) requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.log...)
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

// env builds an Env whose Packagist and GitHub bases point at pub, with
// the private repositories given; it uses a real fetch client.
func env(t *testing.T, pub *server, auth string, private ...*server) *core.Env {
	t.Helper()
	bases := map[string]string{
		core.BasePackagist: pub.url, core.BasePackagistMeta: pub.url,
		core.BaseGitHubAPI: pub.url, core.BaseGitHubCodeload: pub.url,
	}
	for i, p := range private {
		bases[core.BaseComposerRepo+fmt.Sprint(i)] = p.url
	}
	get, err := fetch.New(core.GetterConfig{Bases: bases, CacheDir: t.TempDir(), Retries: -1, ComposerAuth: auth})
	if err != nil {
		t.Fatal(err)
	}
	return &core.Env{Get: get, Blobs: blob.Memory(), Bases: bases}
}

// makeZip builds a zip with files under top.
func makeZip(t *testing.T, top string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		w, err := zw.Create(top + "/" + n)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.WriteString(w, files[n])
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sha1Hex(b []byte) string {
	sum := sha1.Sum(b) //nolint:gosec // matches Packagist's dist.shasum
	return hex.EncodeToString(sum[:])
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
