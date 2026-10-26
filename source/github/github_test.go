// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package github

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/RhythmShahriar/sightread/blob"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/fetch"
)

// The ports this package's tests may listen on.
const firstPort, lastPort = 31000, 31019

// api plays api.github.com's git refs endpoint for the tags it holds.
type api struct {
	mu     sync.Mutex
	tags   map[string]bool // "<owner>/<repo>/<tag>"
	status int
	log    []string
}

func (a *api) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.log = append(a.log, r.URL.EscapedPath())
	if a.status != 0 {
		w.WriteHeader(a.status)
		return
	}
	rest, ok := strings.CutPrefix(r.URL.Path, "/repos/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	parts := strings.SplitN(rest, "/", 3)
	tag, ok := strings.CutPrefix(parts[2], "git/ref/tags/")
	if !ok || !a.tags[parts[0]+"/"+parts[1]+"/"+tag] {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = io.WriteString(w, `{"message":"Not Found","documentation_url":"https://docs.github.com/rest/git/refs#get-a-reference","status":"404"}`)
		return
	}
	_, _ = fmt.Fprintf(w, `{"ref":"refs/tags/%s","node_id":"x","url":"https://api.github.com/repos/%s/%s/git/refs/tags/%s","object":{"sha":"aef6ee73a77a66e404dd6540934a9ef1b3c855b4","type":"commit"}}`,
		tag, parts[0], parts[1], tag)
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

func start(t *testing.T, a *api) *Checker {
	t.Helper()
	srv := httptest.NewUnstartedServer(a)
	_ = srv.Listener.Close()
	srv.Listener = listen(t)
	srv.Start()
	t.Cleanup(srv.Close)
	bases := map[string]string{core.BaseGitHubAPI: srv.URL}
	get, err := fetch.New(core.GetterConfig{Bases: bases, CacheDir: t.TempDir(), Retries: -1})
	if err != nil {
		t.Fatal(err)
	}
	return New(&core.Env{Get: get, Blobs: blob.Memory(), Bases: bases})
}

func TestTagForms(t *testing.T) {
	a := &api{tags: map[string]bool{
		"axios/axios/v1.14.0":            true,
		"lodash/lodash/4.17.21":          true,
		"babel/babel/@babel/core@7.26.0": true,
	}}
	c := start(t, a)
	ctx := context.Background()
	for _, tt := range []struct{ repo, version, name string }{
		{"git+https://github.com/axios/axios.git", "1.14.0", "axios"},
		{"https://github.com/lodash/lodash", "4.17.21", "lodash"},
		{"github:babel/babel", "7.26.0", "@babel/core"},
	} {
		ok, err := c.TagExists(ctx, tt.repo, tt.version, tt.name)
		if err != nil || !ok {
			t.Errorf("%s %s: %v, %v", tt.repo, tt.version, ok, err)
		}
	}
	if !strings.Contains(strings.Join(a.log, "\n"), "/repos/babel/babel/git/ref/tags/@babel/core@7.26.0") {
		t.Errorf("monorepo tag path: %v", a.log)
	}
}

func TestTagMissing(t *testing.T) {
	a := &api{tags: map[string]bool{}}
	c := start(t, a)
	ok, err := c.TagExists(context.Background(), "https://github.com/axios/axios", "1.14.1", "axios")
	if err != nil || ok {
		t.Errorf("got %v, %v; want false, nil", ok, err)
	}
	if len(a.log) != 3 {
		t.Errorf("asked %d tags, want the three forms: %v", len(a.log), a.log)
	}
}

func TestTagError(t *testing.T) {
	a := &api{status: http.StatusInternalServerError}
	c := start(t, a)
	if _, err := c.TagExists(context.Background(), "https://github.com/axios/axios", "1.14.1", "axios"); err == nil {
		t.Error("a 500 should be an error (not checked)")
	}
}

func TestNotGitHub(t *testing.T) {
	a := &api{}
	c := start(t, a)
	for _, repo := range []string{"https://gitlab.com/o/r", "git+https://bitbucket.org/o/r.git", "", "github:", "https://github.com/onlyowner", "file:///tmp/x"} {
		if _, err := c.TagExists(context.Background(), repo, "1.0.0", "x"); !errors.Is(err, ErrNotGitHub) {
			t.Errorf("%q: %v, want ErrNotGitHub", repo, err)
		}
	}
	if len(a.log) != 0 {
		t.Errorf("GitHub was asked: %v", a.log)
	}
}

func TestRepo(t *testing.T) {
	for in, want := range map[string]string{
		"git+https://github.com/axios/axios.git":   "axios/axios",
		"https://github.com/lodash/lodash":         "lodash/lodash",
		"git://github.com/o/r.git":                 "o/r",
		"git+ssh://git@github.com/o/r.git":         "o/r",
		"git@github.com:o/r.git":                   "o/r",
		"github:o/r":                               "o/r",
		"https://github.com/o/r/tree/main/pkg/sub": "o/r",
		"https://github.com/o/r.git#v1.2.3":        "o/r",
	} {
		o, r, err := Repo(in)
		if err != nil || o+"/"+r != want {
			t.Errorf("Repo(%q) = %s/%s, %v", in, o, r, err)
		}
	}
	for _, in := range []string{"https://github.com/../x", "https://github.com/o/..", "https://evil.example/o/r"} {
		if _, _, err := Repo(in); err == nil {
			t.Errorf("Repo(%q) accepted", in)
		}
	}
}

func TestRegistered(t *testing.T) {
	if _, ok := core.TagCheckerFor(&core.Env{}).(*Checker); !ok {
		t.Error("tag checker not registered")
	}
}
