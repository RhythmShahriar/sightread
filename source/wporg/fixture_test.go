// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package wporg

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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

// registry plays WordPress.org on 127.0.0.1: the info APIs, the zips,
// the plugin checksums and the two SVN servers. Every route answers
// from the maps below, so a test sets only what it needs.
type registry struct {
	mu        sync.Mutex
	info      map[string]string      // "plugins/<slug>" or "themes/<slug>" to the info JSON
	closed    map[string]string      // the same keys to a 404 body (a closed plugin)
	status    map[string]int         // a path to the status it answers with
	zips      map[string][]byte      // "plugin/<file>.zip" to the bytes
	checksums map[string]string      // "<slug>/<v>" to the checksums JSON
	dav       map[string]string      // an SVN path to its PROPFIND answer
	svnFiles  map[string]string      // an SVN path to a file's content
	log       []string               // "<method> <path>" of every request
	hits      map[string]int         // the same, counted
	headers   map[string]http.Header // the last request headers per path
}

func newRegistry() *registry {
	return &registry{
		info: map[string]string{}, closed: map[string]string{}, status: map[string]int{}, zips: map[string][]byte{},
		checksums: map[string]string{}, dav: map[string]string{}, svnFiles: map[string]string{},
		hits: map[string]int{}, headers: map[string]http.Header{},
	}
}

func (r *registry) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := req.URL.Path
	r.log = append(r.log, req.Method+" "+p)
	r.hits[req.Method+" "+p]++
	r.headers[p] = req.Header.Clone()
	if st := r.status[p]; st != 0 {
		w.WriteHeader(st)
		return
	}
	switch {
	case req.Method == "PROPFIND":
		if body, ok := r.dav[p]; ok {
			w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
			w.WriteHeader(http.StatusMultiStatus)
			_, _ = io.WriteString(w, body)
			return
		}
	case strings.HasPrefix(p, "/plugins/info/1.2/") || strings.HasPrefix(p, "/themes/info/1.2/"):
		kind := strings.Split(p, "/")[1]
		slug := req.URL.Query().Get("request[slug]")
		w.Header().Set("Content-Type", "application/json")
		if body, ok := r.info[kind+"/"+slug]; ok {
			_, _ = io.WriteString(w, body)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		if body, ok := r.closed[kind+"/"+slug]; ok {
			_, _ = io.WriteString(w, body)
			return
		}
		if kind == "themes" {
			_, _ = io.WriteString(w, `{"error":"Theme not found"}`)
			return
		}
		_, _ = io.WriteString(w, `{"error":"Plugin not found."}`)
		return
	case strings.HasPrefix(p, "/plugin-checksums/"):
		if body, ok := r.checksums[strings.TrimSuffix(strings.TrimPrefix(p, "/plugin-checksums/"), ".json")]; ok {
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, body)
			return
		}
	case strings.HasPrefix(p, "/plugin/") || strings.HasPrefix(p, "/theme/"):
		if data, ok := r.zips[strings.TrimPrefix(p, "/")]; ok {
			_, _ = w.Write(data)
			return
		}
	default:
		if body, ok := r.svnFiles[p]; ok {
			_, _ = io.WriteString(w, body)
			return
		}
	}
	http.NotFound(w, req)
}

// count returns how often "<method> <path>" was asked for.
func (r *registry) count(key string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.hits[key]
}

// requests returns the request log.
func (r *registry) requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.log...)
}

// start serves r on the first free port of the range and returns an
// Env whose every WordPress.org base points at it, with a real fetch
// client (no retries, so a 503 answers at once).
func start(t *testing.T, r *registry, opts core.SourceOptions) *core.Env {
	t.Helper()
	srv := httptest.NewUnstartedServer(r)
	_ = srv.Listener.Close()
	srv.Listener = listen(t)
	srv.Start()
	t.Cleanup(srv.Close)
	bases := map[string]string{
		core.BaseWPOrgAPI: srv.URL, core.BaseWPOrgDownloads: srv.URL,
		core.BaseWPOrgSVN: srv.URL, core.BaseWPOrgThemeSVN: srv.URL,
	}
	get, err := fetch.New(core.GetterConfig{Bases: bases, CacheDir: t.TempDir(), Retries: -1})
	if err != nil {
		t.Fatal(err)
	}
	return &core.Env{Get: get, Blobs: blob.Memory(), Bases: bases, Options: opts}
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

// makeZip builds a zip with every file under top (no folder entries,
// as WordPress.org's zips have them, so a folder entry is added too).
func makeZip(t *testing.T, top string, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if top != "" {
		if _, err := zw.Create(top + "/"); err != nil {
			t.Fatal(err)
		}
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		name := n
		if top != "" {
			name = top + "/" + n
		}
		w, err := zw.Create(name)
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

// sha is the hex SHA-256 of s.
func sha(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// checksumsJSON is a plugin-checksums answer for files, in the shape
// downloads.wordpress.org serves (copied by hand, values made up).
func checksumsJSON(t *testing.T, slug, v string, files map[string]string) string {
	t.Helper()
	type entry struct {
		MD5    string `json:"md5"`
		SHA256 any    `json:"sha256"`
	}
	out := map[string]entry{}
	for p, body := range files {
		out[p] = entry{MD5: "0123456789abcdef0123456789abcdef", SHA256: sha(body)}
	}
	b, err := json.Marshal(map[string]any{
		"plugin": slug, "version": v,
		"source": "https://plugins.svn.wordpress.org/" + slug + "/tags/" + v + "/",
		"zip":    "https://downloads.wordpress.org/plugins/" + slug + "." + v + ".zip",
		"files":  out,
	})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// davOne is a mod_dav_svn answer to a depth 0 PROPFIND of a folder.
func davOne(path, creator, created string) string {
	return `<?xml version="1.0" encoding="utf-8"?>
<D:multistatus xmlns:D="DAV:" xmlns:ns0="DAV:">
<D:response xmlns:lp1="DAV:" xmlns:lp2="http://subversion.tigris.org/xmlns/dav/">
<D:href>` + path + `</D:href>
<D:propstat>
<D:prop>
<lp1:resourcetype><D:collection/></lp1:resourcetype>
<lp1:creator-displayname>` + creator + `</lp1:creator-displayname>
<lp1:creationdate>` + created + `</lp1:creationdate>
</D:prop>
<D:status>HTTP/1.1 200 OK</D:status>
</D:propstat>
</D:response>
</D:multistatus>`
}
