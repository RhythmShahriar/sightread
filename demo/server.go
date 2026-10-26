// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package demo

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/http"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/RhythmShahriar/sightread/core"
)

// The demo server answers each source under its own path prefix on one
// 127.0.0.1 listener, in the layout of the official hosts, so the real
// sources and fetch code read it as a mirror.
const (
	prefixWPAPI    = "/wporg-api"
	prefixWPDL     = "/wporg-downloads"
	prefixSVN      = "/wporg-svn"
	prefixThemeSVN = "/wporg-theme-svn"
	prefixNPM      = "/npm"
	prefixOSV      = "/osv"
	prefixNone     = "/none" // Packagist and GitHub: the demo reviews nothing there
)

// epoch is the modification time of every archive entry, so the
// archives are the same bytes on every run.
var epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// built is one demo version with its archive and hashes.
type built struct {
	pkg       *Package
	v         *Version
	archive   []byte
	integrity string            // npm SRI sha512
	signature string            // npm registry signature
	sums      map[string]string // WordPress.org per-file sha256
	published time.Time
}

// Server serves the demo packages. Its zero value is not usable; call
// Start.
type Server struct {
	srv   *http.Server
	ln    net.Listener
	base  string
	key   *ecdsa.PrivateKey
	keyID string
	pkgs  []Package
	vers  map[string][]*built // "<eco>:<name>" to its versions, oldest first

	mu       sync.Mutex
	requests []string
	refused  []string
}

// Start builds every archive, generates the npm signing key and serves
// on addr, which must be a 127.0.0.1 address ("127.0.0.1:0" picks a
// free port). now dates the versions.
func Start(addr string, now time.Time) (*Server, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host != "127.0.0.1" {
		return nil, fmt.Errorf("%w: %q", ErrNotLoopback, addr)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(spki)
	s := &Server{key: key, keyID: "SHA256:" + base64.StdEncoding.EncodeToString(sum[:]), pkgs: Packages(), vers: map[string][]*built{}}
	for i := range s.pkgs {
		p := &s.pkgs[i]
		for _, v := range []*Version{p.Old, p.New} {
			if v == nil {
				continue
			}
			b, err := s.build(p, v, now)
			if err != nil {
				return nil, err
			}
			k := string(p.Eco) + ":" + p.Name
			s.vers[k] = append(s.vers[k], b)
		}
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("demo server: %w", err)
	}
	s.ln = ln
	s.base = "http://" + ln.Addr().String()
	s.srv = &http.Server{Handler: s, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = s.srv.Serve(ln) }()
	return s, nil
}

// Close stops the server.
func (s *Server) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return s.srv.Shutdown(ctx)
}

// URL is the server's base, http://127.0.0.1:<port>.
func (s *Server) URL() string { return s.base }

// Bases returns the core.Base* mirror URLs that point every source at
// the server.
func (s *Server) Bases() map[string]string {
	return map[string]string{
		core.BaseWPOrgAPI:       s.base + prefixWPAPI,
		core.BaseWPOrgDownloads: s.base + prefixWPDL,
		core.BaseWPOrgSVN:       s.base + prefixSVN,
		core.BaseWPOrgThemeSVN:  s.base + prefixThemeSVN,
		core.BasePackagist:      s.base + prefixNone,
		core.BasePackagistMeta:  s.base + prefixNone,
		core.BaseGitHubAPI:      s.base + prefixNone,
		core.BaseGitHubCodeload: s.base + prefixNone,
		core.BaseNPM:            s.base + prefixNPM,
		core.BaseOSV:            s.base + prefixOSV,
	}
}

// Proxy is a URL to use as the HTTPS proxy: anything that would leave
// the machine reaches the server instead, which refuses it and records
// it in Refused.
func (s *Server) Proxy() string { return s.base }

// Requests returns "METHOD path" for every request served, in order.
func (s *Server) Requests() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.requests)
}

// Refused returns every request that tried to reach another host
// through the proxy. The demo must leave it empty.
func (s *Server) Refused() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.refused)
}

// KeysJSON is the npm signing key in the registry's /-/npm/v1/keys
// shape, for SIGHTREAD_NPM_EXTRA_KEYS.
func (s *Server) KeysJSON() ([]byte, error) {
	spki, err := x509.MarshalPKIXPublicKey(&s.key.PublicKey)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(map[string]any{"keys": []map[string]any{{
		"expires": nil, "keyid": s.keyID, "keytype": "ecdsa-sha2-nistp256", "scheme": "ecdsa-sha2-nistp256",
		"key": base64.StdEncoding.EncodeToString(spki)}}}, "", "  ")
}

// Archive returns the archive bytes of one demo version and its file
// name, for demo --keep.
func (s *Server) Archive(eco core.Ecosystem, name, version string) ([]byte, string, bool) {
	for _, b := range s.vers[string(eco)+":"+name] {
		if b.v.Version == version {
			if eco == core.NPM {
				return b.archive, tarballName(name, version), true
			}
			return b.archive, name + "." + version + ".zip", true
		}
	}
	return nil, "", false
}

// build packs one version: a zip under <slug>/ with WordPress.org
// checksums, or an npm tarball under package/ with its SRI and registry
// signature.
func (s *Server) build(p *Package, v *Version, now time.Time) (*built, error) {
	b := &built{pkg: p, v: v, published: now.Add(-v.Age).UTC().Truncate(time.Second)}
	files := slices.Clone(v.Files)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	var err error
	if p.Eco == core.NPM {
		if b.archive, err = tarGz(files); err != nil {
			return nil, err
		}
		sum := sha512.Sum512(b.archive)
		b.integrity = "sha512-" + base64.StdEncoding.EncodeToString(sum[:])
		digest := sha256.Sum256([]byte(p.Name + "@" + v.Version + ":" + b.integrity))
		der, err := ecdsa.SignASN1(rand.Reader, s.key, digest[:])
		if err != nil {
			return nil, err
		}
		b.signature = base64.StdEncoding.EncodeToString(der)
		return b, nil
	}
	if b.archive, err = zipOf(p.Name, files); err != nil {
		return nil, err
	}
	b.sums = map[string]string{}
	for _, f := range files {
		sum := sha256.Sum256([]byte(f.Body))
		b.sums[f.Path] = hex.EncodeToString(sum[:])
	}
	return b, nil
}

func zipOf(top string, files []File) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		hdr := &zip.FileHeader{Name: path.Join(top, f.Path), Method: zip.Deflate, Modified: epoch}
		hdr.SetMode(0o644)
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write([]byte(f.Body)); err != nil {
			return nil, err
		}
	}
	err := zw.Close()
	return buf.Bytes(), err
}

func tarGz(files []File) ([]byte, error) {
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	gw.ModTime = epoch
	tw := tar.NewWriter(gw)
	for _, f := range files {
		hdr := &tar.Header{Name: path.Join("package", f.Path), Mode: 0o644, Size: int64(len(f.Body)), ModTime: epoch, Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			return nil, err
		}
		if _, err := tw.Write([]byte(f.Body)); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	err := gw.Close()
	return buf.Bytes(), err
}

// tarballName is npm's tarball file name: the unscoped name and the
// version.
func tarballName(name, version string) string {
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	return name + "-" + version + ".tgz"
}

// ServeHTTP routes a request by its path prefix. A CONNECT, or a
// request for an absolute URL, is something trying to leave the machine
// through the proxy: it is refused and recorded.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect || r.URL.IsAbs() {
		s.mu.Lock()
		s.refused = append(s.refused, r.Method+" "+r.Host)
		s.mu.Unlock()
		http.Error(w, "the Sightread demo reaches nothing but 127.0.0.1", http.StatusForbidden)
		return
	}
	s.mu.Lock()
	s.requests = append(s.requests, r.Method+" "+r.URL.Path)
	s.mu.Unlock()
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, prefixWPAPI+"/plugins/info/1.2"):
		s.wpInfo(w, r)
	case strings.HasPrefix(p, prefixWPDL+"/plugin-checksums/"):
		s.wpChecksums(w, strings.TrimPrefix(p, prefixWPDL+"/plugin-checksums/"))
	case strings.HasPrefix(p, prefixWPDL+"/plugin/"):
		s.wpZip(w, strings.TrimPrefix(p, prefixWPDL+"/plugin/"))
	case strings.HasPrefix(p, prefixSVN+"/"):
		s.svn(w, r, strings.TrimPrefix(p, prefixSVN+"/"))
	case p == prefixOSV+"/v1/querybatch" && r.Method == http.MethodPost:
		s.osv(w, r)
	case p == prefixNPM+"/-/npm/v1/keys":
		b, err := s.KeysJSON()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
	case strings.HasPrefix(p, prefixNPM+"/"):
		s.npm(w, r, strings.TrimPrefix(p, prefixNPM+"/"))
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// find returns the versions of one package.
func (s *Server) find(eco core.Ecosystem, name string) []*built {
	return s.vers[string(eco)+":"+name]
}

func (s *Server) version(eco core.Ecosystem, name, version string) (*built, bool) {
	for _, b := range s.find(eco, name) {
		if b.v.Version == version {
			return b, true
		}
	}
	return nil, false
}

// wpInfo answers the plugin information API.
func (s *Server) wpInfo(w http.ResponseWriter, r *http.Request) {
	slug := r.URL.Query().Get("request[slug]")
	vers := s.find(core.WPPlugin, slug)
	if len(vers) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "Plugin not found."})
		return
	}
	latest := vers[len(vers)-1]
	links := map[string]string{}
	var log strings.Builder
	for i := len(vers) - 1; i >= 0; i-- {
		v := vers[i].v.Version
		links[v] = s.base + prefixWPDL + "/plugin/" + slug + "." + v + ".zip"
		log.WriteString("<h4>" + v + "</h4>\n")
	}
	contributors := map[string]any{}
	for _, b := range vers {
		contributors[b.v.Committer] = map[string]string{"profile": "https://profiles.wordpress.org/" + b.v.Committer}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"name": latest.pkg.Title, "slug": slug, "version": latest.v.Version,
		"author": latest.pkg.Title, "author_profile": "https://profiles.wordpress.org/" + latest.v.Committer,
		"contributors": contributors, "requires": "6.0", "tested": "6.8", "requires_php": "7.4",
		"last_updated": latest.published.Format("2006-01-02 3:04pm MST"), "added": vers[0].published.Format(time.DateOnly),
		"download_link": links[latest.v.Version], "versions": links, "sections": map[string]string{"changelog": log.String()},
		"active_installs": 10000,
	})
}

// wpZip serves /plugin/<slug>.<version>.zip.
func (s *Server) wpZip(w http.ResponseWriter, file string) {
	slug, version, ok := strings.Cut(strings.TrimSuffix(file, ".zip"), ".")
	b, found := s.version(core.WPPlugin, slug, version)
	if !ok || !found {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	_, _ = w.Write(b.archive)
}

// wpChecksums serves /plugin-checksums/<slug>/<version>.json.
func (s *Server) wpChecksums(w http.ResponseWriter, rest string) {
	slug, file := path.Split(rest)
	b, ok := s.version(core.WPPlugin, strings.Trim(slug, "/"), strings.TrimSuffix(file, ".json"))
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	files := map[string]map[string]string{}
	for p, sum := range b.sums {
		files[p] = map[string]string{"sha256": sum}
	}
	writeJSON(w, http.StatusOK, map[string]any{"plugin": b.pkg.Name, "version": b.v.Version, "files": files})
}

// svn answers PROPFIND on <slug>/tags/<version>/ with the tag creator,
// the owner fact Sightread reads for a WordPress.org version.
func (s *Server) svn(w http.ResponseWriter, r *http.Request, rest string) {
	slug, after, ok := strings.Cut(rest, "/tags/")
	b, found := s.version(core.WPPlugin, slug, strings.Trim(after, "/"))
	if !ok || !found || r.Method != "PROPFIND" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	type prop struct {
		Creator string `xml:"D:creator-displayname"`
	}
	type response struct {
		Href   string `xml:"D:href"`
		Prop   prop   `xml:"D:propstat>D:prop"`
		Status string `xml:"D:propstat>D:status"`
	}
	ms := struct {
		XMLName   xml.Name   `xml:"D:multistatus"`
		NS        string     `xml:"xmlns:D,attr"`
		Responses []response `xml:"D:response"`
	}{NS: "DAV:", Responses: []response{{Href: r.URL.Path, Prop: prop{Creator: b.v.Committer}, Status: "HTTP/1.1 200 OK"}}}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	_, _ = w.Write([]byte(xml.Header))
	_ = xml.NewEncoder(w).Encode(ms)
}

// osv answers a querybatch with no advisories for anything.
func (s *Server) osv(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Queries []json.RawMessage `json:"queries"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	results := make([]map[string]any, len(body.Queries))
	for i := range results {
		results[i] = map[string]any{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// npm serves the packument, a version document or a tarball.
func (s *Server) npm(w http.ResponseWriter, r *http.Request, rest string) {
	name, tail, _ := strings.Cut(rest, "/")
	vers := s.find(core.NPM, name)
	if len(vers) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "Not found"})
		return
	}
	switch {
	case tail == "":
		latest := vers[len(vers)-1]
		docs, times := map[string]any{}, map[string]string{"created": vers[0].published.Format(npmTime)}
		for _, b := range vers {
			docs[b.v.Version] = s.npmDoc(b)
			times[b.v.Version] = b.published.Format(npmTime)
		}
		times["modified"] = latest.published.Format(npmTime)
		doc := map[string]any{"name": name, "dist-tags": map[string]string{"latest": latest.v.Version}, "versions": docs,
			"modified": times["modified"]}
		if !strings.Contains(r.Header.Get("Accept"), "install-v1") {
			doc["time"] = times
			doc["maintainers"] = []map[string]string{npmUser(latest.v.Committer)}
		}
		writeJSON(w, http.StatusOK, doc)
	case strings.HasPrefix(tail, "-/"):
		for _, b := range vers {
			if tarballName(name, b.v.Version) == strings.TrimPrefix(tail, "-/") {
				w.Header().Set("Content-Type", "application/octet-stream")
				_, _ = w.Write(b.archive)
				return
			}
		}
		http.Error(w, "not found", http.StatusNotFound)
	default:
		b, ok := s.version(core.NPM, name, tail)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "version not found: " + tail})
			return
		}
		writeJSON(w, http.StatusOK, s.npmDoc(b))
	}
}

// npmTime is the packument's time format.
const npmTime = "2006-01-02T15:04:05.000Z"

// npmDoc is one version's document.
func (s *Server) npmDoc(b *built) map[string]any {
	doc := map[string]any{
		"name": b.pkg.Name, "version": b.v.Version, "license": "MIT",
		"_npmUser":    npmUser(b.v.Committer),
		"maintainers": []map[string]string{npmUser(b.v.Committer)},
		"dist": map[string]any{
			"tarball":    s.base + prefixNPM + "/" + b.pkg.Name + "/-/" + tarballName(b.pkg.Name, b.v.Version),
			"integrity":  b.integrity,
			"signatures": []map[string]string{{"keyid": s.keyID, "sig": b.signature}},
		},
	}
	if len(b.v.Scripts) > 0 {
		doc["scripts"] = b.v.Scripts
		doc["hasInstallScript"] = true
	}
	if len(b.v.Deps) > 0 {
		doc["dependencies"] = b.v.Deps
	}
	return doc
}

func npmUser(name string) map[string]string {
	return map[string]string{"name": name, "email": name + "@users.noreply.npmjs.example"}
}

// ErrNotLoopback is returned for an address off 127.0.0.1.
var ErrNotLoopback = errors.New("demo server: not a 127.0.0.1 address")
