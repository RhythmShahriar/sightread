// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package demo

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// start runs a server on the first free port of this lane's range.
func start(t *testing.T) *Server {
	t.Helper()
	for p := 31108; p <= 31111; p++ {
		s, err := Start(fmt.Sprintf("127.0.0.1:%d", p), time.Now())
		if err == nil {
			t.Cleanup(func() { _ = s.Close() })
			return s
		}
	}
	t.Fatal("no free port in 31108-31111")
	return nil
}

func get(t *testing.T, s *Server, method, u string, hdr ...string) (int, []byte) {
	t.Helper()
	req, err := http.NewRequest(method, u, nil) //nolint:noctx // a test request to the test's own server
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := (&http.Client{Transport: coretest.LoopbackOnly(t)}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func TestStartRefusesOtherAddresses(t *testing.T) {
	for _, addr := range []string{"0.0.0.0:0", ":0", "localhost:0", "192.168.1.2:0"} {
		if _, err := Start(addr, time.Now()); !errors.Is(err, ErrNotLoopback) {
			t.Errorf("%s: %v, want ErrNotLoopback", addr, err)
		}
	}
}

// TestWordPressOrg: the info API, the zip and the checksums agree. The
// SVN tag names the committer.
func TestWordPressOrg(t *testing.T) {
	s := start(t)
	b := s.Bases()
	code, body := get(t, s, http.MethodGet, b[core.BaseWPOrgAPI]+"/plugins/info/1.2/?action=plugin_information&request[slug]=share-kit")
	var info struct {
		Version      string            `json:"version"`
		DownloadLink string            `json:"download_link"`
		Versions     map[string]string `json:"versions"`
	}
	if err := json.Unmarshal(body, &info); code != http.StatusOK || err != nil || info.Version != "3.2.1" || len(info.Versions) != 2 {
		t.Fatalf("info: %d %v %s", code, err, body)
	}
	code, zipped := get(t, s, http.MethodGet, info.DownloadLink)
	zr, err := zip.NewReader(bytes.NewReader(zipped), int64(len(zipped)))
	if code != http.StatusOK || err != nil {
		t.Fatalf("zip: %d %v", code, err)
	}
	_, body = get(t, s, http.MethodGet, b[core.BaseWPOrgDownloads]+"/plugin-checksums/share-kit/3.2.1.json")
	var sums struct {
		Files map[string]struct{ SHA256 string } `json:"files"`
	}
	if err := json.Unmarshal(body, &sums); err != nil || len(sums.Files) != len(zr.File) {
		t.Fatalf("checksums %s (%v)", body, err)
	}
	for _, f := range zr.File {
		rc, _ := f.Open()
		data, _ := io.ReadAll(rc)
		_ = rc.Close()
		sum := sha256.Sum256(data)
		rel := strings.TrimPrefix(f.Name, "share-kit/")
		if !strings.HasPrefix(f.Name, "share-kit/") || sums.Files[rel].SHA256 != hex.EncodeToString(sum[:]) {
			t.Errorf("%s: not under share-kit/ or its checksum differs", f.Name)
		}
	}
	code, body = get(t, s, "PROPFIND", b[core.BaseWPOrgSVN]+"/share-kit/tags/3.2.1/")
	if code != http.StatusMultiStatus || !strings.Contains(string(body), "<D:creator-displayname>growth-partners</D:creator-displayname>") {
		t.Errorf("svn 3.2.1: %d %s", code, body)
	}
	if _, body := get(t, s, "PROPFIND", b[core.BaseWPOrgSVN]+"/share-kit/tags/3.2.0/"); !strings.Contains(string(body), ">sharekit<") {
		t.Errorf("svn 3.2.0: %s", body)
	}
	if code, _ := get(t, s, http.MethodGet, b[core.BaseWPOrgAPI]+"/plugins/info/1.2/?request[slug]=akismet"); code != http.StatusNotFound {
		t.Errorf("unknown slug: %d", code)
	}
}

// TestNPM: the packument, the version document and the tarball agree:
// the tarball's sha512 is the integrity and the signature verifies with
// the published key.
func TestNPM(t *testing.T) {
	s := start(t)
	b := s.Bases()
	code, body := get(t, s, http.MethodGet, b[core.BaseNPM]+"/date-utils-lite", "Accept", "application/vnd.npm.install-v1+json")
	var pack struct {
		DistTags map[string]string `json:"dist-tags"`
		Versions map[string]struct {
			Dist struct {
				Tarball, Integrity string
				Signatures         []struct{ Keyid, Sig string }
			}
			Scripts      map[string]string
			Dependencies map[string]string
		}
	}
	if err := json.Unmarshal(body, &pack); code != http.StatusOK || err != nil || pack.DistTags["latest"] != "1.4.1" {
		t.Fatalf("packument: %d %v %s", code, err, body)
	}
	v := pack.Versions["1.4.1"]
	if v.Scripts["postinstall"] == "" || v.Dependencies["axois"] == "" {
		t.Errorf("1.4.1 lacks its install script or new dependency: %+v", v)
	}
	_, tgz := get(t, s, http.MethodGet, v.Dist.Tarball)
	sum := sha512.Sum512(tgz)
	if v.Dist.Integrity != "sha512-"+base64.StdEncoding.EncodeToString(sum[:]) {
		t.Errorf("integrity %s doesn't match the tarball", v.Dist.Integrity)
	}
	_, keysBody := get(t, s, http.MethodGet, b[core.BaseNPM]+"/-/npm/v1/keys")
	var keys struct{ Keys []struct{ Keyid, Key string } }
	if err := json.Unmarshal(keysBody, &keys); err != nil || len(keys.Keys) != 1 || keys.Keys[0].Keyid != v.Dist.Signatures[0].Keyid {
		t.Fatalf("keys %s (%v)", keysBody, err)
	}
	der, _ := base64.StdEncoding.DecodeString(keys.Keys[0].Key)
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := base64.StdEncoding.DecodeString(v.Dist.Signatures[0].Sig)
	digest := sha256.Sum256([]byte("date-utils-lite@1.4.1:" + v.Dist.Integrity))
	if !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), digest[:], sig) { //nolint:forcetypeassert // the server makes a P-256 key
		t.Errorf("the registry signature doesn't verify")
	}
	gz, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, err := tr.Next()
		if err != nil {
			break
		}
		names = append(names, h.Name)
	}
	if strings.Join(names, " ") != "package/index.js package/package.json package/scripts/setup.js" {
		t.Errorf("tarball entries %q", names)
	}
	if code, body := get(t, s, http.MethodGet, b[core.BaseNPM]+"/axois/1.0.0"); code != http.StatusOK || !strings.Contains(string(body), "postinstall") {
		t.Errorf("axois 1.0.0: %d %s", code, body)
	}
	if code, _ := get(t, s, http.MethodGet, b[core.BaseNPM]+"/left-pad"); code != http.StatusNotFound {
		t.Errorf("unknown package: %d", code)
	}
}

// TestOSVAndGuard: OSV answers one empty result per query; anything
// sent through the server as a proxy is refused and recorded.
func TestOSVAndGuard(t *testing.T) {
	s := start(t)
	req, _ := http.NewRequest(http.MethodPost, s.Bases()[core.BaseOSV]+"/v1/querybatch", //nolint:noctx // test request
		strings.NewReader(`{"queries":[{"package":{"name":"a","ecosystem":"npm"},"version":"1"},{}]}`))
	resp, err := (&http.Client{Transport: coretest.LoopbackOnly(t)}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if strings.TrimSpace(string(body)) != `{"results":[{},{}]}` {
		t.Errorf("querybatch %s", body)
	}
	if len(s.Refused()) != 0 {
		t.Fatalf("refused before anything left: %v", s.Refused())
	}
	proxy, _ := url.Parse(s.Proxy())
	conn, err := net.Dial("tcp", proxy.Host)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.WriteString(conn, "CONNECT registry.npmjs.org:443 HTTP/1.1\r\nHost: registry.npmjs.org:443\r\n\r\n")
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	_ = conn.Close()
	if !strings.Contains(string(buf[:n]), "403") || len(s.Refused()) != 1 || s.Refused()[0] != "CONNECT registry.npmjs.org:443" {
		t.Errorf("CONNECT: %q, refused %v", buf[:n], s.Refused())
	}
}

// TestWriteSite: the site holds the old plugins byte for byte and a
// lockfile pinning the old npm version with its integrity.
func TestWriteSite(t *testing.T) {
	dir := t.TempDir()
	if err := WriteSite(dir); err != nil {
		t.Fatal(err)
	}
	for _, p := range Packages() {
		if p.Eco != core.WPPlugin {
			continue
		}
		for _, f := range p.Old.Files {
			b, err := os.ReadFile(filepath.Join(dir, "wp-content", "plugins", p.Name, filepath.FromSlash(f.Path))) //nolint:gosec // the test's own folder
			if err != nil || string(b) != f.Body {
				t.Errorf("%s/%s differs from the published %s (%v)", p.Name, f.Path, p.Old.Version, err)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "wp-includes", "version.php")); err != nil {
		t.Errorf("no WordPress root: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "package-lock.json")) //nolint:gosec // the test's own folder
	if err != nil {
		t.Fatal(err)
	}
	var lock struct {
		Packages map[string]struct{ Version, Integrity string }
	}
	if err := json.Unmarshal(b, &lock); err != nil {
		t.Fatal(err)
	}
	s := start(t)
	tgz, _, _ := s.Archive(core.NPM, "date-utils-lite", "1.4.0")
	sum := sha512.Sum512(tgz)
	if e := lock.Packages["node_modules/date-utils-lite"]; e.Version != "1.4.0" || e.Integrity != "sha512-"+base64.StdEncoding.EncodeToString(sum[:]) {
		t.Errorf("lock entry %+v doesn't pin the published 1.4.0", e)
	}
	if _, ok := lock.Packages["node_modules/axois"]; ok {
		t.Errorf("the typosquat is installed before the update adds it")
	}
}

// TestFixturesStayText: every demo script that looks like it would
// fetch something points at 127.0.0.1. Every piece of the Essential
// Plugin pattern is there.
func TestFixturesStayText(t *testing.T) {
	var all strings.Builder
	for _, p := range Packages() {
		for _, v := range []*Version{p.Old, p.New} {
			if v == nil {
				continue
			}
			for _, f := range v.Files {
				all.WriteString(f.Body)
				if strings.Contains(f.Body, "http://") && !strings.Contains(f.Body, "http://127.0.0.1:9/") {
					t.Errorf("%s %s %s fetches from somewhere other than 127.0.0.1:9", p.Name, v.Version, f.Path)
				}
			}
		}
	}
	for _, want := range []string{"unserialize( wp_remote_retrieve_body", "'permission_callback' => '__return_true'",
		"$fn( $request", "mainnet.infura.io", "Improved compatibility and performance.", "eval(body)", "\"postinstall\""} {
		if !strings.Contains(all.String(), want) {
			t.Errorf("the fixtures lack %q", want)
		}
	}
	if got := Packages(); got[0].Expect != core.Routine || got[1].Expect != core.Hold || got[2].Expect != core.Hold {
		t.Errorf("expected verdicts %v %v %v", got[0].Expect, got[1].Expect, got[2].Expect)
	}
}
