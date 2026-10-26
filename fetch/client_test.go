// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package fetch

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

func init() {
	// The child half of TestSSLCertFile runs before any other test code.
	if os.Getenv("FETCH_TEST_SSL_CHILD") == "1" {
		os.Exit(sslChild())
	}
}

func TestRegistered(t *testing.T) {
	g, err := core.NewGetter(core.GetterConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := g.(*Client); !ok {
		t.Fatalf("core.NewGetter gave %T, want *fetch.Client", g)
	}
}

// TestCodeloadRedirect: a Packagist zipball on api.github.com redirects
// to codeload.github.com. The redirect is followed and the token goes to
// the first host only (SR-5).
func TestCodeloadRedirect(t *testing.T) {
	token := coretest.FakeKey(coretest.KeyGitHub)
	var codeAuth, apiAuth atomic.Value
	code := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		codeAuth.Store("got:" + r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, "zip bytes")
	}), true)
	api := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		apiAuth.Store(r.Header.Get("Authorization"))
		http.Redirect(w, r, code.URL+"/o/r/legacy.zip/abc", http.StatusFound)
	}), true)
	c := client(t, core.GetterConfig{GitHubToken: token, Bases: map[string]string{
		core.BaseGitHubAPI: api.URL, core.BaseGitHubCodeload: code.URL,
	}}, api, code)
	blobs := newRecordBlobs()
	d, err := c.Download(context.Background(), api.URL+"/repos/o/r/zipball/abc", 1<<20, blobs)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(read(t, blobs, d.SHA256)); got != "zip bytes" || d.Size != 9 {
		t.Errorf("downloaded %q (%d bytes)", got, d.Size)
	}
	if apiAuth.Load() != "Bearer "+token {
		t.Error("api.github.com did not get the token")
	}
	if codeAuth.Load() != "got:" {
		t.Errorf("codeload got Authorization %q, want none", codeAuth.Load())
	}
}

func TestDownloadHashes(t *testing.T) {
	body := "archive contents"
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, body) }), true)
	c := client(t, core.GetterConfig{Bases: map[string]string{core.BaseNPM: srv.URL}}, srv)
	d, err := c.Download(context.Background(), srv.URL+"/x/-/x-1.0.0.tgz", 1<<20, coretest.MemBlobs())
	if err != nil {
		t.Fatal(err)
	}
	if d.SHA256 != sha256.Sum256([]byte(body)) {
		t.Error("sha256 differs")
	}
	if d.SHA512 == [64]byte{} || d.SHA1 == [20]byte{} {
		t.Error("sha512 or sha1 left empty")
	}
	if d.Path != "" {
		t.Errorf("memory store gave path %q", d.Path)
	}
}

func TestLoopbackMirror(t *testing.T) {
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"name":"left-pad","accept":`+fmt.Sprintf("%q", r.Header.Get("Accept"))+`}`)
	}), false)
	c := client(t, core.GetterConfig{Bases: map[string]string{core.BaseNPM: srv.URL}})
	var v struct{ Name, Accept string }
	if err := c.JSON(context.Background(), srv.URL+"/left-pad", &v, KindVersions); err != nil {
		t.Fatal(err)
	}
	if v.Name != "left-pad" {
		t.Errorf("name %q", v.Name)
	}
	if !strings.HasPrefix(v.Accept, "application/vnd.npm.install-v1+json") {
		t.Errorf("Accept %q, want the abbreviated packument", v.Accept)
	}
	var m struct{ Accept string }
	if err := c.JSON(context.Background(), srv.URL+"/left-pad/1.3.0", &m, KindMeta); err != nil {
		t.Fatal(err)
	}
	if m.Accept != "application/json" {
		t.Errorf("per-version Accept %q", m.Accept)
	}
	var full struct{ Accept string }
	if err := c.JSON(context.Background(), srv.URL+"/left-pad", &full, KindPackument); err != nil {
		t.Fatal(err)
	}
	if full.Accept != "application/json" {
		t.Errorf("full packument Accept %q", full.Accept)
	}
}

func TestIsLoopbackBase(t *testing.T) {
	for base, want := range map[string]bool{
		"http://127.0.0.1:31000": true, "http://[::1]:8080/npm": true, "https://localhost": true,
		"https://registry.npmjs.org": false, "http://127.0.0.2": false, "not a url": false, "": false,
	} {
		if got := IsLoopbackBase(base); got != want {
			t.Errorf("IsLoopbackBase(%q) = %v", base, got)
		}
	}
}

func TestRetryAfter(t *testing.T) {
	var n atomic.Int32
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if n.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = io.WriteString(w, `{"ok":true}`)
	}), true)
	c := client(t, core.GetterConfig{Bases: map[string]string{core.BaseWPOrgAPI: srv.URL}}, srv)
	var v struct{ OK bool }
	if err := c.JSON(context.Background(), srv.URL+"/plugins/info/1.2/", &v, KindMeta); err != nil {
		t.Fatal(err)
	}
	if !v.OK || n.Load() != 2 {
		t.Errorf("ok %v after %d requests", v.OK, n.Load())
	}
}

func TestComposerAuth(t *testing.T) {
	user, pass := "deploy", "pw-"+"fixture-only"
	var gotRepo, gotOther atomic.Value
	other := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOther.Store("got:" + r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, `{}`)
	}), true)
	repo := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRepo.Store(r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, `{}`)
	}), true)
	host := strings.TrimPrefix(repo.URL, "https://")
	auth, _ := json.Marshal(map[string]any{"http-basic": map[string]any{host: map[string]string{"username": user, "password": pass}}})
	c := client(t, core.GetterConfig{ComposerAuth: string(auth), Bases: map[string]string{
		core.BaseComposerRepo + "0": repo.URL, core.BasePackagist: other.URL,
	}}, repo, other)
	var v any
	if err := c.JSON(context.Background(), repo.URL+"/packages.json", &v, KindMeta); err != nil {
		t.Fatal(err)
	}
	if err := c.JSON(context.Background(), other.URL+"/p2/a/b.json", &v, KindMeta); err != nil {
		t.Fatal(err)
	}
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+pass))
	if gotRepo.Load() != want {
		t.Errorf("repository got %q", gotRepo.Load())
	}
	if gotOther.Load() != "got:" {
		t.Errorf("packagist got %q, want no credential", gotOther.Load())
	}
}

func TestScopeTokenOnlyToItsRegistry(t *testing.T) {
	tok := coretest.FakeKey(coretest.KeyNPM)
	var pub, priv atomic.Value
	public := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pub.Store("got:" + r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, `{}`)
	}), true)
	private := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		priv.Store(r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, `{}`)
	}), true)
	c := client(t, core.GetterConfig{
		ScopeTokens: map[string]string{"@acme": tok},
		Bases:       map[string]string{core.BaseNPM: public.URL, core.BaseNPMScope + "@acme": private.URL},
	}, public, private)
	var v any
	for _, u := range []string{public.URL + "/left-pad", private.URL + "/@acme%2fbilling"} {
		if err := c.JSON(context.Background(), u, &v, KindVersions); err != nil {
			t.Fatal(err)
		}
	}
	if priv.Load() != "Bearer "+tok {
		t.Errorf("scope registry got %q", priv.Load())
	}
	if pub.Load() != "got:" {
		t.Errorf("public registry got %q", pub.Load())
	}
}

// TestRedirectRefusals: SR-3 and SR-12. Each refused hop sends nothing.
func TestRedirectRefusals(t *testing.T) {
	trap := &counter{h: func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{}") }}
	unlisted := serve(t, trap, true)
	unlistedHTTP := serve(t, trap, false)
	cases := []struct {
		name, to string
		want     error
		reason   string
	}{
		{"plain http", "http://downloads.wordpress.org/plugin/x.zip", ErrInsecureScheme, "only https is allowed"},
		{"metadata service", "https://169.254.169.254/latest/meta-data/", ErrOffAllowlist, "not an allowed registry host"},
		{"metadata over http", "http://169.254.169.254/latest/meta-data/", ErrInsecureScheme, "only https is allowed"},
		{"unconfigured loopback port", unlisted.URL + "/x", ErrOffAllowlist, "not an allowed registry host"},
		{"unconfigured loopback http", unlistedHTTP.URL + "/x", ErrInsecureScheme, "only https is allowed"},
		{"other scheme", "ftp://downloads.wordpress.org/x", ErrInsecureScheme, "only https is allowed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, tc.to, http.StatusFound)
			}), true)
			c := client(t, core.GetterConfig{Bases: map[string]string{core.BaseNPM: srv.URL}}, srv)
			var v any
			err := c.JSON(context.Background(), srv.URL+"/pkg", &v, KindVersions)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err %v, want %v", err, tc.want)
			}
			if core.CodeOf(err) != core.ENetwork || !strings.Contains(err.Error(), tc.reason) {
				t.Errorf("err %q, want E7 saying %q", err, tc.reason)
			}
			_, err = c.Download(context.Background(), srv.URL+"/pkg.tgz", 1<<20, coretest.MemBlobs())
			if !errors.Is(err, tc.want) {
				t.Errorf("download err %v, want %v", err, tc.want)
			}
		})
	}
	if n := trap.count(); n != 0 {
		t.Errorf("unconfigured listeners got %d hits, want 0", n)
	}
}

func TestFirstHopRefused(t *testing.T) {
	c := client(t, core.GetterConfig{})
	var v any
	for raw, want := range map[string]error{
		"https://evil.example/x":                 ErrOffAllowlist,
		"http://api.wordpress.org/x":             ErrInsecureScheme,
		"https://169.254.169.254/":               ErrOffAllowlist,
		"https://api.wordpress.org.evil.example": ErrOffAllowlist,
		"https://api.wordpress.org:8443/x":       ErrOffAllowlist,
	} {
		if err := c.JSON(context.Background(), raw, &v, KindMeta); !errors.Is(err, want) {
			t.Errorf("%s: err %v, want %v", raw, err, want)
		}
		if _, _, err := c.Text(context.Background(), "PROPFIND", raw, nil, 1<<10); !errors.Is(err, want) {
			t.Errorf("%s: Text err %v, want %v", raw, err, want)
		}
	}
}

func TestLoopDialerRefusesOtherPorts(t *testing.T) {
	trap := &counter{}
	srv := serve(t, trap, false)
	addr := strings.TrimPrefix(srv.URL, "http://")
	d := loopDialer{allowed: map[string]bool{"127.0.0.1:1": true}}
	if _, err := d.DialContext(context.Background(), "tcp", addr); err == nil {
		t.Fatal("loopback dialer reached an unconfigured port")
	}
	if _, err := (&publicDialer{}).DialContext(context.Background(), "tcp", addr); err == nil {
		t.Fatal("public dialer reached a loopback address")
	}
	if trap.count() != 0 {
		t.Errorf("listener got %d hits", trap.count())
	}
}

func TestSelfSignedRefused(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{}") }), true)
	// No test roots: the system pool doesn't hold httptest's certificate.
	c, err := newClient(core.GetterConfig{Bases: map[string]string{core.BaseNPM: srv.URL}, Retries: -1}, testHooks{})
	if err != nil {
		t.Fatal(err)
	}
	var v any
	err = c.JSON(context.Background(), srv.URL+"/x", &v, KindMeta)
	want := "rhythm sightread: can't reach 127.0.0.1 (certificate not trusted)\n  check the connection or HTTPS_PROXY"
	if err == nil || err.Error() != want {
		t.Errorf("err\n%v\nwant\n%s", err, want)
	}
}

// TestSSLCertFile: the same server is trusted once its certificate is
// in SSL_CERT_FILE (T-14). Go reads the variable once per process, so a
// child process does the request.
func TestSSLCertFile(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a child process")
	}
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"ok":true}`) }), true)
	pemFile := filepath.Join(t.TempDir(), "ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(pemFile, data, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), "FETCH_TEST_SSL_CHILD=1", "FETCH_TEST_URL="+srv.URL, "SSL_CERT_FILE="+pemFile, "SSL_CERT_DIR=")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
}

func sslChild() int {
	base := os.Getenv("FETCH_TEST_URL")
	c, err := New(core.GetterConfig{Bases: map[string]string{core.BaseNPM: base}})
	if err != nil {
		fmt.Println(err)
		return 1
	}
	var v struct{ OK bool }
	if err := c.JSON(context.Background(), base+"/x", &v, KindMeta); err != nil || !v.OK {
		fmt.Println("with SSL_CERT_FILE:", err)
		return 1
	}
	return 0
}

func TestEndlessJSONStopsAtCap(t *testing.T) {
	srv := serve(t, http.HandlerFunc(endless), true)
	c := client(t, core.GetterConfig{Bases: map[string]string{core.BaseNPM: srv.URL}}, srv)
	c.jsonCap = 1 << 20
	var v any
	err := c.JSON(context.Background(), srv.URL+"/huge", &v, KindVersions)
	if !errors.Is(err, core.ErrTooLarge) || core.CodeOf(err) != core.ETooLarge {
		t.Fatalf("err %v, want E11", err)
	}
	if !strings.Contains(err.Error(), "the answer of 127.0.0.1 is over 1 MiB") {
		t.Errorf("err %q", err)
	}
}

func TestDownloadOverLimit(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	srv := serve(t, http.HandlerFunc(endless), true)
	c := client(t, core.GetterConfig{Bases: map[string]string{core.BaseNPM: srv.URL}}, srv)
	blobs := newRecordBlobs()
	_, err := c.Download(context.Background(), srv.URL+"/huge-pkg/-/huge-pkg-1.4.0.tgz", 1<<20, blobs)
	if !errors.Is(err, core.ErrTooLarge) {
		t.Fatalf("err %v, want ErrTooLarge", err)
	}
	if blobs.count() != 0 {
		t.Errorf("%d blobs stored, want none", blobs.count())
	}
	err = Package{Command: "npm", Name: "huge-pkg", Version: "1.4.0", Archive: "tarball"}.Wrap(err)
	want := "rhythm sightread npm: the 1.4.0 tarball of huge-pkg is over 1 MiB\n" +
		"  raise --max-size if you expect that; a size jump this big is worth a look on its own"
	if err.Error() != want {
		t.Errorf("err\n%s\nwant\n%s", err, want)
	}
	var ce *core.Error
	if !errors.As(err, &ce) || ce.ExitCode() != 3 || !errors.Is(err, core.ErrTooLarge) {
		t.Errorf("wrapped err %#v", err)
	}
}

func TestUnpackedTooLargeText(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	err := Package{Command: "npm", Name: "huge-pkg", Version: "1.4.0", Archive: "tarball"}.Wrap(TooLarge(1 << 30))
	want := "rhythm sightread npm: the 1.4.0 archive of huge-pkg unpacks to over 1 GiB\n" +
		"  raise --max-size if you expect that; a size jump this big is worth a look on its own"
	if err.Error() != want {
		t.Errorf("err\n%s\nwant\n%s", err, want)
	}
}

// slow sends one byte a second.
func slow(w http.ResponseWriter, r *http.Request) {
	f, _ := w.(http.Flusher)
	for r.Context().Err() == nil {
		if _, err := w.Write([]byte(" ")); err != nil {
			return
		}
		if f != nil {
			f.Flush()
		}
		select {
		case <-time.After(time.Second):
		case <-r.Context().Done():
		}
	}
}

func TestSlowBodyStopsAtTimeout(t *testing.T) {
	srv := serve(t, http.HandlerFunc(slow), true)
	c := client(t, core.GetterConfig{Timeout: 1500 * time.Millisecond, Retries: -1, Bases: map[string]string{core.BaseNPM: srv.URL}}, srv)
	start := time.Now()
	var v any
	err := c.JSON(context.Background(), srv.URL+"/slow", &v, KindVersions)
	if core.CodeOf(err) != core.ENetwork || !strings.Contains(err.Error(), "(timed out)") {
		t.Errorf("JSON err %v, want E7 timed out", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("JSON took %s", d)
	}

	// A download may stream for longer than one timeout but not stall
	// for one: one byte a second against a 500 ms idle limit stops.
	c = client(t, core.GetterConfig{Timeout: 500 * time.Millisecond, Retries: -1, Bases: map[string]string{core.BaseNPM: srv.URL}}, srv)
	start = time.Now()
	_, err = c.Download(context.Background(), srv.URL+"/slow.tgz", 1<<20, coretest.MemBlobs())
	if core.CodeOf(err) != core.ENetwork || !strings.Contains(err.Error(), "(timed out)") {
		t.Errorf("Download err %v, want E7 timed out", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Download took %s", d)
	}
}

func TestGitHubBudget(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	api := &counter{h: func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "60")
		w.Header().Set("X-RateLimit-Remaining", "0")
		_, _ = io.WriteString(w, `{}`)
	}}
	srv := serve(t, api, true)
	c := client(t, core.GetterConfig{Bases: map[string]string{core.BaseGitHubAPI: srv.URL}}, srv)
	c.ExpectGitHub(111)
	var v any
	if err := c.JSON(context.Background(), srv.URL+"/repos/o/r/git/ref/tags/v1", &v, KindMeta); err != nil {
		t.Fatal(err)
	}
	if limit, rem, known := c.GitHubBudget(); limit != 60 || rem != 0 || !known {
		t.Errorf("budget %d %d %v", limit, rem, known)
	}
	err := c.JSON(context.Background(), srv.URL+"/repos/o/r/git/ref/tags/v2", &v, KindMeta)
	want := "rhythm sightread: api.github.com allows 60 requests an hour without a token and this run needs about 111\n" +
		"  set GITHUB_TOKEN (sent only to api.github.com)"
	if err == nil || err.Error() != want {
		t.Errorf("err\n%v\nwant\n%s", err, want)
	}
	var b *ErrGitHubBudget
	if !errors.As(err, &b) || b.Limit != 60 || b.Needed != 111 {
		t.Errorf("budget error %#v", b)
	}
	if api.count() != 1 {
		t.Errorf("api got %d requests, want 1 (the second is refused before sending)", api.count())
	}
	full := GitHubLimitError("composer", 60, 111, 23, 111)
	wantFull := "rhythm sightread composer: api.github.com allows 60 requests an hour without a token and this run needs about 111\n" +
		"  set GITHUB_TOKEN (sent only to api.github.com); 23 of 111 packages were reviewed"
	if full.Error() != wantFull || full.ExitCode() != 3 {
		t.Errorf("full\n%s\nwant\n%s", full, wantFull)
	}
}

func TestGitHubBudget403(t *testing.T) {
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "60")
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
	}), true)
	c := client(t, core.GetterConfig{Bases: map[string]string{core.BaseGitHubAPI: srv.URL}}, srv)
	var v any
	if err := c.JSON(context.Background(), srv.URL+"/x", &v, KindMeta); core.CodeOf(err) != core.EGitHubLimit {
		t.Errorf("err %v, want E16", err)
	}
	// With a token the budget isn't Sightread's concern: a 403 is E10.
	c = client(t, core.GetterConfig{GitHubToken: coretest.FakeKey(coretest.KeyGitHub), Bases: map[string]string{core.BaseGitHubAPI: srv.URL}}, srv)
	if err := c.JSON(context.Background(), srv.URL+"/y", &v, KindMeta); core.CodeOf(err) != core.EAuth {
		t.Errorf("err %v, want E10", err)
	}
	if _, _, known := c.GitHubBudget(); known {
		t.Error("budget reported with a token")
	}
}

func TestGoldenErrors(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	// E7: a closed port in the range.
	l := listen(t)
	closed := "https://" + l.Addr().String()
	_ = l.Close()
	c := client(t, core.GetterConfig{Retries: -1, Bases: map[string]string{core.BaseNPM: closed}})
	var v any
	err := c.JSON(context.Background(), closed+"/left-pad", &v, KindVersions)
	want := "rhythm sightread: can't reach 127.0.0.1 (connection refused)\n  check the connection or HTTPS_PROXY"
	if err == nil || err.Error() != want {
		t.Errorf("E7\n%v\nwant\n%s", err, want)
	}

	// E9: still 429 after both retries.
	limited := serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}), true)
	c = client(t, core.GetterConfig{Bases: map[string]string{core.BaseWPOrgAPI: limited.URL}}, limited)
	err = c.JSON(context.Background(), limited.URL+"/x", &v, KindMeta)
	want = "rhythm sightread: 127.0.0.1 asked us to slow down (429) and still did after 2 retries\n" +
		"  run again in a few minutes or lower --jobs"
	if err == nil || err.Error() != want {
		t.Errorf("E9\n%v\nwant\n%s", err, want)
	}
	var rl *ErrRateLimited
	if !errors.As(err, &rl) || rl.Retries != 2 || rl.Status != 429 {
		t.Errorf("E9 cause %#v", rl)
	}

	// E10: a private Composer repository answers 401.
	private := serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}), true)
	c = client(t, core.GetterConfig{Bases: map[string]string{core.BaseComposerRepo + "0": private.URL}}, private)
	err = c.JSON(context.Background(), private.URL+"/p2/acme/billing.json", &v, KindVersions)
	err = Package{Command: "composer", Name: "acme/billing"}.Wrap(err)
	want = "rhythm sightread composer: 127.0.0.1 answered 401 for acme/billing\n" +
		"  set COMPOSER_AUTH (as Composer reads it); credentials go only to 127.0.0.1"
	if err.Error() != want {
		t.Errorf("E10\n%v\nwant\n%s", err, want)
	}
	var ae *ErrAuth
	if !errors.As(err, &ae) || ae.Status != 401 || StatusOf(err) != 401 {
		t.Errorf("E10 cause %#v", ae)
	}
}

func TestStatusError(t *testing.T) {
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "503") {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		http.NotFound(w, r)
	}), true)
	c := client(t, core.GetterConfig{Retries: -1, Bases: map[string]string{core.BaseWPOrgDownloads: srv.URL}}, srv)
	var v any
	err := c.JSON(context.Background(), srv.URL+"/plugin-checksums/x/404", &v, KindChecksums)
	var se *StatusError
	if !errors.As(err, &se) || se.Status != 404 || core.CodeOf(err) != "" {
		t.Errorf("err %v, want a plain 404 StatusError", err)
	}
	err = c.JSON(context.Background(), srv.URL+"/plugin-checksums/x/503", &v, KindChecksums)
	if StatusOf(err) != 503 {
		t.Errorf("err %v, want 503", err)
	}
}

func TestOffline(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	dir := t.TempDir()
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".zip") {
			_, _ = io.WriteString(w, "zip")
			return
		}
		_, _ = io.WriteString(w, `{"version":"5.3.5"}`)
	}), true)
	bases := map[string]string{core.BaseWPOrgAPI: srv.URL, core.BaseWPOrgDownloads: srv.URL}
	blobs := coretest.MemBlobs()
	on := client(t, core.GetterConfig{CacheDir: dir, Bases: bases}, srv)
	var v struct{ Version string }
	if err := on.JSON(context.Background(), srv.URL+"/info/akismet", &v, KindMeta); err != nil {
		t.Fatal(err)
	}
	got, err := on.Download(context.Background(), srv.URL+"/plugin/akismet.5.3.5.zip", 1<<20, blobs)
	if err != nil {
		t.Fatal(err)
	}
	srv.Close()

	off := client(t, core.GetterConfig{CacheDir: dir, Offline: true, Bases: bases}, srv)
	v.Version = ""
	if err := off.JSON(context.Background(), srv.URL+"/info/akismet", &v, KindMeta); err != nil || v.Version != "5.3.5" {
		t.Errorf("offline cached JSON: %v %q", err, v.Version)
	}
	d, err := off.Download(context.Background(), srv.URL+"/plugin/akismet.5.3.5.zip", 1<<20, blobs)
	if err != nil || d != got {
		t.Errorf("offline cached download: %v %+v", err, d)
	}
	err = off.JSON(context.Background(), srv.URL+"/info/hello-dolly", &v, KindMeta)
	want := "rhythm sightread: can't reach 127.0.0.1 (offline and not cached)\n" +
		"  with --offline only cached data and archives are used; run once without it to fill the cache"
	if err == nil || err.Error() != want {
		t.Errorf("offline JSON\n%v\nwant\n%s", err, want)
	}
	_, err = off.Download(context.Background(), srv.URL+"/plugin/hello-dolly.1.7.2.zip", 1<<20, blobs)
	want = "rhythm sightread: can't reach 127.0.0.1 (offline and hello-dolly.1.7.2.zip isn't cached)\n" +
		"  with --offline only cached data and archives are used; run once without it to fill the cache"
	if err == nil || err.Error() != want {
		t.Errorf("offline download\n%v\nwant\n%s", err, want)
	}
	// An index entry whose blob is gone is not a cached archive.
	_, err = off.Download(context.Background(), srv.URL+"/plugin/akismet.5.3.5.zip", 1<<20, coretest.MemBlobs())
	if core.CodeOf(err) != core.ENetwork {
		t.Errorf("offline download without the blob: %v", err)
	}
	if _, _, err := off.Text(context.Background(), "PROPFIND", srv.URL+"/x", nil, 10); core.CodeOf(err) != core.ENetwork {
		t.Errorf("offline Text: %v", err)
	}
}

func TestText(t *testing.T) {
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("X-Method", r.Method)
		w.WriteHeader(http.StatusMultiStatus)
		_, _ = w.Write(body)
	}), true)
	c := client(t, core.GetterConfig{Bases: map[string]string{core.BaseWPOrgSVN: srv.URL}}, srv)
	out, h, err := c.Text(context.Background(), "PROPFIND", srv.URL+"/akismet/tags/5.3.5/", strings.NewReader("<propfind/>"), 1<<10)
	if err != nil || string(out) != "<propfind/>" || h.Get("X-Method") != "PROPFIND" {
		t.Errorf("Text: %v %q %v", err, out, h)
	}
	_, _, err = c.Text(context.Background(), http.MethodPost, srv.URL+"/x", strings.NewReader(strings.Repeat("a", 100)), 10)
	if !errors.Is(err, core.ErrTooLarge) {
		t.Errorf("over limit: %v", err)
	}
}

func TestPerHostConcurrency(t *testing.T) {
	var cur, peak atomic.Int32
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := cur.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
		cur.Add(-1)
		_, _ = io.WriteString(w, "x")
	}), true)
	c := client(t, core.GetterConfig{PerHost: 2, Bases: map[string]string{core.BaseNPM: srv.URL}}, srv)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Download(context.Background(), fmt.Sprintf("%s/p/%d.tgz", srv.URL, i), 10, coretest.MemBlobs()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if p := peak.Load(); p > 2 || p == 0 {
		t.Errorf("peak concurrency %d, want 1 or 2", p)
	}
}

func TestDebugLogMasksCredentials(t *testing.T) {
	tok := coretest.FakeKey(coretest.KeyGitHub)
	srv := serve(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "{}") }), true)
	var log strings.Builder
	var mu sync.Mutex
	c := client(t, core.GetterConfig{GitHubToken: tok, Debug: writerFunc(func(p []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return log.Write(p)
	}), Bases: map[string]string{core.BaseGitHubAPI: srv.URL}}, srv)
	var v any
	if err := c.JSON(context.Background(), srv.URL+"/repos/o/r?access_token="+tok, &v, KindMeta); err != nil {
		t.Fatal(err)
	}
	_ = c.JSON(context.Background(), "https://evil.example/?t="+tok, &v, KindMeta)
	mu.Lock()
	defer mu.Unlock()
	if strings.Contains(log.String(), tok) {
		t.Errorf("debug log holds the token:\n%s", log.String())
	}
	if !strings.Contains(log.String(), "> GET https://127.0.0.1") || !strings.Contains(log.String(), "! refused https://evil.example") {
		t.Errorf("debug log:\n%s", log.String())
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestBadConfig(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	cases := []struct {
		cfg  core.GetterConfig
		want string
	}{
		{core.GetterConfig{Bases: map[string]string{core.BaseNPM: "http://mirror.example"}},
			"rhythm sightread: SIGHTREAD_NPM_REGISTRY \"http://mirror.example\" must use https\n  plain http is allowed only for a mirror on 127.0.0.1, ::1 or localhost"},
		{core.GetterConfig{Bases: map[string]string{core.BaseNPMScope + "@acme": "ftp://x"}},
			"rhythm sightread: the registry of @acme \"ftp://x\" must use https\n  plain http is allowed only for a mirror on 127.0.0.1, ::1 or localhost"},
		{core.GetterConfig{Bases: map[string]string{core.BaseOSV: "https://u:p@osv.example"}},
			"rhythm sightread: SIGHTREAD_OSV_API \"https://u:p@osv.example\" is not a base URL\n  give one like https://mirror.example.com/npm"},
		{core.GetterConfig{ComposerAuth: "{not json"},
			"rhythm sightread: COMPOSER_AUTH is not valid JSON\n  give it in the form Composer reads, e.g. {\"http-basic\": {\"repo.example.com\": {\"username\": \"u\", \"password\": \"p\"}}}"},
		{core.GetterConfig{Hosts: []string{"127.0.0.1:8080"}},
			"rhythm sightread: allowed host \"127.0.0.1:8080\" is a loopback address\n  name a loopback mirror by its base URL (SIGHTREAD_* variables) instead"},
		{core.GetterConfig{Hosts: []string{"https://x.example/"}},
			"rhythm sightread: allowed host \"https://x.example/\" is not a host name\n  give a bare host such as repo.example.com"},
	}
	for _, tc := range cases {
		_, err := New(tc.cfg)
		if err == nil || err.Error() != tc.want || core.CodeOf(err) != core.EBadConfig {
			t.Errorf("err\n%v\nwant\n%s", err, tc.want)
		}
	}
}

func TestExtraHosts(t *testing.T) {
	a, err := newAllowlist(core.GetterConfig{Hosts: []string{"github.com", "objects.githubusercontent.com"}})
	if err != nil {
		t.Fatal(err)
	}
	for raw, ok := range map[string]bool{
		"https://github.com/x":                           true,
		"https://GITHUB.COM./x":                          true,
		"https://objects.githubusercontent.com/x":        true,
		"https://release-assets.githubusercontent.com/x": false,
		"https://github.com:444/x":                       false,
	} {
		u, _ := url.Parse(raw)
		if got := a.check(u) == nil; got != ok {
			t.Errorf("%s allowed %v, want %v", raw, got, ok)
		}
	}
	// Review runs never reach github.com.
	def, _ := newAllowlist(core.GetterConfig{})
	if u, _ := url.Parse("https://github.com/x"); def.check(u) == nil {
		t.Error("github.com allowed by default")
	}
}

func TestEnvConfig(t *testing.T) {
	tok := coretest.FakeKey(coretest.KeyGitHub)
	npmTok := coretest.FakeKey(coretest.KeyNPM)
	env := map[string]string{
		"SIGHTREAD_NPM_REGISTRY":   "http://127.0.0.1:31010/",
		"RHYTHM_GITHUB_TOKEN":      tok,
		"SIGHTREAD_NPM_TOKEN_ACME": npmTok,
		"COMPOSER_AUTH":            "{}",
	}
	cfg := EnvConfig(func(k string) string { return env[k] }, []string{"@acme", "@other"})
	if cfg.Bases[core.BaseNPM] != "http://127.0.0.1:31010" || cfg.Bases[core.BaseWPOrgAPI] != "https://api.wordpress.org" {
		t.Errorf("bases %v", cfg.Bases)
	}
	if cfg.GitHubToken != tok || cfg.ScopeTokens["@acme"] != npmTok || len(cfg.ScopeTokens) != 1 || cfg.ComposerAuth != "{}" {
		t.Errorf("credentials not read: %+v", cfg)
	}
	if got := ScopeTokenEnv("@my-co.x"); got != "SIGHTREAD_NPM_TOKEN_MY_CO_X" {
		t.Errorf("ScopeTokenEnv %q", got)
	}
	if got := UserAgent("1.0.0"); got != "rhythm-sightread/1.0.0 (+https://github.com/RhythmShahriar/sightread)" {
		t.Errorf("UserAgent %q", got)
	}
	for k := range DefaultBases() {
		if BaseEnv(k) == "" {
			t.Errorf("base %s has no variable", k)
		}
	}
}

func TestSize(t *testing.T) {
	for n, want := range map[int64]string{256 << 20: "256 MiB", 1 << 30: "1 GiB", 2048: "2 KiB", 1000: "1000 bytes", 3<<20 + 1: "3145729 bytes"} {
		if got := Size(n); got != want {
			t.Errorf("Size(%d) = %q, want %q", n, got, want)
		}
	}
}

func TestUnknownKind(t *testing.T) {
	c := client(t, core.GetterConfig{})
	var v any
	if err := c.JSON(context.Background(), "https://api.wordpress.org/x", &v, "nope"); err == nil {
		t.Error("unknown kind accepted")
	}
	if _, ok := TTL(KindChecksums); !ok {
		t.Error("checksums has no TTL")
	}
}
