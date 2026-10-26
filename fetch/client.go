// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package fetch

import (
	"context"
	"crypto/sha1" //nolint:gosec // Packagist publishes dist.shasum as SHA-1; it is compared, not trusted alone
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cache"
	"github.com/RhythmShahriar/rhythm/kit/httpx"
	"github.com/RhythmShahriar/rhythm/kit/secrets"
	"github.com/RhythmShahriar/rhythm/kit/term"

	"github.com/RhythmShahriar/sightread/core"
)

func init() {
	core.SetGetter(func(cfg core.GetterConfig) (core.Getter, error) { return New(cfg) })
}

// npmAbbreviated is the Accept value of npm's abbreviated packument.
const npmAbbreviated = "application/vnd.npm.install-v1+json; q=1.0, application/json; q=0.8"

// Client is Sightread's core.Getter. Every request and every redirect
// hop must be https to an allowlisted host (or a configured loopback
// mirror), credentials are attached per hop to their own host only,
// bodies are capped while they stream and JSON goes through the kit
// cache. Build one per run with New and share it.
type Client struct {
	api      *http.Client // JSON and Text: Timeout covers the whole request
	dl       *http.Client // downloads: see Download for the timeouts
	timeout  time.Duration
	retries  int
	allow    *allowlist
	creds    *credentials
	stores   map[string]*cache.Store
	index    *cache.Store // url to downloaded blob, read offline
	indexW   *cache.Store // the same folder, for writing
	offline  bool
	jsonCap  int64
	debug    io.Writer
	npmAddrs map[string]bool
	gh       *ghBudget
}

// New builds the run's Getter from cfg. A base or host that may not be
// used is an E12 *core.Error.
func New(cfg core.GetterConfig) (*Client, error) { return newClient(cfg, testHooks{}) }

// testHooks let tests trust their httptest certificate and check that
// no request leaves loopback. Both are zero outside tests.
type testHooks struct {
	roots *x509.CertPool
	wrap  func(http.RoundTripper) http.RoundTripper
}

// newClient is New with test hooks.
func newClient(cfg core.GetterConfig, hooks testHooks) (*Client, error) {
	bases := DefaultBases()
	for k, v := range cfg.Bases {
		bases[k] = strings.TrimRight(strings.TrimSpace(v), "/")
	}
	cfg.Bases = bases
	a, err := newAllowlist(cfg)
	if err != nil {
		return nil, err
	}
	creds, hasGitHub, err := newCredentials(cfg, a)
	if err != nil {
		return nil, err
	}
	pt, lt, err := newTransports(a, cfg.Proxy, hooks.roots)
	if err != nil {
		return nil, err
	}
	var public, loop http.RoundTripper = pt, lt
	if hooks.wrap != nil {
		public, loop = hooks.wrap(pt), hooks.wrap(lt)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	retries := cfg.Retries
	switch {
	case retries == 0:
		retries = DefaultRetries
	case retries < 0:
		retries = 0
	}
	perHost := cfg.PerHost
	if perHost <= 0 {
		perHost = DefaultPerHost
	}
	ua := cfg.UserAgent
	if ua == "" {
		ua = UserAgent("")
	}
	c := &Client{
		timeout: timeout, retries: retries, allow: a, creds: creds,
		offline: cfg.Offline, jsonCap: MaxJSON, debug: cfg.Debug,
		npmAddrs: map[string]bool{},
		gh:       &ghBudget{anon: !hasGitHub, addrs: map[string]bool{githubAPI: true}},
	}
	for k, v := range bases {
		u, err := url.Parse(v)
		if err != nil {
			continue
		}
		if k == core.BaseNPM || strings.HasPrefix(k, core.BaseNPMScope) {
			c.npmAddrs[canonical(u)] = true
		}
		if k == core.BaseGitHubAPI {
			c.gh.addrs[canonical(u)] = true
		}
	}
	rt := &router{public: public, loop: loop, allow: a, creds: creds, sem: newHostSem(perHost), gh: c.gh}
	hc := httpx.New(httpx.Options{
		UserAgent:        ua,
		Timeout:          timeout,
		MaxBody:          -1, // capped here while streaming (G2)
		OffSiteRedirects: true,
		Retries:          retries,
		Debug:            cfg.Debug,
		Transport:        rt,
	})
	next := hc.CheckRedirect
	hc.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := a.check(req.URL); err != nil {
			c.logRefused(req.URL, err)
			return err
		}
		if next != nil {
			return next(req, via)
		}
		return nil
	}
	c.api = hc
	dl := *hc
	dl.Timeout = 0
	c.dl = &dl
	c.stores = map[string]*cache.Store{}
	dir := ""
	if cfg.CacheDir != "" {
		dir = filepath.Join(cfg.CacheDir, "meta")
	}
	for kind, ttl := range ttls {
		c.stores[kind] = &cache.Store{Dir: dir, TTL: ttl, Offline: cfg.Offline}
	}
	c.index = &cache.Store{Dir: dir, TTL: forever, Offline: true}
	c.indexW = &cache.Store{Dir: dir, TTL: forever, Force: true}
	return c, nil
}

// ExpectGitHub tells the client how many api.github.com requests the run
// is about to make. Once GitHub has said what is left, an anonymous run
// whose plan would exceed it is refused before the next request, and a
// run that runs out says how many it needed (E16).
func (c *Client) ExpectGitHub(n int) { c.gh.expect(n) }

// GitHubBudget returns GitHub's hourly allowance and what is left of it
// as the last api.github.com answer said; false before any answer or
// when a token is set (the budget is then not Sightread's concern).
func (c *Client) GitHubBudget() (limit, remaining int, known bool) { return c.gh.state() }

// JSON fetches url and decodes it into v, reusing a cached answer of
// kind while it is fresh. Offline, only the cache is read.
func (c *Client) JSON(ctx context.Context, rawURL string, v any, kind string) error {
	u, err := c.parse(rawURL)
	if err != nil {
		return err
	}
	store, ok := c.stores[kind]
	if !ok {
		return fmt.Errorf("fetch: unknown cache kind %q", kind)
	}
	raw, _, err := cache.Load(store, ctx, kind, u.String(), func(ctx context.Context) (json.RawMessage, error) {
		return c.getJSON(ctx, u, kind)
	})
	if errors.Is(err, cache.ErrOffline) {
		return networkError(u.Hostname(), "offline and not cached", hintOffline, err)
	}
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, v); err != nil {
		return fmt.Errorf("decode the answer of %s: %w", u.Hostname(), err)
	}
	return nil
}

// getJSON is one JSON request, capped at jsonCap.
func (c *Client) getJSON(ctx context.Context, u *url.URL, kind string) (json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil) //nolint:gosec // u passed the allowlist in parse
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	if kind == KindVersions && c.npmAddrs[canonical(u)] {
		req.Header.Set("Accept", npmAbbreviated)
	}
	resp, err := c.do(c.api, req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, c.jsonCap+1))
	if err != nil {
		return nil, c.netError(ctx, u, err)
	}
	if int64(len(body)) > c.jsonCap {
		return nil, tooLargeError("the answer of "+u.Hostname(), &SizeError{Limit: c.jsonCap})
	}
	if !json.Valid(body) {
		return nil, fmt.Errorf("%s did not answer with JSON", u.Hostname())
	}
	return body, nil
}

// Text sends one request that is not a GET of JSON or an archive (SVN
// PROPFIND, the OSV batch POST) and returns up to limit bytes of a 2xx
// answer. Offline it fails with E7.
func (c *Client) Text(ctx context.Context, method, rawURL string, body io.Reader, limit int64) ([]byte, http.Header, error) {
	u, err := c.parse(rawURL)
	if err != nil {
		return nil, nil, err
	}
	if c.offline {
		return nil, nil, networkError(u.Hostname(), "offline", hintOffline, cache.ErrOffline)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return nil, nil, err
	}
	if method == http.MethodPost && body != nil {
		// The one POST Sightread sends is the OSV batch query.
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.do(c.api, req)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, nil, c.netError(ctx, u, err)
	}
	if int64(len(out)) > limit {
		return nil, nil, tooLargeError("the answer of "+u.Hostname(), &SizeError{Limit: limit})
	}
	return out, resp.Header, nil
}

// indexEntry is what the download index keeps per URL.
type indexEntry struct {
	SHA256 [32]byte `json:"sha256"`
	SHA512 [64]byte `json:"sha512"`
	SHA1   [20]byte `json:"sha1"`
	Size   int64    `json:"size"`
}

// Download streams url into blobs, hashing it three ways. It stops at
// limit with an E11 *core.Error that leaves nothing stored. The whole
// download may take downloadSpan request timeouts; a stall of one
// timeout without a byte ends it sooner. Offline, only an archive this
// cache downloaded before is returned; any other is E7 naming it.
func (c *Client) Download(ctx context.Context, rawURL string, limit int64, blobs core.BlobStore) (core.Download, error) {
	u, err := c.parse(rawURL)
	if err != nil {
		return core.Download{}, err
	}
	if c.offline {
		return c.cachedDownload(ctx, u, blobs)
	}
	ctx, cancel := context.WithTimeout(ctx, downloadSpan*c.timeout)
	defer cancel()
	idle := newIdle(c.timeout, cancel)
	defer idle.stop()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return core.Download{}, err
	}
	resp, err := c.do(c.dl, req)
	if err != nil {
		return core.Download{}, idle.explain(u, err)
	}
	defer func() { _ = resp.Body.Close() }()
	h256, h512, h1 := sha256.New(), sha512.New(), sha1.New() //nolint:gosec // see the import
	src := &idleReader{r: resp.Body, i: idle}
	sum, n, err := blobs.Put(ctx, io.TeeReader(src, io.MultiWriter(h256, h512, h1)), limit)
	switch {
	case errors.Is(err, core.ErrTooLarge):
		return core.Download{}, tooLargeError(archiveName(u), &SizeError{Limit: limit})
	case err != nil && (src.err != nil || ctx.Err() != nil):
		// The body failed, not the store: a network error.
		return core.Download{}, idle.explain(u, c.netError(ctx, u, err))
	case err != nil:
		return core.Download{}, fmt.Errorf("store %s: %w", archiveName(u), err)
	}
	d := core.Download{Size: n}
	copy(d.SHA256[:], h256.Sum(nil))
	copy(d.SHA512[:], h512.Sum(nil))
	copy(d.SHA1[:], h1.Sum(nil))
	if d.SHA256 != sum {
		return core.Download{}, fmt.Errorf("blob store hashed %s differently from the download", archiveName(u))
	}
	d.Path, _ = blobs.Path(sum)
	entry := indexEntry{SHA256: d.SHA256, SHA512: d.SHA512, SHA1: d.SHA1, Size: n}
	_, _, _ = cache.Load(c.indexW, ctx, kindDownloads, u.String(), func(context.Context) (indexEntry, error) { return entry, nil })
	return d, nil
}

// cachedDownload answers Download offline from the index.
func (c *Client) cachedDownload(ctx context.Context, u *url.URL, blobs core.BlobStore) (core.Download, error) {
	e, _, err := cache.Load(c.index, ctx, kindDownloads, u.String(), func(context.Context) (indexEntry, error) {
		return indexEntry{}, cache.ErrOffline
	})
	if err != nil || !blobs.Has(e.SHA256) {
		if err == nil {
			err = cache.ErrOffline
		}
		return core.Download{}, networkError(u.Hostname(), "offline and "+archiveName(u)+" isn't cached", hintOffline, err)
	}
	d := core.Download{SHA256: e.SHA256, SHA512: e.SHA512, SHA1: e.SHA1, Size: e.Size}
	d.Path, _ = blobs.Path(e.SHA256)
	return d, nil
}

// archiveName is the last segment of u's path, how messages name an
// archive without printing its URL.
func archiveName(u *url.URL) string {
	name := term.Sanitize(path.Base(u.Path))
	if name == "" || name == "/" || name == "." {
		return "the archive from " + u.Hostname()
	}
	return name
}

// parse parses a URL and checks it against the allowlist, so a refused
// first hop sends nothing.
func (c *Client) parse(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("fetch: %q is not a URL", term.Sanitize(secrets.Redact(rawURL)))
	}
	if err := c.allow.check(u); err != nil {
		c.logRefused(u, err)
		var r *refusal
		errors.As(err, &r)
		return nil, refusedError(r)
	}
	return u, nil
}

// do sends req and turns every failure into the typed errors of the
// package. The caller closes the body of a 2xx answer.
func (c *Client) do(hc *http.Client, req *http.Request) (*http.Response, error) {
	if err := c.gh.before(canonical(req.URL)); err != nil {
		return nil, budgetError(err)
	}
	resp, err := hc.Do(req) //nolint:gosec // every hop is checked against the allowlist (parse, CheckRedirect, router)
	if err != nil {
		return nil, c.netError(req.Context(), req.URL, err)
	}
	if resp.StatusCode/100 == 2 {
		return resp, nil
	}
	// A registry may explain a refusal in a short JSON body (WordPress.org
	// answers 404 with {"error": "closed", ...}); keep that much for the
	// source and drain the rest of the first 4 KiB so the connection can
	// be reused.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodyCap))
	_, _ = io.CopyN(io.Discard, resp.Body, 4<<10)
	_ = resp.Body.Close()
	err = c.statusError(resp)
	var se *StatusError
	if errors.As(err, &se) && json.Valid(body) {
		se.Body = body
	}
	return nil, err
}

// errorBodyCap is how much of a non-2xx answer StatusError keeps.
const errorBodyCap = 4 << 10

// statusError maps a non-2xx answer.
func (c *Client) statusError(resp *http.Response) error {
	u := resp.Request.URL
	addr := canonical(u)
	host := u.Hostname()
	if c.gh.exhausted(addr, resp) {
		return budgetError(c.gh.budgetErr())
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden, http.StatusProxyAuthRequired:
		return authError(&ErrAuth{Host: host, Status: resp.StatusCode}, c.creds.authHint(addr))
	case http.StatusTooManyRequests:
		return rateLimitError(&ErrRateLimited{Host: host, Status: resp.StatusCode, Retries: c.retries})
	}
	return &StatusError{Host: host, Status: resp.StatusCode}
}

// netError maps a transport failure to E7, keeping cancellation as is.
func (c *Client) netError(ctx context.Context, u *url.URL, err error) error {
	var ce *core.Error
	if errors.As(err, &ce) {
		return err
	}
	if ctx.Err() != nil && errors.Is(err, context.Canceled) {
		return ctx.Err()
	}
	var r *refusal
	if errors.As(err, &r) {
		return refusedError(r)
	}
	return networkError(u.Hostname(), reason(err), hintNetwork, err)
}

// reason is the short cause of a network failure, as PRD 10 prints it.
func reason(err error) string {
	var dns *net.DNSError
	var unknown x509.UnknownAuthorityError
	var verify *tls.CertificateVerificationError
	var host x509.HostnameError
	switch {
	case errors.As(err, &dns) && dns.IsNotFound:
		return "no such host"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "connection refused"
	case errors.Is(err, httpx.ErrPrivate):
		return "refused: not a public address"
	case errors.As(err, &unknown), errors.As(err, &host), errors.As(err, &verify):
		return "certificate not trusted"
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded), isTimeout(err):
		return "timed out"
	case errors.Is(err, io.ErrUnexpectedEOF), errors.Is(err, syscall.ECONNRESET):
		return "connection dropped"
	}
	return "network error"
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// logRefused writes a refused hop to the -v log, URL masked.
func (c *Client) logRefused(u *url.URL, err error) {
	if c.debug == nil {
		return
	}
	fmt.Fprintf(c.debug, "! refused %s: %s\n", term.Sanitize(secrets.Redact(u.Redacted())), term.Sanitize(err.Error()))
}

// router is the transport under the kit client. It sees every hop and
// retry: it checks the allowlist again, puts this hop's credential on
// (and only this hop's), holds the per-host slot until the body is
// closed and reads GitHub's rate limit headers.
type router struct {
	public, loop http.RoundTripper
	allow        *allowlist
	creds        *credentials
	sem          *hostSem
	gh           *ghBudget
}

func (r *router) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := r.allow.check(req.URL); err != nil {
		return nil, err
	}
	addr := canonical(req.URL)
	req = req.Clone(req.Context())
	// Go copies headers onto redirect hops and keeps Authorization when
	// only the port changes, so every hop starts without one.
	req.Header.Del("Authorization")
	if v := r.creds.header(addr); v != "" {
		req.Header.Set("Authorization", v)
	}
	release, err := r.sem.acquire(req.Context(), addr)
	if err != nil {
		return nil, err
	}
	tr := r.public
	if r.allow.loop[addr] {
		tr = r.loop
	}
	r.gh.sent(addr)
	resp, err := tr.RoundTrip(req)
	if err != nil {
		release()
		return nil, err
	}
	r.gh.observe(addr, resp)
	resp.Body = &releaseBody{ReadCloser: resp.Body, release: release}
	return resp, nil
}

// releaseBody frees the host slot when the body is closed.
type releaseBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (b *releaseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.release)
	return err
}

// hostSem limits concurrent requests per host:port.
type hostSem struct {
	n  int
	mu sync.Mutex
	m  map[string]chan struct{}
}

func newHostSem(n int) *hostSem { return &hostSem{n: n, m: map[string]chan struct{}{}} }

func (s *hostSem) acquire(ctx context.Context, addr string) (func(), error) {
	s.mu.Lock()
	ch, ok := s.m[addr]
	if !ok {
		ch = make(chan struct{}, s.n)
		s.m[addr] = ch
	}
	s.mu.Unlock()
	select {
	case ch <- struct{}{}:
		return func() { <-ch }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ghBudget follows GitHub's anonymous allowance from the X-RateLimit
// headers of api.github.com answers.
type ghBudget struct {
	anon  bool
	addrs map[string]bool // api.github.com and a loopback github_api mirror

	mu               sync.Mutex
	known            bool
	limit, remaining int
	used, planned    int
}

func (g *ghBudget) expect(n int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.planned = n
}

func (g *ghBudget) state() (int, int, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.limit, g.remaining, g.anon && g.known
}

// before refuses an anonymous request GitHub would refuse anyway, and
// one of a run whose remaining plan (ExpectGitHub less what it sent) is
// more than GitHub has left: that run would stop part way, having spent
// the hour's allowance for nothing.
func (g *ghBudget) before(addr string) *ErrGitHubBudget {
	if !g.anon || !g.addrs[addr] {
		return nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.known && (g.remaining <= 0 || g.planned > 0 && g.planned-g.used > g.remaining) {
		return g.errLocked()
	}
	return nil
}

func (g *ghBudget) sent(addr string) {
	if !g.addrs[addr] {
		return
	}
	g.mu.Lock()
	g.used++
	g.mu.Unlock()
}

func (g *ghBudget) observe(addr string, resp *http.Response) {
	if !g.addrs[addr] {
		return
	}
	lim, err1 := strconv.Atoi(resp.Header.Get("X-RateLimit-Limit"))
	rem, err2 := strconv.Atoi(resp.Header.Get("X-RateLimit-Remaining"))
	if err2 != nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.known, g.remaining = true, rem
	if err1 == nil {
		g.limit = lim
	}
}

// exhausted reports whether resp is GitHub refusing an anonymous run
// for its allowance (403 or 429 with nothing remaining).
func (g *ghBudget) exhausted(addr string, resp *http.Response) bool {
	if !g.anon || !g.addrs[addr] {
		return false
	}
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusTooManyRequests {
		return false
	}
	return resp.Header.Get("X-RateLimit-Remaining") == "0"
}

func (g *ghBudget) budgetErr() *ErrGitHubBudget {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.errLocked()
}

func (g *ghBudget) errLocked() *ErrGitHubBudget {
	limit := g.limit
	if limit <= 0 {
		limit = 60 // GitHub's documented anonymous allowance
	}
	return &ErrGitHubBudget{Limit: limit, Needed: max(g.planned, g.used+1)}
}

// idle ends a download that sends no byte for d.
type idle struct {
	d     time.Duration
	t     *time.Timer
	fired atomic.Bool
}

func newIdle(d time.Duration, cancel context.CancelFunc) *idle {
	i := &idle{d: d}
	i.t = time.AfterFunc(d, func() {
		i.fired.Store(true)
		cancel()
	})
	return i
}

func (i *idle) stop() { i.t.Stop() }

// explain turns the cancellation an idle stop causes into E7 "timed out".
func (i *idle) explain(u *url.URL, err error) error {
	if i.fired.Load() && errors.Is(err, context.Canceled) {
		return networkError(u.Hostname(), "timed out", hintNetwork, err)
	}
	return err
}

// idleReader resets the idle timer on every byte and keeps the first
// read error, so Download can tell a failed body from a failed store.
type idleReader struct {
	r   io.Reader
	i   *idle
	err error
}

func (r *idleReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.i.t.Reset(r.i.d)
	}
	if err != nil && err != io.EOF && r.err == nil { //nolint:errorlint // Read returns io.EOF itself, never wrapped
		r.err = err
	}
	return n, err
}
