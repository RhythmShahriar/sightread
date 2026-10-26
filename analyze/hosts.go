// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/lex/js"
	"github.com/RhythmShahriar/sightread/lex/php"
)

// URL, host and domain extraction. Hosts are found in text only: no
// host is ever resolved or contacted (this package imports no network
// code; internal/exectest checks it). A domain is keyed by its eTLD+1
// from the public suffix list, so www.example.com and api.example.com
// are one domain.

// maxURLPath is the most bytes of a URL's path a key keeps.
const maxURLPath = 120

// maxBare is the longest literal read as a bare host.
const maxBare = 256

// hostRef is one URL or host found in text.
type hostRef struct {
	raw  string // the host as written
	off  int    // byte offset of the match in the text
	host string // normalised: lower case, punycode, no port, no trailing dot
	url  string // scheme://host/path for a URL, "" for a bare host
	key  string // eTLD+1, or the IP for an address
	ip   bool
}

// allowedSchemes are the URL schemes extracted.
var allowedSchemes = map[string]bool{"http": true, "https": true, "ftp": true, "ftps": true, "ws": true, "wss": true, "sftp": true}

// bareTLDs are the public suffixes a bare literal ("evil.example.ru")
// may end in to count as a host. Suffixes that are also common file
// extensions or JavaScript property names (.md, .py, .sh, .js, .name,
// .info, .id, .in) are left out: "readme.md" is a file, "user.name" a
// path. Multi-label suffixes (co.uk) always count.
var bareTLDs = map[string]bool{
	"com": true, "net": true, "org": true, "io": true, "co": true, "biz": true, "xyz": true, "top": true,
	"online": true, "site": true, "club": true, "live": true, "app": true, "dev": true, "cloud": true,
	"tech": true, "store": true, "shop": true, "pro": true, "ru": true, "su": true, "cn": true,
	"tk": true, "ga": true, "cf": true, "gq": true, "pw": true, "ws": true, "ly": true, "de": true,
	"fr": true, "nl": true, "uk": true, "jp": true, "br": true, "ir": true, "ua": true, "by": true,
	"kz": true, "eu": true, "vn": true, "kr": true, "es": true, "ca": true, "us": true, "icu": true,
	"buzz": true, "cyou": true, "rest": true, "fun": true, "space": true, "website": true, "host": true,
}

// reservedTLDs never name a real host (RFC 2606, RFC 6761 and friends).
var reservedTLDs = map[string]bool{
	"localhost": true, "local": true, "test": true, "example": true, "invalid": true, "internal": true,
	"lan": true, "home": true, "corp": true, "localdomain": true,
}

// exampleDomains are documentation domains (RFC 2606).
var exampleDomains = map[string]bool{"example.com": true, "example.net": true, "example.org": true}

// normHost normalises a host as written. It reports false for text
// that is not a public host: a reserved name, loopback, an unknown top
// level domain or invalid labels.
func normHost(raw string) (string, string, bool, bool) {
	h := strings.TrimSuffix(raw, ".")
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		a, err := netip.ParseAddr(h[1 : len(h)-1])
		if err != nil || !a.Is6() || a.Zone() != "" || !publicAddr(a) {
			return "", "", false, false // a zone only names a local link
		}
		s := a.String()
		return s, s, true, true
	}
	if a, err := netip.ParseAddr(h); err == nil {
		if !a.Is4() || !publicAddr(a) {
			return "", "", false, false
		}
		s := a.String()
		return s, s, true, true
	}
	if h == "" || len(h) > 253 {
		return "", "", false, false
	}
	ascii, err := idna.Lookup.ToASCII(strings.ToLower(h))
	if err != nil || ascii == "" {
		return "", "", false, false
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", "", false, false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return "", "", false, false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return "", "", false, false
			}
		}
	}
	tld := labels[len(labels)-1]
	if reservedTLDs[tld] || strings.Trim(tld, "0123456789") == "" {
		return "", "", false, false
	}
	ps, icann := publicsuffix.PublicSuffix(ascii)
	if !icann && !strings.Contains(ps, ".") {
		return "", "", false, false // no such top level domain
	}
	key, err := publicsuffix.EffectiveTLDPlusOne(ascii)
	if err != nil || exampleDomains[key] {
		return "", "", false, false
	}
	return ascii, key, false, true
}

// publicAddr reports whether an address could be a host on the
// internet or a network: not loopback, unspecified, multicast or link
// local.
func publicAddr(a netip.Addr) bool {
	return !a.IsLoopback() && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLinkLocalUnicast() &&
		!a.IsLinkLocalMulticast() && !a.IsInterfaceLocalMulticast()
}

// stopsAuthority are the bytes that end a URL's host part.
func stopsAuthority(c byte) bool {
	return c <= ' ' || c == 0x7f || strings.IndexByte("/?#\\\"'<>`()[]{}|^,;", c) >= 0
}

// stopsPath are the bytes that end a URL in text.
func stopsPath(c byte) bool {
	return c <= ' ' || c == 0x7f || strings.IndexByte("\\\"'<>`{}|^)]", c) >= 0
}

func schemeChar(c byte) bool {
	return ('a' <= c|0x20 && c|0x20 <= 'z') || ('0' <= c && c <= '9') || c == '+' || c == '-' || c == '.'
}

// findURLs returns every URL in s.
func findURLs(s string) []hostRef {
	var out []hostRef
	for i := 0; i < len(s); {
		k := strings.Index(s[i:], "://")
		if k < 0 {
			break
		}
		k += i
		i = k + 3
		st := k
		for st > 0 && schemeChar(s[st-1]) {
			st--
		}
		scheme := strings.ToLower(s[st:k])
		if j := strings.LastIndexAny(scheme, "+-."); j >= 0 {
			scheme = scheme[j+1:] // git+https:// reads as https://
		}
		if !allowedSchemes[scheme] {
			continue
		}
		a := k + 3
		e := a
		if e < len(s) && s[e] == '[' {
			if c := strings.IndexByte(s[e:], ']'); c > 0 {
				e += c + 1
			}
		}
		for e < len(s) && !stopsAuthority(s[e]) {
			e++
		}
		hostport := s[a:e]
		if at := strings.LastIndexByte(hostport, '@'); at >= 0 {
			hostport = hostport[at+1:]
			a += at + 1
		}
		raw := hostport
		if strings.HasPrefix(raw, "[") {
			if c := strings.IndexByte(raw, ']'); c > 0 {
				raw = raw[:c+1]
			}
		} else if c := strings.LastIndexByte(raw, ':'); c >= 0 {
			raw = raw[:c]
		}
		host, key, ip, ok := normHost(raw)
		if !ok {
			continue
		}
		p := e
		for p < len(s) && !stopsPath(s[p]) && s[p] != '?' && s[p] != '#' {
			p++
		}
		path := strings.TrimRight(s[e:p], ".:,;")
		if len(path) > maxURLPath {
			path = path[:maxURLPath]
		}
		out = append(out, hostRef{raw: raw, off: a, host: host, key: key, ip: ip, url: buildURL(scheme, host, ip, path)})
		i = max(p, i)
	}
	return out
}

// buildURL joins a normalised URL and makes sure net/url reads it back
// with the same host; a path it cannot read is dropped.
func buildURL(scheme, host string, ip bool, path string) string {
	h := host
	if ip && strings.Contains(host, ":") {
		h = "[" + host + "]"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + strings.TrimLeft(path, "/")
	}
	u := scheme + "://" + h + path
	if p, err := url.Parse(u); err != nil || p.Hostname() != host {
		u = scheme + "://" + h + "/"
	}
	return u
}

// bareHost reads a whole literal as a host: "evil.example.ru",
// "evil.example.ru:8080", "//cdn.example.net/x.js" or an IP with a
// port. strict leaves out names whose suffix is not in bareTLDs and IPs
// without a port; a literal passed where a host is expected (a socket
// or DNS call) is read with strict off.
func bareHost(s string, strict bool) (hostRef, bool) {
	t := strings.TrimSpace(s)
	off := strings.Index(s, t)
	if len(t) > maxBare || t == "" || strings.ContainsAny(t, " \t\r\n\"'<>`") || strings.Contains(t, "://") {
		return hostRef{}, false
	}
	if strings.HasPrefix(t, "//") {
		t, off = t[2:], off+2
	}
	end := len(t)
	if k := strings.IndexAny(t, "/?#"); k >= 0 {
		end = k
	}
	hostport := t[:end]
	raw, port := hostport, ""
	if strings.HasPrefix(raw, "[") {
		if c := strings.IndexByte(raw, ']'); c > 0 {
			raw, port = raw[:c+1], strings.TrimPrefix(raw[c+1:], ":")
		}
	} else if c := strings.LastIndexByte(raw, ':'); c >= 0 && strings.Count(raw, ":") == 1 {
		raw, port = raw[:c], raw[c+1:]
	} else if strings.Count(raw, ":") >= 2 {
		raw = "[" + raw + "]" // a bare IPv6 address
	}
	if port != "" && strings.Trim(port, "0123456789") != "" {
		return hostRef{}, false
	}
	host, key, ip, ok := normHost(raw)
	if !ok {
		return hostRef{}, false
	}
	if strict {
		switch {
		case ip && port == "" && !strings.HasPrefix(raw, "["):
			return hostRef{}, false // "1.2.3.4" is as likely a version as a host
		case !ip:
			ps, _ := publicsuffix.PublicSuffix(host)
			if !strings.Contains(ps, ".") && !bareTLDs[ps] {
				return hostRef{}, false
			}
		}
	}
	return hostRef{raw: strings.Trim(raw, "[]"), off: off, host: host, key: key, ip: ip}, true
}

// findWWW finds www.host names in free text, where a link is often
// written without its scheme.
func findWWW(s string) []hostRef {
	var out []hostRef
	l := asciiLower(s) // same length as s, so offsets carry over
	for i := 0; i < len(l); {
		k := strings.Index(l[i:], "www.")
		if k < 0 {
			break
		}
		k += i
		i = k + 4
		if k > 0 && (schemeChar(l[k-1]) || l[k-1] == '/' || l[k-1] == '@') {
			continue // part of a URL or a longer name
		}
		e := k
		for e < len(s) && !stopsAuthority(s[e]) && s[e] != ':' {
			e++
		}
		raw := strings.TrimRight(s[k:e], ".")
		if host, key, _, ok := normHost(raw); ok {
			out = append(out, hostRef{raw: raw, off: k, host: host, key: key})
		}
		i = max(e, i)
	}
	return out
}

// asciiLower lowers ASCII letters only, keeping every byte offset.
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// textHosts is every URL in s, plus www. names (free text) or s itself
// as a bare host (a literal).
func textHosts(s string, literal, freeText bool) []hostRef {
	refs := findURLs(s)
	if freeText {
		refs = append(refs, findWWW(s)...)
	}
	if literal && len(refs) == 0 {
		if r, ok := bareHost(s, true); ok {
			refs = append(refs, r)
		}
	}
	return refs
}

// addHost records a host reference at byte offset off of the file:
// FDomain always, FURL for a URL.
func (c *collector) addHost(ctx string, r hostRef, off, line int, fn string) {
	if c.has(ctx, core.FDomain, r.key, line) && (r.url == "" || c.has(ctx, core.FURL, attrText(r.url), line)) {
		return
	}
	cat := hostCategory(r.host)
	if r.ip {
		cat = catRawIP
	}
	a := map[string]string{"host": attrText(r.host)}
	if cat != "" {
		a["category"] = cat
	}
	c.addCtxAt(ctx, off, core.FDomain, r.key, line, line, fn, a)
	if r.url != "" {
		u := map[string]string{"host": attrText(r.host), "domain": r.key}
		if cat != "" {
			u["category"] = cat
		}
		c.addCtxAt(ctx, off, core.FURL, attrText(r.url), line, line, fn, u)
	}
}

// addTextHosts records the hosts of text that starts on line, at
// about byte offset base of the file (-1 unknown).
func (c *collector) addTextHosts(ctx, text string, base, line int, fn string, literal, freeText bool) {
	for _, r := range textHosts(text, literal, freeText) {
		off := -1
		if base >= 0 {
			off = base + r.off
		}
		c.addHost(ctx, r, off, line+strings.Count(text[:r.off], "\n"), fn)
	}
}

// commentCtx is the context of a comment in a file of context ctx:
// a comment in the package's own code is "comment"; one in vendored,
// test or doc files keeps that context.
func commentCtx(ctx string) string {
	if ctx == core.CtxCode {
		return core.CtxComment
	}
	return ctx
}

// phpHosts records the hosts of a PHP file's literals, comments and
// inline HTML.
func (e *extractor) phpHosts(toks []php.Token) {
	ctx := e.col.ctx
	for _, t := range toks {
		switch t.Kind {
		case php.Comment:
			e.col.addTextHosts(commentCtx(ctx), t.Text, t.Off, t.Line, "", false, true)
		case php.InlineHTML:
			if strings.Contains(t.Text, "://") {
				e.col.addTextHosts(ctx, t.Text, t.Off, t.Line, "", false, false)
			}
		case php.String:
			if v, ok := php.StringValue(t); ok {
				e.col.addTextHosts(ctx, v, t.Off, t.Line, "", true, false)
				continue
			}
			for _, sg := range php.Segments(t) {
				if sg.Code == nil {
					e.col.addTextHosts(ctx, sg.Lit, t.Off, sg.Line, "", false, false)
				}
			}
		}
	}
}

// jsHosts records the hosts of a JavaScript file's literals and
// comments.
func (e *extractor) jsHosts(toks []js.Token) {
	ctx := e.col.ctx
	for _, t := range toks {
		switch t.Kind {
		case js.Comment:
			e.col.addTextHosts(commentCtx(ctx), t.Text, t.Off, t.Line, "", false, true)
		case js.String:
			if v, ok := js.StringValue(t); ok {
				e.col.addTextHosts(ctx, v, t.Off, t.Line, "", true, false)
			}
		case js.Template:
			if v, ok := js.TemplateText(t); ok {
				e.col.addTextHosts(ctx, v, t.Off, t.Line, "", strings.HasPrefix(t.Text, "`") && strings.HasSuffix(t.Text, "`"), false)
			}
		}
	}
}

// callHosts records hosts that only folding shows: a URL or host built
// from pieces and passed to a call. A call that opens a connection
// reads its string arguments as hosts without the bare-name rules.
func (e *extractor) callHosts(c *callSite, network bool) {
	for i := 0; i < len(c.args) && i < 4; i++ {
		v, ok := c.args[i].v.str()
		if !ok || v == "" {
			continue
		}
		sp := e.span(c, i)
		single := sp[1]-sp[0] == 1 && e.toks[sp[0]].k == tStr
		if single && !network {
			continue // the literal scan has it
		}
		refs := findURLs(v)
		if len(refs) == 0 {
			if r, ok := bareHost(v, !network); ok {
				refs = append(refs, r)
			}
		}
		for _, r := range refs {
			e.col.addHost(e.col.ctx, r, e.toks[c.pos].off, c.line, e.fnAt(c.pos))
		}
	}
}

// sendHost is the host a send call goes to when its arguments name it:
// the URL in the first argument of an HTTP call, or the host argument of
// a socket or DNS call (fsockopen("evil.test", 80), net.connect(443,
// "1.2.3.4"), stream_socket_client("tcp://evil.test:80")). It is false
// for a host built at run time.
func sendHost(c *callSite, channel string) (hostRef, bool) {
	switch channel {
	case "http":
		if v, ok := c.arg(0).v.str(); ok {
			if refs := findURLs(v); len(refs) > 0 {
				return refs[0], true
			}
		}
	case "socket", "dns":
		for i := 0; i < len(c.args) && i < 4; i++ {
			v, ok := c.args[i].v.str()
			if !ok || v == "" {
				continue
			}
			if refs := findURLs(v); len(refs) > 0 {
				return refs[0], true // a WebSocket URL
			}
			if scheme, rest, ok := strings.Cut(v, "://"); ok && socketSchemes[strings.ToLower(scheme)] {
				v = rest
			}
			if r, ok := bareHost(v, false); ok {
				return r, true
			}
		}
	}
	return hostRef{}, false
}

// sendLocal is the target of a send call that names a local address
// (loopback, unspecified, link-local or multicast) or a local or
// reserved name (localhost, .test, .internal, example.com), as
// written. sendHost leaves those out (they are not hosts on the
// internet), so without this the send would read as going to a host
// built at run time.
func sendLocal(c *callSite, channel string) (string, bool) {
	n := 0
	switch channel {
	case "http":
		n = 1
	case "socket", "dns":
		n = 4
	}
	for i := 0; i < len(c.args) && i < n; i++ {
		v, ok := c.args[i].v.str()
		if !ok || v == "" {
			continue
		}
		if h, ok := localAddr(v); ok {
			return h, true
		}
	}
	return "", false
}

// localAddr returns the host of s, a URL, a host with a port or a bare
// host, when it is local: an address publicAddr rejects, or a valid
// name normHost leaves out for its reserved top level domain or as a
// documentation domain.
func localAddr(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if scheme, rest, ok := strings.Cut(s, "://"); ok {
		if !allowedSchemes[strings.ToLower(scheme)] && !socketSchemes[strings.ToLower(scheme)] {
			return "", false
		}
		s = rest
	}
	if k := strings.IndexAny(s, "/?#"); k >= 0 {
		s = s[:k]
	}
	if at := strings.LastIndexByte(s, '@'); at >= 0 {
		s = s[at+1:]
	}
	switch {
	case strings.HasPrefix(s, "["):
		if c := strings.IndexByte(s, ']'); c > 0 {
			s = s[1:c]
		}
	case strings.Count(s, ":") == 1:
		s, _, _ = strings.Cut(s, ":")
	}
	if a, err := netip.ParseAddr(s); err == nil {
		if a.Zone() != "" || publicAddr(a) {
			return "", false
		}
		return a.String(), true
	}
	return reservedName(s)
}

// reservedName returns s in lower case punycode when it is a valid host
// name that is localhost, ends in a reserved top level domain or is
// under a documentation domain.
func reservedName(s string) (string, bool) {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return "", false
	}
	ascii, err := idna.Lookup.ToASCII(strings.ToLower(s))
	if err != nil || ascii == "" {
		return "", false
	}
	labels := strings.Split(ascii, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 || strings.Trim(l, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" || l[0] == '-' || l[len(l)-1] == '-' {
			return "", false
		}
	}
	if ascii == "localhost" || len(labels) > 1 && reservedTLDs[labels[len(labels)-1]] {
		return ascii, true
	}
	if key, err := publicsuffix.EffectiveTLDPlusOne(ascii); err == nil && exampleDomains[key] {
		return ascii, true
	}
	return "", false
}

// socketSchemes are the transports PHP's stream_socket_client and
// fsockopen take in front of a host.
var socketSchemes = map[string]bool{"tcp": true, "udp": true, "ssl": true, "tls": true}

// hostCalls are the calls whose arguments name a host to connect to.
var hostCalls = map[string]bool{
	"fsockopen": true, "pfsockopen": true, "stream_socket_client": true, "gethostbyname": true,
	"dns_get_record": true, "socket_connect": true, "net.connect": true, "net.createConnection": true,
	"tls.connect": true, "dns.resolve": true, "dns.resolveTxt": true, "dns.resolve4": true, "dns.lookup": true,
}

// jsonHosts records the hosts in the string values of a JSON document.
func jsonHosts(col *collector, src []byte) {
	dec := json.NewDecoder(bytes.NewReader(src))
	for {
		tk, err := dec.Token()
		if errors.Is(err, io.EOF) || err != nil {
			return
		}
		s, ok := tk.(string)
		if !ok {
			continue
		}
		end := int(dec.InputOffset())
		line := bytes.Count(src[:min(end, len(src))], []byte("\n")) + 1
		// A JSON string holds no raw line break; an escaped one must not
		// move the line.
		col.addTextHosts(col.ctx, strings.ReplaceAll(s, "\n", " "), -1, line, "", true, false)
	}
}

// docHosts records the URLs and www. names of documentation text.
func docHosts(col *collector, src []byte) {
	ctx := col.ctx
	if ctx == core.CtxCode {
		ctx = core.CtxDoc
	}
	col.addTextHosts(ctx, string(src), 0, 1, "", false, true)
}

// jsonFeatures returns the features of a JSON file: its hosts, plus
// npm install hooks for a package.json (hasGyp: a binding.gyp sits next
// to it).
func jsonFeatures(p string, src []byte, hasGyp bool) []core.Feature {
	col := newCollector(p, pathContext(p), newLineIndex(src))
	jsonHosts(col, src)
	out := col.out
	if strings.HasSuffix(p, "package.json") && (p == "package.json" || strings.HasSuffix(p, "/package.json")) {
		out = append(out, packageJSONFeatures(p, src, hasGyp)...)
	}
	sortFeatures(out)
	return out
}

// docFeatures returns the hosts of a documentation or text file.
func docFeatures(p string, src []byte) []core.Feature {
	col := newCollector(p, pathContext(p), newLineIndex(src))
	docHosts(col, src)
	sortFeatures(col.out)
	return col.out
}
