// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package code

import (
	"cmp"
	"context"
	"io"
	"net/netip"
	"net/url"
	"path"
	"slices"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
)

// The signals of the network, data and credential detector.
const (
	SigOutboundNewDomain = "outbound-new-domain"
	SigDataExfil         = "data-exfil"
	SigCredentialAccess  = "credential-access" //nolint:gosec // a signal ID, not a credential
	SigSecretAdded       = "secret-added"
	SigUnicodeHidden     = "unicode-hidden"
	SigCodeInAsset       = "code-in-asset"
)

// More feature attributes, read by the network detector.
const (
	// AttrCategory is a host's category when the analyzer knows it
	// ("raw-ip", "blockchain-rpc", "paste", "shortener", "dyndns",
	// "raw-github"). The detector also works it out from the host.
	AttrCategory = "category"
	// AttrHost is the host an FSend goes to, when it could be folded.
	AttrHost = "host"
	// AttrReads is what an FSend's function reads and sends, comma
	// separated: "users", "admin_email", "options", "env", "files".
	AttrReads = "reads"
	// AttrSent is "true" on an FCredRead whose value reaches a send.
	AttrSent = "sent"
	// AttrExample is "true" on an FSecret whose value is a documented
	// example (EXAMPLE, xxxx).
	AttrExample = "example"
	// AttrSecret is an FSecret's masked text as kit secrets prints it
	// (name=masked).
	AttrSecret = "secret"
	// AttrTarget is the folded path an FInclude loads.
	AttrTarget = "target"
	// AttrTrailing is "code" on an FHalt with code after
	// __halt_compiler().
	AttrTrailing = "trailing"
)

// Host categories that raise outbound-new-domain to high.
const (
	CatRawIP         = "raw-ip"
	CatBlockchainRPC = "blockchain-rpc"
	CatPaste         = "paste"
	CatShortener     = "shortener"
	CatDynDNS        = "dyndns"
	CatRawGitHub     = "raw-github"
)

func init() { core.RegisterDetector(netDetector{}) }

// netDetector finds new hosts, sends of site data, credential and token
// reads, added secrets, hidden characters and code hidden in assets
// (PRD 12.1). It works on host names as text: it never resolves or
// contacts a host.
type netDetector struct{}

func (netDetector) Info() core.DetectorInfo {
	return core.DetectorInfo{Name: "code-network", Signals: []string{
		SigOutboundNewDomain, SigDataExfil, SigCredentialAccess, SigSecretAdded, SigUnicodeHidden, SigCodeInAsset,
	}}
}

func (netDetector) Detect(ctx context.Context, s *core.Subject, emit func(core.Finding)) {
	out := newEmitter(s, emit)
	all := s.NewFeatures.NewIn(s.OldFeatures)
	for _, fd := range domainFindings(s, all) {
		out.send(fd)
	}
	feats := newFeatures(s)
	docs := docText(s)
	for _, f := range all {
		if ctx.Err() != nil {
			return
		}
		// Secrets and hidden characters matter in comments too. A
		// published key is published; Trojan Source hides in comments.
		// Tests (and docs, for hidden characters) lower them to info.
		switch f.Kind {
		case core.FSecret:
			out.send(secretFinding(f))
			continue
		case core.FUnicode:
			out.send(unicodeFinding(f))
			continue
		}
		if !fires(f) {
			continue
		}
		switch f.Kind {
		case core.FSend:
			if fd, ok := exfilFinding(s, f); ok {
				out.send(fd)
			}
		case core.FCredRead:
			if credRead(f, feats) {
				out.send(newFinding(SigCredentialAccess, f))
			}
		case core.FEnvRead:
			if tokenName(f.Key) && !docs.mentions(f.Key) {
				out.send(newFinding(SigCredentialAccess, f))
			}
		case core.FCodeInAsset:
			out.send(assetFinding(s, f))
		case core.FHalt:
			if f.Attrs[AttrTrailing] == "code" {
				out.send(assetFinding(s, f))
			}
		}
	}
}

// Why a finding was lowered, in the Demoted field.
const (
	DemotedNotCode  = "not in code (comment, docs or tests)"
	DemotedKnown    = "known host"
	DemotedOwnHost  = "the package's own host"
	DemotedConfig   = "listed in signals.domains_ok"
	DemotedTestPath = "test or fixture path"
	DemotedExample  = "documented example value"
	DemotedI18n     = "translation file"
)

// domainFindings gives one outbound-new-domain finding per new host, at
// its worst place: code beats comments and docs, then the first by path
// and line.
func domainFindings(s *core.Subject, all []core.Feature) []core.Finding {
	best := map[string]core.Finding{}
	var order []string
	for _, f := range all {
		if f.Kind != core.FDomain {
			continue
		}
		host := normHost(f.Key)
		if host == "" {
			continue
		}
		fd := domainFinding(s, f, host)
		prev, ok := best[host]
		if !ok {
			order = append(order, host)
		}
		if !ok || fd.Severity > prev.Severity {
			best[host] = fd
		}
	}
	out := make([]core.Finding, 0, len(order))
	for _, h := range order {
		out = append(out, best[h])
	}
	return out
}

// domainFinding rates one new host: info outside code and for known
// hosts, high for the risky categories, else medium.
func domainFinding(s *core.Subject, f core.Feature, host string) core.Finding {
	fd := newFinding(SigOutboundNewDomain, f)
	fd.Domains = []string{host}
	cat := f.Attrs[AttrCategory]
	if cat == "" {
		cat = hostCategory(host)
	}
	switch {
	case !fires(f):
		fd.Severity, fd.Demoted = cli.SeverityInfo, DemotedNotCode
	case matchesAny(host, configDomains(s)):
		fd.Severity, fd.Demoted = cli.SeverityInfo, DemotedConfig
	case matchesAny(host, ownHosts(s)):
		fd.Severity, fd.Demoted = cli.SeverityInfo, DemotedOwnHost
	case matchesAny(host, knownDomains()):
		fd.Severity, fd.Demoted = cli.SeverityInfo, DemotedKnown
	case cat != "":
		fd.Severity = cli.SeverityHigh
		fd.Evidence = core.NewSnippet(cat + " host " + host + ": " + f.Ev.Snippet.String())
	}
	return fd
}

// Hosts of the risky categories. A suffix entry matches the host and
// its subdomains.
var (
	rpcHosts = []string{"infura.io", "alchemy.com", "cloudflare-eth.com", "etherscan.io", "bscscan.com",
		"quiknode.pro", "publicnode.com", "llamarpc.com", "ankr.com", "trongrid.io", "binance.org"}
	pasteHosts = []string{"pastebin.com", "paste.ee", "hastebin.com", "ghostbin.com", "rentry.co", "dpaste.org",
		"dpaste.com", "termbin.com", "paste.rs", "controlc.com", "pastes.io", "justpaste.it"}
	shortHosts = []string{"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "v.gd", "ow.ly", "cutt.ly",
		"rebrand.ly", "shorturl.at", "tiny.cc", "buff.ly", "rb.gy", "t.ly"}
	dynHosts = []string{"duckdns.org", "no-ip.com", "noip.com", "ddns.net", "hopto.org", "zapto.org", "sytes.net",
		"dynu.com", "afraid.org", "dyndns.org", "dynv6.net", "ngrok.io", "ngrok-free.app", "trycloudflare.com",
		"serveo.net", "loca.lt"}
	rawGitHubHosts = []string{"raw.githubusercontent.com", "gist.githubusercontent.com"}
)

// hostCategory names the risky category of host, or "".
func hostCategory(host string) string {
	switch {
	case isIP(host):
		return CatRawIP
	case strings.HasPrefix(host, "rpc.") || matchesAny(host, rpcHosts):
		return CatBlockchainRPC
	case matchesAny(host, pasteHosts):
		return CatPaste
	case matchesAny(host, shortHosts):
		return CatShortener
	case matchesAny(host, dynHosts):
		return CatDynDNS
	case matchesAny(host, rawGitHubHosts):
		return CatRawGitHub
	}
	return ""
}

// isIP reports whether host is an IPv4 or IPv6 address. It uses
// net/netip, which only parses text: package net may not be imported
// where package text is read (internal/exectest).
func isIP(host string) bool {
	_, err := netip.ParseAddr(host)
	return err == nil
}

// normHost lower-cases a host and drops a port, brackets and a trailing
// dot. A bare IPv6 address has several colons and keeps them all.
func normHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	switch {
	case strings.HasPrefix(h, "["):
		if i := strings.IndexByte(h, ']'); i > 0 {
			h = h[1:i]
		}
	case strings.Count(h, ":") == 1:
		h, _, _ = strings.Cut(h, ":")
	}
	return strings.TrimSuffix(strings.Trim(h, "[]"), ".")
}

// matchesAny reports whether host matches one of pats. A plain pattern
// matches the host and its subdomains. A pattern with * is a glob;
// "*.x" also matches x itself.
func matchesAny(host string, pats []string) bool {
	for _, p := range pats {
		p = strings.ToLower(strings.TrimSpace(p))
		switch {
		case p == "":
		case strings.ContainsAny(p, "*?["):
			if ok, _ := path.Match(p, host); ok || strings.HasPrefix(p, "*.") && host == p[2:] {
				return true
			}
		case host == p || strings.HasSuffix(host, "."+p):
			return true
		}
	}
	return false
}

func configDomains(s *core.Subject) []string {
	if s.Config == nil {
		return nil
	}
	return s.Config.Signals.DomainsOK
}

// knownDomains is the shipped known-safe list, empty until package data
// is linked.
func knownDomains() []string {
	if d := core.GetDataPacks(); d != nil {
		return d.DomainsOK()
	}
	return nil
}

// ownHosts are the hosts of the package's homepage and repository. They
// come from the installed version when there is one: the candidate
// could name the new host as its homepage to hide it.
func ownHosts(s *core.Subject) []string {
	m := s.Old
	if m == nil {
		m = s.New
	}
	if m == nil {
		return nil
	}
	var out []string
	for _, u := range []string{m.Homepage, m.Repository} {
		if h := strings.TrimPrefix(urlHost(u), "www."); h != "" && !codeHosts[h] {
			out = append(out, h)
		}
	}
	return out
}

// codeHosts serve everyone's repositories, so a repository there makes
// no host the package's own: github.com/attacker/x is not the package.
// Feature keys hold the host only, so the owner path can't be compared.
var codeHosts = map[string]bool{
	"github.com": true, "gitlab.com": true, "bitbucket.org": true, "codeberg.org": true,
	"sourceforge.net": true, "git.sr.ht": true,
}

// urlHost returns the host of a homepage or repository field: a URL,
// "git+https://...", "git@host:owner/repo" or "github:owner/repo".
func urlHost(raw string) string {
	raw = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(raw), "git+"))
	switch {
	case raw == "":
		return ""
	case strings.HasPrefix(raw, "github:"):
		return "github.com"
	case strings.HasPrefix(raw, "gitlab:"):
		return "gitlab.com"
	case strings.HasPrefix(raw, "bitbucket:"):
		return "bitbucket.org"
	}
	if at := strings.Index(raw, "@"); at >= 0 && !strings.Contains(raw, "://") {
		if h, _, ok := strings.Cut(raw[at+1:], ":"); ok {
			return normHost(h)
		}
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return normHost(u.Hostname())
}

// exfilFinding is a data-exfil finding for a new send that carries what
// its function reads: high to a host new in this version, medium to a
// host the installed version already used or one built at run time.
func exfilFinding(s *core.Subject, f core.Feature) (core.Finding, bool) {
	reads := strings.TrimSpace(f.Attrs[AttrReads])
	if reads == "" {
		return core.Finding{}, false
	}
	fd := newFinding(SigDataExfil, f)
	host := normHost(f.Attrs[AttrHost])
	if host != "" {
		fd.Domains = []string{host}
	}
	if host == "" || knownHost(s.OldFeatures, host) {
		fd.Severity = cli.SeverityMedium
	}
	fd.Evidence = core.NewSnippet("sends " + reads + " to " + cmp.Or(host, "a host built at run time") + ": " + f.Ev.Snippet.String())
	return fd, true
}

// knownHost reports whether the installed version already named host,
// as a domain or as the target of a send.
func knownHost(old *core.FeatureSet, host string) bool {
	if old == nil {
		return false
	}
	for _, fs := range old.ByKey {
		for _, f := range fs {
			switch f.Kind {
			case core.FDomain:
				if normHost(f.Key) == host {
					return true
				}
			case core.FSend:
				if normHost(f.Attrs[AttrHost]) == host {
					return true
				}
			}
		}
	}
	return false
}

// credRead reports whether a new credential read counts. wp-config.php
// constants are read by many plugins (the database prefix, salts for
// their own hashes), so those count only when the value is sent out:
// AttrSent, or a new send in the same file.
func credRead(f core.Feature, feats []core.Feature) bool {
	if !strings.HasPrefix(strings.ToLower(f.Key), "wp-config") {
		return true
	}
	if f.Attrs[AttrSent] == "true" {
		return true
	}
	return slices.ContainsFunc(feats, func(o core.Feature) bool { return o.Kind == core.FSend && o.Ev.Path == f.Ev.Path })
}

// tokenName reports whether an environment variable holds a credential:
// registry and cloud tokens and anything named like a secret. "*" is a
// read of the whole environment. NODE_ENV and the like never count.
func tokenName(name string) bool {
	n := strings.ToUpper(strings.TrimSpace(name))
	switch n {
	case "*", "NPM_TOKEN", "NODE_AUTH_TOKEN", "GITHUB_TOKEN", "GH_TOKEN", "GITLAB_TOKEN", "CI_JOB_TOKEN",
		"COMPOSER_AUTH", "PACKAGIST_TOKEN":
		return true
	case "":
		return false
	}
	return strings.HasPrefix(n, "AWS_") || strings.HasPrefix(n, "AZURE_CLIENT_SECRET") ||
		strings.HasSuffix(n, "_TOKEN") || strings.Contains(n, "SECRET") || strings.HasSuffix(n, "_PASSWORD") ||
		strings.HasSuffix(n, "_API_KEY") || strings.HasSuffix(n, "_ACCESS_KEY") || strings.HasSuffix(n, "_PRIVATE_KEY")
}

// docs is the text of a package's documentation, upper-cased.
type docs string

func (d docs) mentions(name string) bool {
	n := strings.ToUpper(strings.TrimSpace(name))
	return n != "" && n != "*" && strings.Contains(string(d), n)
}

// docMax bounds how much documentation is read per file.
const docMax = 256 << 10

// docText reads the README, readme.txt, *.md and docs/ files of the
// installed version, or of the candidate for an added package. A doc
// line added in the same update does not count: whoever adds a token
// read can add a line about it too.
func docText(s *core.Subject) docs {
	t := s.OldTree
	if s.Old == nil {
		t = s.NewTree
	}
	if t == nil || t.Blobs == nil {
		return ""
	}
	var b strings.Builder
	for _, f := range t.Files {
		if !docFile(f.Path) {
			continue
		}
		rc, err := t.Blobs.Open(f.SHA256)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(rc, docMax))
		_ = rc.Close()
		if err == nil {
			b.Write(data)
			b.WriteByte('\n')
		}
	}
	return docs(strings.ToUpper(b.String()))
}

// docFile reports whether p is documentation.
func docFile(p string) bool {
	base := strings.ToLower(path.Base(p))
	return strings.HasPrefix(base, "readme") || strings.HasSuffix(base, ".md") ||
		strings.HasPrefix(p, "docs/") || strings.Contains(p, "/docs/")
}

// testDirs are folders whose secrets are fixtures, not credentials.
var testDirs = []string{"test", "tests", "__tests__", "spec", "fixtures", "__fixtures__", "testdata"}

func testPath(p string) bool {
	for _, seg := range strings.Split(strings.ToLower(p), "/") {
		if slices.Contains(testDirs, seg) {
			return true
		}
	}
	return false
}

// secretFinding is a secret-added finding; info in tests and fixtures
// and for documented example values. Evidence is always masked.
func secretFinding(f core.Feature) core.Finding {
	fd := newFinding(SigSecretAdded, f)
	if sec := f.Attrs[AttrSecret]; sec != "" {
		fd.Evidence = core.NewSnippet(cmp.Or(f.Key, "secret") + ": " + sec)
	}
	ev := strings.ToUpper(fd.Evidence.String())
	switch {
	case f.Context == core.CtxTest || testPath(f.Ev.Path):
		fd.Severity, fd.Demoted = cli.SeverityInfo, DemotedTestPath
	case f.Attrs[AttrExample] == "true" || strings.Contains(ev, "EXAMPLE") || strings.Contains(ev, "XXXX"):
		fd.Severity, fd.Demoted = cli.SeverityInfo, DemotedExample
	}
	return fd
}

// i18nFile reports whether p is a translation file, where
// right-to-left marks are text: .po, .pot, .mo, .l10n.php, or JSON under
// a languages, i18n or locales folder.
func i18nFile(p string) bool {
	p = "/" + strings.ToLower(p)
	switch path.Ext(p) {
	case ".po", ".pot", ".mo":
		return true
	case ".json":
		return strings.Contains(p, "/languages/") || strings.Contains(p, "/i18n/") || strings.Contains(p, "/locales/")
	}
	return strings.HasSuffix(p, ".l10n.php")
}

// unicodeFinding is an unicode-hidden finding: medium in code and
// comments (Trojan Source hides in comments), info in translation files,
// docs and tests.
func unicodeFinding(f core.Feature) core.Finding {
	fd := newFinding(SigUnicodeHidden, f)
	switch {
	case i18nFile(f.Ev.Path):
		fd.Severity, fd.Demoted = cli.SeverityInfo, DemotedI18n
	case f.Context == core.CtxDoc || f.Context == core.CtxTest:
		fd.Severity, fd.Demoted = cli.SeverityInfo, DemotedNotCode
	}
	return fd
}

// assetFinding is a code-in-asset finding: high, critical when code of
// the candidate includes that file.
func assetFinding(s *core.Subject, f core.Feature) core.Finding {
	fd := newFinding(SigCodeInAsset, f)
	if included(s.NewFeatures, f.Ev.Path) {
		fd.Severity = cli.SeverityCritical
		fd.Evidence = core.NewSnippet("included by the package's code: " + f.Ev.Snippet.String())
	}
	return fd
}

// included reports whether an FInclude of the set loads p. The folded
// target is compared by its tail, so __DIR__ . '/assets/icon.png' and
// 'assets/icon.png' both name assets/icon.png.
func included(fs *core.FeatureSet, p string) bool {
	if fs == nil {
		return false
	}
	want := "/" + strings.TrimLeft(p, "/")
	for k, list := range fs.ByKey {
		if !strings.HasPrefix(k, string(core.FInclude)+":") {
			continue
		}
		for _, inc := range list {
			if !fires(inc) {
				continue
			}
			target := cmp.Or(inc.Attrs[AttrTarget], inc.Key)
			target = "/" + strings.TrimLeft(strings.TrimPrefix(strings.ReplaceAll(target, `\`, "/"), "./"), "/")
			if target != "/" && (strings.HasSuffix(want, target) || strings.HasSuffix(target, want)) {
				return true
			}
		}
	}
	return false
}
