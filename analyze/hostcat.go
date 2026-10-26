// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import "strings"

// Host categories: kinds of hosts that legitimate plugins and packages
// rarely talk to and that past incidents used for payloads or
// collection. A category raises a new-domain finding; it is never a
// verdict on its own.
const (
	catRawIP      = "raw-ip"
	catBlockchain = "blockchain-rpc"
	catPaste      = "paste"
	catShortener  = "shortener"
	catDynDNS     = "dyndns"
	catRawGitHub  = "raw-github"
)

// hostCats maps a category to the domains in it. A host is in a
// category when it is one of the domains or a subdomain of one.
var hostCats = []struct {
	cat     string
	domains []string
}{
	{catRawGitHub, []string{"raw.githubusercontent.com", "gist.githubusercontent.com"}},
	{catBlockchain, []string{
		"infura.io", "alchemy.com", "alchemyapi.io", "cloudflare-eth.com", "etherscan.io", "ankr.com",
		"quiknode.pro", "quicknode.com", "quiknode.io", "publicnode.com", "bscscan.com", "polygonscan.com",
		"blastapi.io", "llamarpc.com", "chainstack.com", "drpc.org", "getblock.io", "bsc-dataseed.binance.org",
		"trongrid.io", "tronscan.org", "blockcypher.com", "mempool.space",
	}},
	{catPaste, []string{
		"pastebin.com", "paste.ee", "hastebin.com", "hastebin.skyra.pw", "ghostbin.co", "ghostbin.com",
		"rentry.co", "rentry.org", "pastes.io", "dpaste.org", "dpaste.com", "controlc.com", "justpaste.it",
		"paste.rs", "termbin.com",
	}},
	{catShortener, []string{
		"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "goo.gl", "ow.ly", "rebrand.ly", "shorturl.at",
		"rb.gy", "buff.ly", "tiny.cc", "v.gd", "t.ly", "bl.ink", "s.id",
	}},
	{catDynDNS, []string{
		"duckdns.org", "no-ip.com", "no-ip.org", "no-ip.biz", "no-ip.info", "noip.com", "ddns.net",
		"ngrok-free.app", "ngrok.io", "ngrok.app", "ngrok-free.dev", "trycloudflare.com", "hopto.org",
		"zapto.org", "sytes.net", "serveo.net", "loca.lt", "dynu.com", "dynu.net", "afraid.org",
		"myftp.org", "myftp.biz", "serveftp.com", "servebeer.com", "3utilities.com", "dyndns.org",
		"freeddns.org", "localto.net", "pinggy.link",
	}},
}

// hostCategory returns the category of a normalised host, or "". The
// first label "rpc" (rpc.example.org) also marks a blockchain node.
func hostCategory(host string) string {
	for _, c := range hostCats {
		for _, d := range c.domains {
			if host == d || strings.HasSuffix(host, "."+d) {
				return c.cat
			}
		}
	}
	if strings.HasPrefix(host, "rpc.") || strings.Contains(host, "quiknode") {
		return catBlockchain
	}
	return ""
}
