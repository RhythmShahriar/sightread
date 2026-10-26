// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/secrets"
	"github.com/RhythmShahriar/rhythm/kit/term"
)

// Schema identifies the JSON layout the webhook backend posts.
const Schema = "rhythm-sightread-notify/v1"

// MaxListed is how many items a chat or email message lists before it
// says how many more there are. Webhooks get every item.
const MaxListed = 25

// Kinds of Item.Kind.
const (
	// KindUpdate is a new candidate version with findings at or above
	// the watch's --notify-min.
	KindUpdate = "update"
	// KindNewSignal is a finding a newer signal data pack raised on a
	// version a site already runs.
	KindNewSignal = "new-signal"
	// KindOwner is a change of who can publish an installed package.
	KindOwner = "owner-change"
	// KindClosed is an installed WordPress.org package that was closed.
	KindClosed = "closed"
)

// Item is one thing a notification tells, grouped by update: the same
// version on 14 sites is one item listing 14 sites.
type Item struct {
	Kind      string   `json:"kind"`
	Ecosystem string   `json:"ecosystem"`
	Name      string   `json:"name"`
	From      string   `json:"from,omitempty"` // the installed version, or the release before it for new-signal
	To        string   `json:"to,omitempty"`   // the candidate, or the installed version for new-signal
	Verdict   string   `json:"verdict,omitempty"`
	Sites     []string `json:"sites"`
	Severity  string   `json:"severity,omitempty"` // the worst counted finding
	Findings  int      `json:"findings"`
	// Top is the title of the most severe finding: a catalogue title,
	// never text from the package.
	Top    string `json:"top,omitempty"`
	Detail string `json:"detail,omitempty"` // owner-change and closed: what changed
}

// Message is what every backend sends.
type Message struct {
	Schema      string `json:"schema"`  // rhythm-sightread-notify/v1
	Tool        string `json:"tool"`    // rhythm-sightread
	Version     string `json:"version"` // the Sightread version that sent it
	Watch       string `json:"watch"`   // the watch's --name
	MinSeverity string `json:"min_severity"`
	Summary     string `json:"summary"`
	Report      string `json:"report"` // the run's JSON report on the watching machine
	Items       []Item `json:"items"`
	// Incomplete says the run left packages out, so nobody reads a short
	// list as a clean bill of health.
	Incomplete string `json:"incomplete,omitempty"`
}

// New builds a message, cleaning and masking every text and writing its
// summary line.
func New(watch, version, minSeverity, report, incomplete string, items []Item) Message {
	m := Message{Schema: Schema, Tool: "rhythm-sightread", Version: safe(version), Watch: safe(watch),
		MinSeverity: safe(minSeverity), Report: safe(report), Incomplete: safe(incomplete), Items: []Item{}}
	for _, it := range items {
		it.Kind, it.Ecosystem, it.Name = safe(it.Kind), safe(it.Ecosystem), safe(it.Name)
		it.From, it.To, it.Verdict, it.Severity = safe(it.From), safe(it.To), safe(it.Verdict), safe(it.Severity)
		it.Top, it.Detail = safe(it.Top), safe(it.Detail)
		sites := make([]string, 0, len(it.Sites))
		for _, s := range it.Sites {
			sites = append(sites, safe(s))
		}
		it.Sites = sites
		m.Items = append(m.Items, it)
	}
	m.Summary = summary(m)
	return m
}

// summary reads e.g. "Sightread shop-fleet: 2 updates to look at, 1 new
// signal on a version you already run, 1 owner change".
func summary(m Message) string {
	counts := map[string]int{}
	for _, it := range m.Items {
		counts[it.Kind]++
	}
	var parts []string
	add := func(n int, one, many string) {
		switch {
		case n == 1:
			parts = append(parts, one)
		case n > 1:
			parts = append(parts, fmt.Sprintf(many, n))
		}
	}
	add(counts[KindUpdate], "1 update to look at", "%d updates to look at")
	add(counts[KindNewSignal], "1 new signal on a version you already run", "%d new signals on versions you already run")
	add(counts[KindOwner], "1 owner change", "%d owner changes")
	add(counts[KindClosed], "1 closed plugin or theme", "%d closed plugins or themes")
	who := "Sightread"
	if m.Watch != "" {
		who += " " + m.Watch
	}
	if len(parts) == 0 {
		return who + ": nothing new"
	}
	return who + ": " + strings.Join(parts, ", ")
}

// Text renders the message as plain lines for chat and email. esc
// escapes each line for the backend's markup.
func (m Message) Text(esc func(string) string) string {
	var b strings.Builder
	b.WriteString(esc(m.Summary) + "\n")
	if m.Incomplete != "" {
		b.WriteString(esc(m.Incomplete) + "\n")
	}
	b.WriteString("\n")
	for i, it := range m.Items {
		if i == MaxListed {
			fmt.Fprintf(&b, "…and %d more\n", len(m.Items)-MaxListed)
			break
		}
		b.WriteString(esc(it.Line()) + "\n")
		if it.Top != "" {
			b.WriteString(esc("  top finding: "+it.Top) + "\n")
		}
	}
	b.WriteString("\n" + esc("Report: "+m.Report) + "\n")
	return b.String()
}

// Line is an item's one-line form, e.g. "wpforms-lite 1.9.1 → 1.9.2 HOLD
// on 14 sites".
func (it Item) Line() string {
	where := sitesText(it.Sites)
	switch it.Kind {
	case KindNewSignal:
		return fmt.Sprintf("new signal on a version you already run: %s %s %s%s", it.Name, it.To, strings.ToUpper(it.Verdict), where)
	case KindOwner:
		return fmt.Sprintf("owner change: %s %s%s: %s", it.Name, it.To, where, it.Detail)
	case KindClosed:
		return fmt.Sprintf("closed on wordpress.org: %s %s%s: %s", it.Name, it.To, where, it.Detail)
	}
	from := it.From
	if from == "" {
		from = "new"
	}
	return fmt.Sprintf("%s %s → %s %s%s", it.Name, from, it.To, strings.ToUpper(it.Verdict), where)
}

// sitesText is " on shop" or " on 14 sites", "" outside a fleet.
func sitesText(sites []string) string {
	switch len(sites) {
	case 0:
		return ""
	case 1:
		return " on " + sites[0]
	}
	return fmt.Sprintf(" on %d sites", len(sites))
}

// Notifier sends a message to one place.
type Notifier interface {
	Send(ctx context.Context, m Message) error
	// String names the receiver for logs: its scheme and host, never
	// the path, query or user that hold its secrets.
	String() string
}

// Options are what backends need besides the URL.
type Options struct {
	// HTTPClient sends webhook requests. Nil means a client with a 30s
	// timeout; redirects are never followed either way.
	HTTPClient *http.Client
	// SMTPPassword is the SMTP password, from SIGHTREAD_SMTP_PASSWORD. It
	// never goes in the URL, where shell history and process lists see it.
	SMTPPassword string
	// TLSConfig is the base TLS config for SMTP; nil uses the system roots.
	TLSConfig *tls.Config
	// Dial opens SMTP connections; nil uses net.Dialer. Tests point it at
	// a local server.
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// Parse returns the notifier a URL names. Its errors never include the
// URL's path, query or user.
func Parse(raw string, o Options) (Notifier, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" {
		return nil, errors.New("not a notification URL; want slack://, discord://, webhook+https:// or smtp://")
	}
	shown := Redacted(raw)
	if u.Host == "" {
		return nil, fmt.Errorf("%s: no host in the URL", shown)
	}
	switch strings.ToLower(u.Scheme) {
	case "slack":
		return newHook(u, "https", o, shown, slackBody)
	case "discord":
		return newHook(u, "https", o, shown, discordBody)
	case "webhook+https":
		return newHook(u, "https", o, shown, webhookBody)
	case "webhook+http":
		if !loopback(u.Hostname()) {
			return nil, fmt.Errorf("%s: plain http is only for a receiver on this machine; use webhook+https://", shown)
		}
		return newHook(u, "http", o, shown, webhookBody)
	case "smtp", "smtps":
		return newMailer(u, o, shown)
	}
	return nil, fmt.Errorf("unsupported notification scheme %q; want slack, discord, webhook+https or smtp", safe(u.Scheme))
}

// Redacted is a notification URL as logs may show it: scheme and host
// (with port), no user, path or query.
func Redacted(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "notification URL"
	}
	return safe(strings.ToLower(u.Scheme) + "://" + u.Host)
}

// cleanErr drops the URL that net/http puts in its errors.
func cleanErr(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

// loopback reports whether host is this machine. Only a receiver there
// may take a message over plain http or SMTP without TLS: a message
// names a client's sites and the updates they are waiting on.
func loopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// safe cleans a string for a message: control bytes become U+FFFD and
// anything that looks like a secret is masked.
func safe(s string) string { return term.SafeText(secrets.Redact(s)) }
