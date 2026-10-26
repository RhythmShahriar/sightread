// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core/coretest"
)

const token = "SECRETTOKEN123"

// items is one of each kind: a HOLD on 14 sites whose top finding title
// carries a secret and an escape sequence, a new signal, an owner change
// and a closure.
func items() []Item {
	sites := make([]string, 14)
	for i := range sites {
		sites[i] = fmt.Sprintf("site%02d", i+1)
	}
	return []Item{
		{Kind: KindUpdate, Ecosystem: "wp-plugin", Name: "wpforms-lite", From: "1.9.1", To: "1.9.2", Verdict: "hold", Sites: sites,
			Severity: "critical", Findings: 3, Top: "Remote code fetched and run with " + coretest.FakeKey(coretest.KeyStripe) + "\x1b]0;PWNED\x07"},
		{Kind: KindNewSignal, Ecosystem: "npm", Name: "left-pad", From: "1.2.0", To: "1.3.0", Verdict: "review", Sites: []string{"api"},
			Severity: "high", Findings: 1, Top: "New install script <@everyone> **bold**"},
		{Kind: KindOwner, Ecosystem: "wp-plugin", Name: "share-kit", To: "3.2.0", Sites: []string{"shop", "blog"},
			Detail: "now growth-partners (was alice)"},
		{Kind: KindClosed, Ecosystem: "wp-plugin", Name: "gone", To: "2.0.0", Sites: []string{"shop"}, Detail: "security issue"},
	}
}

func message() Message {
	return New("agency", "1.0.0", "high", "/home/ann/.cache/rhythm/sightread/watch/agency/20261026T160000Z.json", "", items())
}

func TestText(t *testing.T) {
	want := "Sightread agency: 1 update to look at, 1 new signal on a version you already run, 1 owner change, 1 closed plugin or theme\n" +
		"\n" +
		"wpforms-lite 1.9.1 → 1.9.2 HOLD on 14 sites\n" +
		"  top finding: Remote code fetched and run with sk_l•••••�]0;PWNED�\n" +
		"new signal on a version you already run: left-pad 1.3.0 REVIEW on api\n" +
		"  top finding: New install script <@everyone> **bold**\n" +
		"owner change: share-kit 3.2.0 on 2 sites: now growth-partners (was alice)\n" +
		"closed on wordpress.org: gone 2.0.0 on shop: security issue\n" +
		"\nReport: /home/ann/.cache/rhythm/sightread/watch/agency/20261026T160000Z.json\n"
	if got := message().Text(func(s string) string { return s }); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}

	// Long lists end with a count instead of every line.
	var many []Item
	for i := range MaxListed + 3 {
		many = append(many, Item{Kind: KindUpdate, Name: fmt.Sprint("p", i), From: "1", To: "2", Verdict: "review"})
	}
	if got := New("", "", "high", "r.json", "", many).Text(func(s string) string { return s }); !strings.Contains(got, "…and 3 more\n") ||
		!strings.HasPrefix(got, "Sightread: 28 updates to look at\n") {
		t.Errorf("no cap:\n%s", got)
	}
	// A run that left packages out says so even with nothing to list.
	got := New("", "", "high", "r.json", "Partial: 2 packages were not checked", nil).Text(func(s string) string { return s })
	if got != "Sightread: nothing new\nPartial: 2 packages were not checked\n\n\nReport: r.json\n" {
		t.Errorf("incomplete:\n%q", got)
	}
}

func TestItemLineAddedPackage(t *testing.T) {
	it := Item{Kind: KindUpdate, Name: "axois", To: "1.0.0", Verdict: "hold"}
	if got := it.Line(); got != "axois new → 1.0.0 HOLD" {
		t.Errorf("Line() = %q", got)
	}
}

// listen opens a loopback listener on the cli lane's test ports.
func listen(t *testing.T) net.Listener {
	t.Helper()
	for port := 31112; port < 31116; port++ {
		if l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port)); err == nil {
			return l
		}
	}
	t.Fatal("no free port in 31112-31115")
	return nil
}

// receiver is an https server that records one request body.
func receiver(t *testing.T, status int) (*httptest.Server, chan []byte, chan string) {
	t.Helper()
	bodies, paths := make(chan []byte, 1), make(chan string, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies <- b
		paths <- r.URL.Path
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" ||
			!strings.HasPrefix(r.Header.Get("User-Agent"), "rhythm-sightread/") {
			t.Errorf("%s %s %s", r.Method, r.Header.Get("Content-Type"), r.Header.Get("User-Agent"))
		}
		w.WriteHeader(status)
	}))
	_ = srv.Listener.Close()
	srv.Listener = listen(t)
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, bodies, paths
}

func send(t *testing.T, scheme string, srv *httptest.Server) error {
	t.Helper()
	n, err := Parse(scheme+"://"+srv.Listener.Addr().String()+"/hooks/"+token, Options{HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(n.String(), token) || n.String() != scheme+"://"+srv.Listener.Addr().String() {
		t.Errorf("String() = %q", n.String())
	}
	return n.Send(context.Background(), message())
}

// clean checks a payload never carries what a chat channel must not see.
func clean(t *testing.T, body []byte) {
	t.Helper()
	for _, bad := range []string{coretest.FakeKey(coretest.KeyStripe), "\x1b", `\u001b`, token} {
		if strings.Contains(string(body), bad) {
			t.Errorf("payload holds %q:\n%s", bad, body)
		}
	}
}

func TestSlack(t *testing.T) {
	srv, bodies, paths := receiver(t, http.StatusOK)
	if err := send(t, "slack", srv); err != nil {
		t.Fatal(err)
	}
	body := <-bodies
	clean(t, body)
	if p := <-paths; p != "/hooks/"+token {
		t.Errorf("path %q", p)
	}
	var got struct {
		Text        string `json:"text"`
		UnfurlLinks *bool  `json:"unfurl_links"`
	}
	if err := json.Unmarshal(body, &got); err != nil || got.UnfurlLinks == nil || *got.UnfurlLinks {
		t.Fatalf("%v: %s", err, body)
	}
	for _, want := range []string{"wpforms-lite 1.9.1 → 1.9.2 HOLD on 14 sites", "New install script &lt;@everyone&gt; **bold**"} {
		if !strings.Contains(got.Text, want) {
			t.Errorf("text lacks %q:\n%s", want, got.Text)
		}
	}
}

func TestDiscord(t *testing.T) {
	srv, bodies, _ := receiver(t, http.StatusNoContent)
	if err := send(t, "discord", srv); err != nil {
		t.Fatal(err)
	}
	body := <-bodies
	clean(t, body)
	var got struct {
		Content  string `json:"content"`
		Username string `json:"username"`
		Mentions struct {
			Parse []string `json:"parse"`
		} `json:"allowed_mentions"`
		Flags int `json:"flags"`
	}
	if err := json.Unmarshal(body, &got); err != nil || got.Mentions.Parse == nil || len(got.Mentions.Parse) != 0 || got.Flags != 4 ||
		got.Username != "Rhythm Sightread" {
		t.Fatalf("%v: %s", err, body)
	}
	if !strings.Contains(got.Content, `New install script \<\@everyone\> \*\*bold\*\*`) {
		t.Errorf("content:\n%s", got.Content)
	}
	// Discord refuses content over 2000 characters.
	var many []Item
	for range 40 {
		many = append(many, Item{Kind: KindUpdate, Name: strings.Repeat("x", 120), From: "1", To: "2", Verdict: "hold"})
	}
	if c := discordBody(New("", "", "high", "r.json", "", many)).(map[string]any)["content"].(string); len([]rune(c)) > discordLimit {
		t.Errorf("content is %d characters", len([]rune(c)))
	}
}

// TestWebhookGolden: a receiver on 127.0.0.1 gets the grouped payload,
// one item per update, every text cleaned and masked.
func TestWebhookGolden(t *testing.T) {
	srv, bodies, _ := receiver(t, http.StatusAccepted)
	if err := send(t, "webhook+https", srv); err != nil {
		t.Fatal(err)
	}
	body := <-bodies
	clean(t, body)
	var pretty bytes.Buffer
	if err := json.Indent(&pretty, body, "", "  "); err != nil {
		t.Fatal(err)
	}
	pretty.WriteByte('\n')
	coretest.Golden(t, "webhook.json", pretty.Bytes())
}

func TestReceiverErrorsKeepTheURLSecret(t *testing.T) {
	srv, _, _ := receiver(t, http.StatusInternalServerError)
	if err := send(t, "slack", srv); err == nil || err.Error() != "receiver answered 500 Internal Server Error" {
		t.Errorf("err = %v", err)
	}
	// A receiver that redirects is an error, not a second POST elsewhere.
	redirect := httptest.NewUnstartedServer(http.RedirectHandler("https://elsewhere.test/", http.StatusFound))
	_ = redirect.Listener.Close()
	redirect.Listener = listen(t)
	redirect.StartTLS()
	defer redirect.Close()
	if err := send(t, "webhook+https", redirect); err == nil || !strings.Contains(err.Error(), "302") {
		t.Errorf("redirect: %v", err)
	}
	// A receiver that is down: net/http's error names the URL, ours doesn't.
	l := listen(t)
	addr := l.Addr().String()
	_ = l.Close()
	n, _ := Parse("discord://"+addr+"/api/webhooks/1/"+token, Options{})
	if err := n.Send(context.Background(), Message{}); err == nil || strings.Contains(err.Error(), token) {
		t.Errorf("down: %v", err)
	}
}

func TestParseErrors(t *testing.T) {
	slack := coretest.FakeKey(coretest.KeySlack)
	for raw, want := range map[string]string{
		"hooks.slack.com/services/" + token:                            "not a notification URL",
		"ftp://example.com/" + token:                                   `unsupported notification scheme "ftp"`,
		"slack://hooks.slack.com":                                      "slack://hooks.slack.com: the URL has no path",
		"slack:///services/" + token:                                   "no host",
		"webhook+http://hooks.example.com/" + token:                    "plain http is only for a receiver on this machine",
		"smtp://me:" + token + "@mail.example.com?to=a@b.c&from=t@b.c": "put the SMTP password in SIGHTREAD_SMTP_PASSWORD",
		"smtp://me@mail.example.com?to=a@b.c&from=t@b.c":               "set SIGHTREAD_SMTP_PASSWORD",
		"smtp://mail.example.com?from=t@b.c":                           "no to= address",
		"smtp://mail.example.com?to=a@b.c":                             "from=",
		"smtp://mail.example.com?to=nobody&from=t@b.c":                 "to=",
		"slack://hooks.slack.com/%zz" + token:                          "not a notification URL",
		strings.Replace(slack, "https://", "gopher://", 1):             `unsupported notification scheme "gopher"`,
	} {
		_, err := Parse(raw, Options{})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", raw, err, want)
		}
		if err != nil && (strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "/services/")) {
			t.Errorf("%s: error shows the token: %v", raw, err)
		}
	}
	// The positive cases: a loopback http receiver and the fake Slack URL.
	if n, err := Parse("webhook+http://127.0.0.1:31100/hook", Options{}); err != nil || n.String() != "webhook+http://127.0.0.1:31100" {
		t.Errorf("loopback http: %v %v", n, err)
	}
	if n, err := Parse(strings.Replace(slack, "https://", "slack://", 1), Options{}); err != nil || n.String() != "slack://hooks.slack.com" {
		t.Errorf("slack: %v %v", n, err)
	}
	if got := Redacted("smtp://me@mail.example.com:587?to=a@b.c"); got != "smtp://mail.example.com:587" {
		t.Errorf("Redacted = %q", got)
	}
	if got := Redacted("::"); got != "notification URL" {
		t.Errorf("Redacted = %q", got)
	}
}

// A title word that looks like a URL must not carry a masked link.
func TestDiscordEscapesURLLookalikes(t *testing.T) {
	for in, want := range map[string]string{
		"top: https://x[click](https://evil.test) now": `top: https://x%5Bclick%5D%28https://evil.test%29 now`,
		"see https://a.test/a_b?q=1 **now**":           `see https://a.test/a_b?q=1 \*\*now\*\*`,
		"https://a.test/<@everyone>":                   "https://a.test/%3C@everyone%3E",
	} {
		if got := discordEscape(in); got != want {
			t.Errorf("discordEscape(%q) = %q, want %q", in, got, want)
		}
	}
}

// A cut never leaves half an escape before the ellipsis.
func TestDiscordCutKeepsEscapes(t *testing.T) {
	for in, want := range map[string]string{`aa\`: `aa`, `aa\\`: `aa\\`, `aa\\\`: `aa\\`, `aa`: `aa`, ``: ``} {
		if got := cutEscape(in); got != want {
			t.Errorf("cutEscape(%q) = %q, want %q", in, got, want)
		}
	}
}
