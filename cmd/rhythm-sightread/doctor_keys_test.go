// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/source/npm"
)

// keysRegistry serves body as the npm registry's /-/npm/v1/keys on a
// lane port and points SIGHTREAD_NPM_REGISTRY at it.
func keysRegistry(t *testing.T, body []byte) {
	t.Helper()
	ln := laneListener(t)
	srv := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/-/npm/v1/keys" {
			_, _ = w.Write(body)
			return
		}
		w.WriteHeader(http.StatusOK)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	t.Setenv("SIGHTREAD_NPM_REGISTRY", "http://"+ln.Addr().String())
	t.Setenv(npm.ExtraKeysEnv, "")
	t.Cleanup(core.SwapSource(core.NPM, func(env *core.Env) core.Source { return npm.New(env) }))
}

// TestDoctorNPMKeys runs doctor's key check through the real npm
// source: the registry's keys as pinned pass, one more key fails.
func TestDoctorNPMKeys(t *testing.T) {
	pinned, err := os.ReadFile(filepath.Join("..", "..", "source", "npm", "keys.json"))
	if err != nil {
		t.Fatal(err)
	}
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	extra := strings.Replace(string(pinned), `"keys": [`, `"keys": [{"expires": null, "keyid": "SHA256:mirror-own",
	  "keytype": "ecdsa-sha2-nistp256", "scheme": "ecdsa-sha2-nistp256", "key": "`+base64.StdEncoding.EncodeToString(der)+`"},`, 1)
	for _, c := range []struct {
		name, body, want string
		code             int
	}{
		{"pinned", string(pinned), "ok    npm keys: 2 keys of 127.0.0.1 match the set pinned in this build\n", cli.ExitOK},
		{"unknown key", extra, "FAIL  npm keys: 127.0.0.1 serves 1 signing key this build does not pin (SHA256:mirror-own); update Sightread\n", cli.ExitFindings},
	} {
		t.Run(c.name, func(t *testing.T) {
			world(t)
			doctorWorld(t)
			keysRegistry(t, []byte(c.body))
			code, out, _ := execute(t, "doctor", "--plain")
			if !strings.Contains(out, c.want) || code != c.code {
				t.Errorf("exit %d, want %d and %q in\n%s", code, c.code, c.want, out)
			}
		})
	}
}
