# Sightread testbed

The testbed is how Sightread is measured: 23 bad updates it must catch,
15 good updates it must stay quiet about and 15 environment scenarios
where the network, the cache or the machine around it goes wrong. Every
scenario runs through the real `rhythm-sightread` binary against
servers on 127.0.0.1 that play WordPress.org, Packagist, GitHub, npm and
OSV. Nothing reaches a real registry: every `SIGHTREAD_*` base points
at the fixture registry and `HTTPS_PROXY` points at a guard that closes
every connection.

The results are in [docs/benchmark.md](../docs/benchmark.md), written by
the benchmark and never by hand.

## Honest framing

We wrote Sightread and the testbed, so read this as a regression suite with a scoreboard, not an independent review. Every bad scenario is something we built Sightread to catch, modelled on real incidents (the 2026 WordPress.org plugin backdoor, Shai-Hulud). Every good scenario is a benign update that must stay quiet. The other tools run on the same fixtures, which are not real packages. A real attacker who reads our detectors can write code they miss; Sightread lowers the risk of an update, it does not prove an update is safe.

## Run it

Needs Go. Docker with Compose v2 is needed only for the `--soundcheck`
cases (e15) and the Soundcheck column.

```sh
make -C testbed bench                  # every scenario; writes docs/benchmark.md
make -C testbed bench BENCH="-only b01,g05,env"
make -C testbed up-wp                  # the Docker WordPress for e15
make -C testbed bench TOOLS=all        # also the Soundcheck column (slow)
make -C testbed reproduce              # the benchmark twice, outcomes diffed
make -C testbed test-bench             # the tagged bench tests (after up-wp for the Docker checks)
make -C testbed down
```

The benchmark (`go run -tags testbed ./testbed/bench`) builds
`bin/rhythm-sightread` from the checkout and starts its own registry,
canary, webhook receiver, probes, fronts and proxy guard, so stop a
`make up` first. It exits non-zero until every 1.0 target is met: every
non-pending bad scenario caught, zero false alarms on the good scenarios
and in a 10-round control pass, every run writing a report, zero
canary, egress, outside-write, unmasked-key and forwarded-token events,
every environment scenario passing, cold and warm runs agreeing, p01-large under 10 s warm
and 512 MB RSS, the whole run under 10 minutes. A run that wrote no
report (a crash, a usage error, a timeout) is shown as NO REPORT, apart
from misses and false alarms. A partial run (`-only`) never claims the
targets; it exits 0 when every scenario that ran passed.

e13 runs only on Windows, where Go ignores `SSL_CERT_FILE`. There the
registry serves plain HTTP on loopback (`-plain-http`, the default on
Windows), which Sightread accepts for a loopback mirror only. The
nightly `bench-windows` job runs
`go run -tags testbed ./testbed/bench -only e13 -plain-http`.

The tests behind it run the same way: `go test -tags testbed
./testbed/bench` or `make -C testbed test-bench` (TestGoodStateIsClean,
TestCanaryNeverFires, TestNoEgress, TestManifest, TestLargeFixture,
TestSoundcheckE15, TestRSSIsMeasured). The nightly bench job runs them
after `up-wp`, so the sealed Docker check runs there too. The
library parts (the registry, the manifest, the scoreboard, the page)
have ordinary tests that run with `go test ./...`.

### Run Sightread by hand

`make -C testbed up` starts the registry, the canary and the webhook in
the background. Then, from `testbed/`:

```sh
export SSL_CERT_FILE=$PWD/state/ca.pem SIGHTREAD_NPM_EXTRA_KEYS=$PWD/state/npm-keys.json
export SIGHTREAD_WPORG_API=https://127.0.0.1:18900 SIGHTREAD_WPDL_API=https://127.0.0.1:18900
export SIGHTREAD_WPSVN=https://127.0.0.1:18900/svn/plugins SIGHTREAD_WPTHEMESVN=https://127.0.0.1:18900/svn/themes
export SIGHTREAD_PACKAGIST=https://127.0.0.1:18901 SIGHTREAD_PACKAGIST_META=https://127.0.0.1:18901
export SIGHTREAD_GITHUB_API=https://127.0.0.1:18902 SIGHTREAD_GITHUB_CODELOAD=https://localhost:18908
export SIGHTREAD_NPM_REGISTRY=https://127.0.0.1:18903 SIGHTREAD_OSV_API=https://127.0.0.1:18904
export HTTPS_PROXY=http://127.0.0.1:23399 RHYTHM_NO_UPDATE_CHECK=1
../bin/rhythm-sightread plugin b01-widget --path projects/wp
```

`./toggle.sh b01 good` withholds b01's candidate (the update is then
already the latest); `./toggle.sh b01 bad` publishes it again. The
registry reads the state on every request, so nothing restarts.
`./toggle.sh status` lists the withheld ones.

## Ports

All on 127.0.0.1. `testbed/ports/ports.go` is the single source; a test
checks this table against it.

| Port | Service |
|---|---|
| 18900 | WordPress.org: info API, downloads, plugin checksums, SVN PROPFIND and GET |
| 18901 | Packagist: p2 metadata, maintainers, security advisories |
| 18902 | GitHub API: zipball redirect, git ref, rate limit |
| 18903 | npm: packuments, versions, tarballs, signing keys, audit advisories |
| 18904 | OSV: querybatch and vulns |
| 18905 | Canary: every bad payload would connect here; must stay silent |
| 18906 | Webhook receiver for watch notifications |
| 18907 | Docker WordPress for `--soundcheck` (e15), through the gate |
| 18908 | GitHub codeload, the zipball redirect target, reached as `localhost` (a second host name) |
| 23300-23339 | Probes and fronts for the environment scenarios |
| 23301 | Probe: a body that stalls |
| 23302 | Probe: an endless body |
| 23303 | Probe: 429 then 200 |
| 23304 | Probe: redirect to 169.254.169.254 |
| 23305 | Probe: self-signed TLS |
| 23310 | Probe: redirect to an unconfigured loopback port, hit-counted |
| 23311 | Nothing listens: the unconfigured port (e01 points npm here) |
| 23320 | Front: 429 with Retry-After on each path's first request (e02) |
| 23321 | Front: stalls every tarball body (e03, e08) |
| 23399 | Proxy guard: HTTPS_PROXY and HTTP_PROXY; closes every connection and counts it |

## Scenarios

`scenarios.yaml` holds each scenario's command, expected verdict, exit
code and signals. Bad scenarios must report every listed signal at or
above its severity; good scenarios must report nothing at or above their
gate beyond what is listed.

| ID | Kind | Update | Expected |
|---|---|---|---|
| b01 | bad | owner change, new cron that fetches and runs remote code | HOLD: owner-change, remote-fetch-exec, cron-new-hook, changelog-mismatch |
| b02 | bad | exfiltrates admin email, users and options on init | REVIEW: data-exfil, outbound-new-domain |
| b03 | bad | creates an administrator and hides it | HOLD: admin-user-hidden, admin-user-create |
| b04 | bad | grants manage_options to subscribers | REVIEW: capability-change |
| b05 | bad | layered decode that runs built code | HOLD: decode-exec |
| b06 | bad | unserializes a request cookie in a new handler | REVIEW: input-unserialize |
| b07 | bad | writes a mu-plugin and edits .htaccess | HOLD: write-outside-package |
| b08 | bad | PHP payload hidden in an asset and included | HOLD: code-in-asset |
| b09 | bad | theme serves fetched SEO spam to bots only | REVIEW: bot-cloaking, outbound-new-domain |
| b10 | bad | new postinstall that downloads and runs a script | HOLD: npm-install-script-new, remote-fetch-exec |
| b11 | bad | postinstall bundle reads .npmrc and the token | HOLD: npm-install-script-new, credential-access |
| b12 | bad | all maintainers replaced, a patch adds network code | REVIEW: owner-change, outbound-new-domain |
| b13 | bad | lock gains a typosquat with an install script | REVIEW: typosquat, dependency-new, npm-install-script-new |
| b14 | bad | lock resolved moved off the registry | REVIEW: lockfile-source-change |
| b15 | bad | new autoload.files that fetches and runs remote code | HOLD: composer-autoload-files, remote-fetch-exec |
| b16 | bad | becomes a composer-plugin with a post-install-cmd | REVIEW: composer-plugin-new |
| b17 | bad | registry serves a tampered archive | HOLD: integrity-mismatch |
| b18 | bad | same version, fresh bytes after an allow | HOLD: approved-version-changed |
| b19 | bad | composer tag moved to another commit | HOLD: version-republished |
| b20 | bad | fresh dependency with a postinstall, no provenance, no tag | HOLD: dependency-new, fresh-release, provenance-dropped, git-tag-missing |
| b21 | bad | Essential Plugin replay | HOLD: input-unserialize, eval-dynamic, rest-open-route, changelog-mismatch, owner-change |
| b22 | bad | Gravity Forms pattern reviewed from a vendor zip | UNVERIFIED: admin-user-create, update-suppression, outbound-new-domain |
| b23 | bad | Trojan Source bidi plus an obfuscated blob | REVIEW: unicode-hidden, obfuscation |
| g01 | good | large feature release with real permission callbacks | nothing at or above medium |
| g02 | good | rebuilt minified bundle | nothing at or above medium |
| g03 | good | thirty translation files added | nothing at or above medium |
| g04 | good | bundled Guzzle bumped in vendor | nothing at or above medium |
| g05 | good | documented daily cleanup cron | nothing at or above medium beyond cron-new-hook (low) |
| g06 | good | a contributor added, all old ones stay | nothing at or above medium |
| g07 | good | theme CSS and templates only | nothing at or above medium |
| g08 | good | line endings switched to LF | nothing at or above medium |
| g09 | good | npm patch, same maintainers, no scripts | nothing at or above medium |
| g10 | good | native addon, unchanged node-gyp install | nothing at or above medium |
| g11 | good | popular dependencies added | nothing at or above medium |
| g12 | good | GitHub dist with empty shasum, source unchanged | nothing at or above medium |
| g13 | good | composer minor with a new class and tests | nothing at or above medium |
| g14 | good | whole site, every package on its good candidate | nothing at or above medium |
| g15 | good | official takeover, code unchanged, owner-change only | exactly owner-change |
| e01 | env | registry down | exits could-not-fetch, never a clean verdict |
| e02 | env | 429 then success | retries with Retry-After and succeeds |
| e03 | env | body stalls | stops at the configured timeout |
| e04 | env | zip bomb | stops at the archive limits, within the memory cap |
| e05 | env | hostile archive entries | reports each entry, writes nothing outside the work folder |
| e06 | env | cached blob tampered on disk | detects on reuse and refetches |
| e07 | env | two runs share one cache | both runs correct, no corrupt cache |
| e08 | env | Ctrl-C during fetch | no partial cache entry, temp removed |
| e09 | env | offline with a warm cache | works and says it is offline |
| e10 | env | read-only HOME | clear error or a temp cache fallback |
| e11 | env | private host namesake and private npm scope | no request names the private host, the namesake or the scope |
| e12 | env | version unpublished from npm | says the version was unpublished |
| e13 | env | Windows run catches b10 | runs on Windows only (nightly bench-windows) |
| e14 | env | bidi and ANSI escapes in the name and changelog | prints the escapes escaped, never raw |
| e15 | env | --soundcheck on the Docker WordPress with the Roadie stub | applied only on the staging copy; each refusal exits before any change |

e15 runs eight cases (`testbed/staging`): one that applies the update
with the real `rhythm-soundcheck` (not run when it is not on PATH) and
seven refusals: a HOLD, a production target, Roadie failed, stale,
unsealed or missing and a remote `--wp` prefix. Each refusal must leave
the container's plugin and the host project byte-identical. The Roadie
stub (`testbed/stubs/roadie`) answers the contract of
[docs/roadie-contract.md](../docs/roadie-contract.md) with the outcome
written to `state/roadie`.

## Add a scenario

1. Make `packages/<id>-<name>/` with `meta.yaml` (ecosystem, name, the
   installed and the candidate version, owners, scripts, publish times)
   and the two trees `old/` and `new/`. A bad payload stays a short
   inline snippet in the shape of the incident that targets the
   canary: it connects to 127.0.0.1:18905 and writes
   `$SIGHTREAD_CANARY_DIR/<id>`.
2. Install the old version in `projects/wp` (or pin it in a lockfile
   there) when the command reads the project.
3. Add the entry to `scenarios.yaml`: the command after
   `rhythm-sightread`, the expected verdict, exit code and signals (each
   an ID of the signal catalogue); add `pending` with a note while its
   detector is not merged.
4. Add a row to the table above, then run `go test ./testbed/...` (the
   manifest, catalogue and fake-secret checks) and
   `make -C testbed bench BENCH="-only <id>"`.

## Fake secrets

Some payloads steal a token, so the fixtures need key-shaped strings. No
real-format key is ever committed: GitHub push protection blocks them
and only the owner can allow one. A fixture writes a placeholder such as
`{{fakekey:npm}}`; the registry expands it when it builds the archive,
with the same runtime assembly as `coretest.FakeKey` (a test compares
the two for every kind). b11's payload falls back to `{{fakekey:npm}}`.
A test scans every fixture for literal key prefixes. The benchmark
searches every output and report for the assembled keys: one found in
full is counted as an unmasked key.

Sightread runs with a fake `GITHUB_TOKEN` assembled the same way. The
token belongs to the GitHub API only (PRD 11). The zipball redirect
points at codeload under a second host name, `localhost`, while the API
is `127.0.0.1`: an HTTP client copies `Authorization` across a redirect
to the same host name on another port, so a shared name would hide a
forwarded token. The request log records whether each request carried
an `Authorization` header (a boolean, never the value) and the benchmark
counts every codeload request that did.

## Why archives are never committed

The registry builds every zip and tarball at start from `old/` and
`new/`, computes the checksums each ecosystem publishes and signs every
npm version with an ECDSA P-256 key generated for that run. Committed
archives would hide what changed in review, could carry a real-format
key past the scan and would pin a signing key in the repository. The
trees are the source; `state/` (archives built for `--from-file`, the
CA, the npm keys, the request log) is ignored by git.

## Real releases

`make -C testbed corpus` is owner-run and needs network: it fetches the
50 WordPress.org plugins and 50 npm packages pinned by hash in
`corpus/corpus.lock`, reviews each pair and writes the real-release
section of docs/benchmark.md. It is never part of `make bench` or CI.
The lock ships with the versions and no hashes yet: the first
`make -C testbed corpus PIN=1` records the SHA-256 of each archive, the
owner commits the lock; every later fetch must match it.
