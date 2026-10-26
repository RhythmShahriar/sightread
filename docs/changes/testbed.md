# Testbed lane: what it runs and what it relies on

This page records what the testbed lane (`testbed/`, `docs/benchmark.md`,
`.github/action-test/`, `.github/workflows/action-test.yml` and
`.github/workflows/nightly.yml`) adds. None of it changes the
`rhythm-sightread` binary. It is how Sightread is measured, so the
integrator checks the flags, texts and variables below against the
other lanes. The testbed's own guide is [testbed/README.md](../../testbed/README.md);
the results are in [docs/benchmark.md](../benchmark.md).

## Run the testbed and the benchmark

Needs Go. Docker with Compose v2 only for e15 and the Soundcheck column.
Nothing contacts a real registry: every base points at 127.0.0.1 and
every proxy variable at a guard that closes each connection.

```sh
make -C testbed up                     # registry, canary and webhook in the background
make -C testbed up-wp                  # the sealed Docker WordPress for e15
make -C testbed bench                  # every scenario; writes docs/benchmark.md
make -C testbed bench BENCH="-only b01,g05,env"
make -C testbed bench TOOLS=all        # also the Soundcheck column (slow)
make -C testbed reproduce              # the benchmark twice, outcomes diffed
make -C testbed test-bench             # the tagged bench tests (after up-wp for the Docker checks)
make -C testbed toggle ID=b01 STATE=good
make -C testbed down
make test-integrated                   # every test; a stage not linked fails
```

`make -C testbed bench` runs `go run -tags testbed ./testbed/bench`,
which builds `bin/rhythm-sightread` and starts its own registry, canary,
webhook, probes, fronts and proxy guard (stop a `make up` first). Flags:
`-bin`, `-build`, `-out` (default `docs/benchmark.md`), `-work` (default
`testbed/bench/work`), `-results`, `-only` (ids, `bad`, `good` or `env`),
`-tools` (`auto`, `all`, `none` or names), `-rounds` (default 10),
`-timeout` (default 2m), `-large`, `-plain-http` (default on Windows),
`-diff a.json b.json`. It prints `bench: NOT MET: <target> (<detail>)`
per failed target or `bench: every 1.0 target met`. Exit codes: 0 every
target met, 1 a target not met, 2 a setup error. A partial run (`-only`)
never claims the targets: it prints `bench: partial run (-only): every
scenario that ran passed; the 1.0 targets are not claimed` and exits 0,
or `bench: partial run (-only): failed: <ids>` and exits 1.

`-plain-http` serves the registry and the fronts over plain HTTP on
loopback, sets every base to `http://127.0.0.1:<port>`, leaves
`SSL_CERT_FILE` unset and runs no compared tool. Go ignores
`SSL_CERT_FILE` on Windows, so e13 runs this way there.

A scenario whose run wrote no report (a crash, a usage error, a
timeout) has the status `no-report`, shown as `NO REPORT` in its own
scoreboard section and never as a miss or a false alarm.

## Ports

All on 127.0.0.1; `testbed/ports/ports.go` is the single source and a
test keeps the README table equal to it.

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
| 23301 to 23305 | Probes: stalled body, endless body, 429 then 200, redirect to 169.254.169.254, self-signed TLS |
| 23310, 23311 | Probe: redirect to an unconfigured port (hit-counted); nothing listens on 23311 |
| 23320 | Front: 429 with Retry-After on each path's first request (e02) |
| 23321 | Front: stalls every tarball body (e03, e08) |
| 23399 | Proxy guard: every proxy variable points here |
| 31121 | Payload sink of the headless HTML check (`testbed/htmlcheck_test.go`) |
| 31130 to 31136 | Release mirrors in `action-test.yml` (CI runners only) |

## Scenarios

`testbed/scenarios.yaml` holds each command, verdict, exit code and
signals. Bad scenarios must report every listed signal at or above its
severity; good scenarios nothing at or above their gate beyond what is
listed.

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
| b12 | bad | all maintainers replaced, a patch adds network code | HOLD: owner-change, outbound-new-domain |
| b13 | bad | lock gains a typosquat with an install script | HOLD: typosquat, dependency-new, npm-install-script-new |
| b14 | bad | lock resolved moved off the registry | REVIEW: lockfile-source-change |
| b15 | bad | new autoload.files that fetches and runs remote code | HOLD: composer-autoload-files, remote-fetch-exec |
| b16 | bad | becomes a composer-plugin with a post-install-cmd | REVIEW: composer-plugin-new |
| b17 | bad | registry serves a tampered archive | HOLD: integrity-mismatch |
| b18 | bad | same version, fresh bytes after an allow | HOLD: approved-version-changed |
| b19 | bad | composer tag moved to another commit | HOLD: version-republished |
| b20 | bad | fresh dependency with a postinstall, no provenance, no tag | REVIEW: dependency-new, fresh-release, provenance-dropped, git-tag-missing |
| b21 | bad | Essential Plugin replay | HOLD: input-unserialize, eval-dynamic, rest-open-route, changelog-mismatch, owner-change |
| b22 | bad | Gravity Forms pattern reviewed from a vendor zip | UNVERIFIED: admin-user-create, update-suppression, outbound-new-domain |
| b23 | bad | Trojan Source bidi plus an obfuscated blob | REVIEW: unicode-hidden, obfuscation |
| g01 | good | large feature release with real permission callbacks | ROUTINE |
| g02 | good | rebuilt minified bundle | ROUTINE |
| g03 | good | thirty translation files added | ROUTINE |
| g04 | good | bundled Guzzle bumped in vendor | ROUTINE |
| g05 | good | documented daily cleanup cron | ROUTINE: cron-new-hook |
| g06 | good | a contributor added, all old ones stay | ROUTINE |
| g07 | good | theme CSS and templates only | ROUTINE |
| g08 | good | line endings switched to LF | ROUTINE |
| g09 | good | npm patch, same maintainers, no scripts | ROUTINE |
| g10 | good | native addon, unchanged node-gyp install | ROUTINE |
| g11 | good | popular dependencies added | REVIEW: dependency-new only, no typosquat |
| g12 | good | GitHub dist with empty shasum, source unchanged | ROUTINE |
| g13 | good | composer minor with a new class and tests | ROUTINE |
| g14 | good | whole site, every package on its good candidate | ROUTINE, exit 3: b22 not-wporg and core Not checked |
| g15 | good | official takeover, code unchanged, owner-change only | REVIEW: owner-change |
| e01 | env | registry down | exit 3 |
| e02 | env | 429 then success | exit 0 |
| e03 | env | body stalls | exit 3 |
| e04 | env | zip bomb | exit 0: unanalysed |
| e05 | env | hostile archive entries | exit 0: archive-path-escape, archive-link, archive-collision |
| e06 | env | cached blob tampered on disk | exit 0 |
| e07 | env | two runs share one cache | exit 0 |
| e08 | env | Ctrl-C during fetch | exit 130 |
| e09 | env | offline with a warm cache | exit 0 |
| e10 | env | read-only HOME | exit 0 |
| e11 | env | private host namesake and private npm scope | exit 0 |
| e12 | env | version unpublished from npm | exit 2, says the version was unpublished |
| e13 | env | Windows run catches b10 | exit 0 |
| e14 | env | bidi and ANSI escapes in the name and changelog | exit 0 |
| e15 | env | --soundcheck on the Docker WordPress with the Roadie stub | exit 0 |

e15 runs eight cases: `applies` (exit 0, the update lands on the staging
copy only; not run without `rhythm-soundcheck` on PATH) and seven
refusals, each of which must leave the container's plugin and the host
project byte-identical: `hold` (exit 1, E17), `production` (exit 2,
E14), `roadie-failed`, `roadie-stale`, `roadie-unsealed` and
`roadie-missing` (exit 3, E15) and `remote-wp` (exit 2, E21, the text
names `--apply`).

## Benchmark targets

The bench exits non-zero until each is met; `docs/benchmark.md` shows
them in this order.

| Target | Measured as |
|---|---|
| Every non-pending bad scenario caught | each listed signal at or above its severity in the JSON report |
| Zero false alarms on good scenarios | nothing at or above the gate beyond the listed signals |
| Every run wrote a report | no scenario with the status `no-report` |
| Exit codes, verdicts and Not checked as expected | the manifest's `expect` per scenario |
| Zero false alarms in the control pass | 10 rounds of every good scenario |
| Zero canary, egress, outside-write, unmasked-key and forwarded-token events | canary connections and files, proxy guard lines, tree snapshots, the fixtures' fake keys found in full in any output or report, codeload requests that carried an `Authorization` header (the bench sets a fake `GITHUB_TOKEN`) |
| Every environment scenario passes | each `env` block, e15's eight cases; e13 is "not run" on Linux and runs in the nightly `bench-windows` job |
| Cold and warm runs agree | the same outcome from an empty and a warm cache |
| p01-large under 10 s warm and 512 MB RSS | 4,000 files of about 10 KB, rusage of the child |
| Full benchmark under 10 minutes | wall time of the whole run |

Real-release numbers come from `make -C testbed corpus` (owner only,
needs network) and fill the block between `<!-- corpus:start -->` and
`<!-- corpus:end -->`; they are never part of `make bench` or CI.

## What the testbed relies on from other lanes

Every run gets a fresh environment: only PATH, LANG, TZ, the Windows
process variables and the Docker client variables come from the caller.
The rest:

| Variable | Value | Lane that must honour it |
|---|---|---|
| `SIGHTREAD_WPORG_API`, `SIGHTREAD_WPDL_API` | `https://127.0.0.1:18900` | fetch (source/wporg), cli |
| `SIGHTREAD_WPSVN` | `https://127.0.0.1:18900/svn/plugins` | fetch |
| `SIGHTREAD_WPTHEMESVN` | `https://127.0.0.1:18900/svn/themes` | fetch |
| `SIGHTREAD_PACKAGIST`, `SIGHTREAD_PACKAGIST_META` | `https://127.0.0.1:18901` | fetch (source/packagist) |
| `SIGHTREAD_GITHUB_API` | `https://127.0.0.1:18902` | fetch (source/github) |
| `SIGHTREAD_GITHUB_CODELOAD` | `https://localhost:18908` | fetch (source/github) |
| `SIGHTREAD_NPM_REGISTRY` | `https://127.0.0.1:18903`; e01 `:23311`, e02 `:23320`, e03 and e08 `:23321` | fetch (source/npm) |
| `SIGHTREAD_OSV_API` | `https://127.0.0.1:18904` | fetch (source/osv) |
| `SIGHTREAD_NPM_EXTRA_KEYS` | `testbed/state/npm-keys.json`, the run's npm signing key | fetch (source/npm) |
| `SSL_CERT_FILE` | `testbed/state/ca.pem`, the registry's CA | fetch (Go's system pool reads it on Linux only; macOS and Windows use the OS store, so the bench and the Action test run on Linux and e13 runs on Windows with `-plain-http`, where every base is `http://127.0.0.1:<port>` and this is unset) |
| `HTTPS_PROXY`, `HTTP_PROXY`, `ALL_PROXY` and lower case | `http://127.0.0.1:23399` | fetch: a forgotten base must reach the guard |
| `NO_PROXY`, `no_proxy` | `127.0.0.1,localhost,::1` | fetch: loopback bases bypass the proxy |
| `RHYTHM_CACHE_DIR` | `testbed/bench/work/cache/<id>` | cli, fetch (blobs under a `blobs` folder; e06 tampers there) |
| `RHYTHM_CONFIG_DIR`, `HOME`, `TMPDIR`, `TMP`, `TEMP` | inside `testbed/bench/work` | cli |
| `RHYTHM_NO_UPDATE_CHECK`, `NO_COLOR` | `1` | kit, output |
| `RHYTHM_OFFLINE` | `1` in e09's offline run | cli |
| `SIGHTREAD_CANARY_DIR` | `testbed/state/canary` | none: only the fixture payloads read it |
| `TESTBED_STATE` | `testbed/state` | none: the Roadie stub reads it |
| `SIGHTREAD_REQUIRE_LINKED` | `1` in `make test-integrated` and the nightly | core/coretest |
| `SIGHTREAD_CHROME` | optional path to Chrome for the headless HTML check | none |

Flags the bench and corpus pass, with the meaning they assume: `--fail-on`,
`-o <file>.json`, `--no-color`, `--plain`, `--timeout`, `--retries`,
`--offline`, `--from-file` and `--to-file` (a folder, zip or tgz),
`--allow-unverified`, `--only` (one comma list of `<eco>:<name>` globs),
`--transitive`, `--soundcheck`, `--wp`, `changes --before --after`,
`all <path>`, `watch -l --once --now --dir`, `--version`. Exit codes as
PRD 10: 0, 1, 2, 3 and 130 after Ctrl-C (e08).

## Action test (`.github/workflows/action-test.yml`)

Runs the composite Action (`uses: ./`) on GitHub's runners against the
fixture registry. `.github/action-test/release.sh build` builds this
commit as `rhythm-sightread_linux_amd64.tar.gz` with `checksums.txt`
(version `0.0.0-actiontest`), `serve.sh release` serves it on 127.0.0.1
for the `download-url` input and `serve.sh registry` starts the
registry and writes the variables above to `$GITHUB_ENV`. `pr.sh make`
builds a repository whose base branch `sr-base` pins leftpadplus 1.0.0
and whose head moves it to 1.0.1 and adds expresss (the b13 pair; a test
keeps the copies equal). Jobs:

- `changes`: mode changes with `base: sr-base` and `sarif: true`. The
  step fails (the gate) and must set `exit-code` 1, `verdict` hold or
  review, `updates` 2, `findings` at least 3, `report` (a
  `rhythm-sightread/v1` JSON with both packages), `sarif-file` (SARIF
  2.1.0 with results) and `version` `0.0.0-actiontest`; the `summary`
  output and the job summary hold a `## Sightread: ` heading. The
  report's envelope `verdict` must be `findings` and the `verdict`
  output must equal the worst per-update verdict in
  `.data.updates[].verdict` (hold before review).
- `pr-allow` (SR-61): the head adds `.sightread/allowed.yaml` with both
  reviewed hashes. Without `trust-pr-allow`: `exit-code` 1, verdict not
  allowed, `summary.allowed` 0 and `allowed in this change, not counted`
  in the report. With `trust-pr-allow: true`: `exit-code` 0, verdict
  `allowed`, `summary.allowed` 2.
- `tampered-release` (SR-17, SR-81): a `checksums.txt` that no longer
  matches the archive (with `verify-signature: false`) and a signature
  bundle that signs nothing (signature on) must both fail the step with
  no `exit-code` and no `rhythm-sightread` on PATH. Every job here
  stays on 127.0.0.1; the case with a real signed release runs in the
  nightly `signed-release` job.
- `comment-read-only` (pull requests only, `contents: read` alone):
  `comment: true` with `fail-on: none` passes with `exit-code` 0 and no
  `comment-id`. The job then runs the Action's `scripts/comment.sh post`
  again with the same token and fails unless it printed a line starting
  `::warning::Sightread: couldn't` and ending `on the pull request` and
  wrote no `comment-id`.

## Nightly (`.github/workflows/nightly.yml`)

Daily at 02:41 UTC and on demand, read-only token:

- `fuzz`: six jobs, `make fuzz FUZZTIME=10m SHARD=<0-5> SHARDS=6`,
  each running every sixth target (timeout 180 minutes); a target that
  finds a crasher doesn't stop the rest of its shard. On failure every
  new file under a `testdata/fuzz/` folder is uploaded as the artifact
  `fuzz-crashers-<shard>`.
- `integrated`: `SIGHTREAD_REQUIRE_LINKED=1 go test -race ./...` (what
  `make test-integrated` runs; Windows runners have no make) on Ubuntu,
  macOS and Windows.
- `bench`: `make -C testbed up-wp`, `make -C testbed test-bench` (the
  tagged bench tests, including the sealed Docker egress check),
  `make -C testbed bench`, `make -C testbed reproduce`, then
  `docs/benchmark.md` and the results JSON uploaded as the artifact
  `benchmark` (never committed), then `make -C testbed down`.
- `bench-windows`: on windows-latest, `go run -tags testbed
  ./testbed/bench -only e13 -plain-http -tools none -rounds 0
  -large=false`, then fails unless e13's result is `pass`; the page and
  results are uploaded as the artifact `benchmark-windows`.
- `signed-release` (SR-17, SR-81): from the first release on, the
  latest signed release is downloaded from GitHub, served on 127.0.0.1
  with its archive and `checksums.txt` line swapped for this commit's
  build and must be refused; the untouched release then installs from
  the same kind of mirror. It is the only CI step that reaches a real
  service (the GitHub release API), which is why it is not on every
  push.

## Link check and headless HTML check

- `testbed/linkcheck_test.go`: `TestLinkListMatchesBinary` (always runs)
  fails when its blank imports differ from
  `cmd/rhythm-sightread/imports.go`. `TestAllStagesLinked` (only with
  `SIGHTREAD_REQUIRE_LINKED=1`) fails on any stage not registered, any
  detector signal outside the catalogue or emitted by policy, any detect
  signal no detector lists and any signal without explain text, one line
  each, for example `differ not linked`, `no detector emits
  remote-fetch-exec`, `eval-dynamic has no explain text`.
- `testbed/htmlcheck_test.go` (T-51, dynamic part): writes the HTML
  report of a sample whose package text is script tags, event handlers,
  `javascript:` links, remote images, frames, stylesheets and a meta
  refresh, opens it from a file in headless Chrome and fails on any
  payload that ran or any request to the sink. A control page with the
  same payloads unescaped must trip both first. Skips with `-short`,
  until the HTML writer is linked, or when no Chrome is found
  (`SIGHTREAD_CHROME`, PATH, the usual install folders, rod's Chromium
  that rhythm-soundcheck downloads).
