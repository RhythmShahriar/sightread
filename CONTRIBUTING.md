# Contributing to Sightread

Setup, commit messages and the review process are shared by every Rhythm tool and live in the
[shared CONTRIBUTING](https://github.com/RhythmShahriar/.github/blob/master/CONTRIBUTING.md).
This page covers what is particular to Sightread: how a signal is added, how it is tested and the
rules that keep the fixtures and the fuzz corpus safe.

```sh
make hooks   # Conventional Commits check
make check   # lint + tests
make fuzz    # every fuzz target for 30s (FUZZTIME=10m for longer; SHARD=n SHARDS=m for a part)
make testbed # the fixture registries on 127.0.0.1, for end-to-end tests and the benchmark
```

Sightread builds with `GOWORK=off` against released versions of the Rhythm kit only; the Makefile
sets it for you.

## The one rule

Sightread never runs the code it downloads. No `php`, `node`, `npm`, `composer`, `git` or `svn`
on fetched content, no JavaScript, PHP or WASM engine, no install scripts. Fetched text is read,
diffed and analysed as text. `os/exec` is imported only by `internal/proc`. The packages that
start the user's own programs are the only ones that import `internal/proc` (`internal/exectest`
fails the build otherwise). A change that needs to run something from a package is a change to the product: open
an issue first.

## Signals

A signal is one entry in the catalogue (`core/catalog.go`) with an ID, a default severity and
confidence, a title and the ecosystems it applies to. It compares what the two versions can do,
not their lines: it fires when a capability is in the candidate and absent in the installed
version. Write titles about behaviour ("Fetches remote code and runs it"), never about intent
("malware", "backdoor").

Adding one takes four pieces:

1. **The catalogue entry** in `core/catalog.go`. IDs are kebab-case and never change once
   released, since allow entries, baselines and SARIF fingerprints name them.
2. **A detector** under `detect/code` (features of the code) or `detect/meta` (registry facts,
   archives, lockfiles). It reads the features the analyzer extracted from both sides and emits
   only what is new in the candidate. Comments, docs and test files never fire; the scorer
   lowers vendored paths.
3. **Explain text** in `detect/explain/<id>.yaml`: why it matters, how to review it, its false
   alarms in plain words, real incidents where they exist and the one-line advice printed under
   a finding. `make signals-doc` writes `docs/signals.md` from it; a test fails when the
   committed file is stale.
4. **Fixture pairs**, below.

### Fixture pairs

Every signal needs at least **3 positive and 3 negative pairs**. A pair is an old and a new
version of a package under `detect/testdata/pairs/<signal-id>/`:

- `pos-<n>/case.yaml`: the update the signal must catch, with `expect` naming the ID (and a
  minimum severity when it matters).
- `neg-<n>/case.yaml`: an update it must stay quiet on, with `forbid` naming the ID.
- At least one negative is a **look-alike** (`lookalike: true`): benign code that looks like the
  bad case, such as `json_decode` of a fetched body for `remote-fetch-exec`, a webpack runtime
  helper for `eval-dynamic` or a plugin filtering only its own update entry for
  `update-suppression`. This is the false-alarm guard of the signal, written as a test.

`TestEverySignalHasFixtures` walks the catalogue and fails the build when an ID has fewer pairs,
no look-alike or when a case names an unknown ID. Base your cases on what real updates do: the
false-alarm rate on real benign updates matters as much as the catch rate.

### Fake secrets

Never write a real-looking credential into a file, not even a revoked one: GitHub push protection
blocks the push and only the owner can allow it. Assemble fake keys at run time:

- in Go, `coretest.FakeKey(coretest.KeyNPM)` and the other kinds in `coretest.FakeKeyKinds()`, or
  build the string from parts (`"sk_" + "live_" + ...`);
- in a `case.yaml`, the placeholder `{{fakekey:npm}}`, expanded when the case loads.

Tests that check masking assert that the raw fake key appears in no output, log or report.

## Parsers and fuzzing

Everything a package or a registry sends is hostile input. Every parser of fetched or local text
(archives, lockfiles, readmes, changelogs, manifests, versions, the PHP and JavaScript lexers,
config and allow files) has a native Go fuzz target `Fuzz<Name>` next to its tests, with
invariants beyond "doesn't panic": paths stay under the root, limits hold, round trips are stable,
token text joins back to the input.

- Seed the corpus with `f.Add` from small `testdata` files. Keep seeds small and synthetic: no
  copied third-party code beyond a few lines, no real secrets, no live URLs other than
  `example.com`, `example.org`, `.test` hosts and `127.0.0.1`.
- A crasher found by `make fuzz` or the nightly run is committed under
  `testdata/fuzz/<FuzzName>/` with the fix, so it stays a regression test.
- CI runs each target for 30 seconds on every pull request and the nightly run for 10 minutes.

## Tests and the network

Tests never contact real sites or registries. Sources are tested against `httptest` servers or the
testbed's fixture registry on `127.0.0.1`; `coretest.LoopbackOnly` gives a transport that refuses
anything else. Fixture archives are built at test time from folders under `testdata/` and never
committed as zips or tarballs. Every user-visible message has a test asserting its exact text.

## Writing

Help, messages, docs and comments follow the Rhythm writing rules: short plain sentences, no em
dashes, no comma before "and" or "but", no AI attribution. `scripts/check-style.py` from the
shared `.github` repository checks them in CI. Every exported identifier and package has a doc
comment and every Go file starts with the copyright and `SPDX-License-Identifier: MIT` header.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/), header at most 72
characters, small and focused. The scope names the area of the tree:

| Scope | Area |
|---|---|
| `core` | shared types, the catalogue and registries |
| `fetch`, `archive`, `source`, `version` | downloads, archives, registries and version schemes |
| `inventory`, `diff` | what is installed, lockfiles and the tree diff |
| `lex`, `analyze`, `detect`, `data` | lexers, feature extraction, signals and data packs |
| `policy`, `score`, `report` | config and allow files, verdicts, writers |
| `cli`, `run`, `watch`, `stage` | commands, the review pipeline, watch and `--soundcheck` |
| `action`, `testbed`, `docs`, `ci`, `release`, `deps` | the GitHub Action, testbed, docs, workflows, packaging and dependencies |

`make hooks` enables the check locally; CI runs the same script on every commit and pull request
title.
