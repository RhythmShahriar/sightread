<h1 align="center">♪ rhythm sightread</h1>

<p align="center">
  <b>What will this update really change?</b><br>
  Read the update before you install it. Sightread diffs the version you have against the one you would get from the official source and tells you, in plain words, what is new: network calls, code execution, admin users, install scripts, a new owner. It never runs the code.
</p>

<p align="center">
  <a href="https://github.com/RhythmShahriar/sightread/releases/latest"><img alt="Release" src="https://img.shields.io/github/v/release/RhythmShahriar/sightread?style=flat-square&color=ff7c52&label=release"></a>
  <a href="https://github.com/RhythmShahriar/sightread/actions/workflows/ci.yml"><img alt="CI" src="https://img.shields.io/github/actions/workflow/status/RhythmShahriar/sightread/ci.yml?branch=master&style=flat-square&label=ci"></a>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/badge/license-MIT-100f0d?style=flat-square"></a>
  <a href="go.mod"><img alt="Go" src="https://img.shields.io/github/go-mod/go-version/RhythmShahriar/sightread?style=flat-square&color=100f0d"></a>
</p>

<p align="center">
  <a href="#install">Install</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#what-it-checks">What it checks</a> ·
  <a href="#honest-limits">Honest limits</a> ·
  <a href="https://github.com/RhythmShahriar/rhythm/wiki/Sightread">Docs</a> ·
  <a href="https://github.com/RhythmShahriar/rhythm/wiki/Sightread-CI">CI</a>
</p>

<!-- Screenshot: replaced at release with a frame of a real `rhythm sightread demo` run
     (CLICOLOR_FORCE=1 COLORTERM=truecolor, DejaVu Sans Mono). -->

WordPress.org plugins and themes, Composer and npm, in one local, free tool. It diffs only what changed, ranks it, explains it and keeps a review record you commit next to your code.

## The Rhythm set

| | Asks | Checks |
|---|---|---|
| [Tuner](https://github.com/RhythmShahriar/tuner) | Is my site safe? | what an attacker can find |
| [Soundcheck](https://github.com/RhythmShahriar/soundcheck) | Did my change break anything? | what visitors see and do |
| [Echo](https://github.com/RhythmShahriar/echo) | Is my site still saying what it should? | everything the site sends |
| [Roadie](https://github.com/RhythmShahriar/roadie) | Is my staging a safe copy of production? | the copy you test on |
| **Sightread** | **What will this update really change?** | **the code an update brings** |

All five run through [rhythm](https://github.com/RhythmShahriar/rhythm), one CLI that installs, updates and verifies them. They work on the same change: Tuner says a plugin needs updating, Sightread reads the update, Roadie gives you a safe staging copy, Soundcheck shows what the update did to the pages and Echo what it did to the messages.

## Install

```sh
rhythm install sightread
```

That needs rhythm 0.9.0 or later (`rhythm update` gets it). No `rhythm` yet? `curl -fsSL https://rythm.sh/install | sh` on macOS and Linux, `irm https://rythm.sh/install.ps1 | iex` in Windows PowerShell. With Go: `go install github.com/RhythmShahriar/sightread/cmd/rhythm-sightread@latest`.

`rhythm-sightread` works on its own; `rhythm sightread` (or `rhythm sr`) is the same tool through the rhythm CLI. `rhythm-sightread --help` lists every command and `rhythm-sightread help <command>` every flag of one.

## Quick start

```sh
rhythm sr demo                              # three built-in updates, no network, a few seconds
rhythm sr plugin akismet --from 5.3.3       # one WordPress.org plugin, installed 5.3.3 against the latest
rhythm sr all /var/www/shop                 # every available update in a site or project
rhythm sr init ci                           # a GitHub workflow that reviews lockfile changes in pull requests
```

`demo` serves three made-up updates from memory on 127.0.0.1 and reviews them: one routine, one that copies a real plugin takeover and one npm package with a new install script and a look-alike dependency. Nothing in them ever runs.

Each update gets a verdict:

| Verdict | Means |
|---|---|
| **HOLD** | a critical finding: don't install it before you have read it |
| **REVIEW** | a high or medium finding worth a look |
| **ROUTINE** | only low or info findings, or none |
| **ALLOWED** | every finding is covered by a review you recorded for these exact bytes |
| **UNVERIFIED** | Sightread couldn't check where the bytes came from, so it didn't diff them (unless `--allow-unverified`) |

| You want to… | Run |
|---|---|
| Review a theme | `rhythm sr theme astra --path /var/www/shop` |
| Review the Composer updates a project can take | `rhythm sr composer --path api` |
| Review one npm package at a given version | `rhythm sr npm axios --to 1.7.9` |
| See which versions exist | `rhythm sr plugin akismet --to list` |
| Review a premium plugin from the vendor's zip | `rhythm sr plugin gravityforms --to-file ~/zips/gravityforms-2.9.1.zip` |
| Gate a pull request that moves lockfiles | `rhythm sr changes --base origin/main --fail-on high --md` |
| A report to read or send | `rhythm sr all -o review.html --open` |
| What a signal means and how to review it | `rhythm sr explain remote-fetch-exec` |
| Record that you reviewed a version | `rhythm sr allow npm:sharp@0.33.5 --reason "known install script"` |
| Review every site of a fleet once per update | `rhythm sr all --sites sites.yaml` |
| Check every site each night and get told what is new | `rhythm sr watch -l sites.yaml --at 02:00 --notify slack://hooks.slack.com/services/T0/B0/XXXX` |
| Install it on staging and compare before and after | `rhythm sr plugin woocommerce --soundcheck https://staging.shop.test --wp "wp --path=/srv/staging"` |
| Check sources, cache, tokens and helpers | `rhythm sr doctor` |

Without a site, `--from` names the installed version. With one, Sightread reads it from `--path`, from a WP-CLI command (`--wp "ssh deploy@host -- wp --path=/srv/www"`), from a Tuner report (`--from-tuner tuner.json`) or from the lockfile. Every flag is in the [CLI reference](https://github.com/RhythmShahriar/rhythm/wiki/Sightread-CLI-Reference).

### Record a review

`allow` writes `.sightread/allowed.yaml`. Each entry binds to the sha256 of the archive you reviewed, so the same version with other bytes is the critical finding `approved-version-changed`, never allowed. Commit the file; in CI the Action reads it from the base branch, so a pull request can't allow its own update unless you pass `trust-pr-allow`. The same goes for `.sightread/config.yaml` and a committed `--baseline`: an ignore entry, `osv: false`, a new mirror or another setting the pull request relaxes counts only once it is merged. The report notes each one.

```sh
rhythm sr allow --from review.json --reason "reviewed in PR 412"
rhythm sr allow list
```

## What it checks

Sightread compares what the two versions can do, not their lines. A signal fires when a capability is in the new version and not in the old one, so reformatting, minifying and line endings stay quiet. `rhythm sr signals` lists all 48 signals and `rhythm sr explain <signal-id>` explains each one.

| Group | Signals |
|---|---|
| Bytes and where they came from | archive differs from the published hash, same version with other bytes, allowed version with a new hash, lockfile entry moved off the registry, npm provenance dropped, no git tag for the release |
| Code that runs | fetches remote code and runs it, decodes hidden code and runs it, code built at run time (`eval`, variable functions), large encoded blobs, `unserialize` of request or remote data, code hidden in images and fonts, Trojan Source characters |
| WordPress powers | creates or hides administrators, grants admin capabilities, blocks other updates, REST routes anyone can call, new cron tasks, content shown only to search engines |
| Data and files | writes outside its own folder (`wp-config.php`, `.htaccess`, mu-plugins, `~/.npmrc`), reads credentials and tokens, sends site data to a new host, contacts a new domain, adds a secret (shown masked) |
| Install time | new npm install scripts, Composer plugins and script hooks, `autoload.files`, new dependencies, names one typo from a popular package, private names that also exist publicly (`--check-confusion`) |
| Who and when | new owner, committer or publisher, closed on WordPress.org, released in the last 72 hours, first release after a year of silence, abandoned, license changed |
| Known records | listed as malicious or vulnerable by [OSV](https://osv.dev) |
| The archive itself | entries that escape the package, links and special files, duplicate names, code too large or too strange to read, size far above the usual |
| Context | changelog that doesn't mention what the code adds, installed copy differs from the official one, PHP requirement moved, security files removed |

An owner change raises the code signals of the same update. Findings in tests, docs and vendored folders are lowered one level. `--min-confidence confirmed` keeps only exact patterns.

### Verified by

Sightread diffs bytes only after they match what the source publishes. The report says what that meant for each source, never "verified as safe":

| Source | What "verified" means |
|---|---|
| npm | matches the hash and signature the npm registry publishes |
| WordPress.org plugins | matches WordPress.org's own checksums (both come from WordPress.org, so this proves the copy was not changed on the way, not what the author intended) |
| WordPress.org themes | downloaded over TLS from WordPress.org; WordPress.org publishes no theme checksums (`--svn-check` compares each file with themes.svn.wordpress.org) |
| Composer | pinned to commit `<sha>`; Packagist publishes no archive hash for most packages |
| A local zip (`--to-file`) | nothing to check it against, so the update is UNVERIFIED |

## Honest limits

- Sightread never runs the code it downloads. `--soundcheck` is the one exception: it installs the update on a staging copy and loads it in a browser, so the new code runs there.
- No risk signals found means Sightread found no known risk signal in what it could analyse. It is evidence for your review, not a guarantee that the update is safe. It can miss obfuscation it cannot decode, logic that waits for a date or a domain, code fetched at run time from a server that serves clean code to scanners, compiled assets and binaries and changes in a dependency of the package that Sightread did not review.
- Unanalysed means a file was too large or too strange to read. It fails the gate by default because hiding code that way is a known trick.
- WordPress can install updates on its own (auto-updates, forced security releases). A gate only covers updates you run by hand or through your tooling.
- A registry signature or provenance proves who published and from which workflow, not that the content is harmless. Owner change detection depends on what the registry shows: a transfer that keeps the same account is invisible.
- Sightread reports what changed. It does not judge intent.

## Contacted hosts and privacy

Sightread talks only to the official sources, over HTTPS, with a fixed allowlist on every redirect: `api.wordpress.org`, `downloads.wordpress.org`, `plugins.svn.wordpress.org`, `themes.svn.wordpress.org`, `repo.packagist.org`, `packagist.org`, `api.github.com`, `codeload.github.com`, `gitlab.com` and `bitbucket.org` (Composer archives only), `registry.npmjs.org` and `api.osv.dev`, plus mirrors and private registries you configure. `rhythm-sightread update` also reaches GitHub's release hosts for its own signed data packs.

- Each lookup tells that registry a package name and version you use. Sightread never uploads site files and has no telemetry. `--no-osv` skips api.osv.dev.
- Private names stay local: plugins with their own `Update URI`, npm scopes mapped to a private registry and Composer packages from other repositories are never sent to a public host. `--check-confusion` sends them on purpose, to look for public namesakes.
- `GITHUB_TOKEN` goes only to api.github.com, registry tokens only to their registry and `COMPOSER_AUTH` entries only to their host. Secrets found in code are masked in every output and log.
- Reports hold your full inventory. They are written with mode 0600 and paths are relative when `CI` is set (`--redact-paths`).
- Lockfile URLs are never fetched: names and versions are looked up in the registry's own metadata. Archives are read into a content-addressed store and never unpacked under their own names.

## CI

```yaml
- uses: RhythmShahriar/sightread@v1
  with:
    fail-on: high
    comment: true
```

On a pull request the Action reviews every version the lockfile changes move; on other events it reviews every available update. It installs the release that matches the action tag, checks it with cosign, writes Markdown to the job summary, keeps the JSON and HTML reports as a workflow artifact and with `comment: true` keeps one pull request comment up to date. `sarif: true` uploads findings to code scanning. `rhythm sr init ci` writes the whole workflow, pinned by commit with the matching `version` input: a commit doesn't name a release, so without `version` the Action installs the latest one and warns. The Action runs on Linux and macOS runners, not Windows.

Dependabot and Renovate pull requests get a read-only token: the gate and the job summary still work and the comment and SARIF upload are skipped with a notice. To run it only on their pull requests add `if: github.actor == 'dependabot[bot]' || github.actor == 'renovate[bot]'` to the job. Don't use `pull_request_target` with a checkout of the pull request's head. More in the [CI guide](https://github.com/RhythmShahriar/rhythm/wiki/Sightread-CI).

## Exit codes

| Code | Means |
|---|---|
| 0 | ok |
| 1 | findings at `--fail-on`, or new findings at `--fail-on-new` (watch) |
| 2 | usage error |
| 3 | couldn't fetch, verify or check a package (with `--fail-on`, unless `--allow-partial` or `--allow-unverified`), a failed Soundcheck run, or a notification that failed under `--notify-strict` |
| 130 | interrupted |

Without `--fail-on` a run with gaps still exits 0 and says so in the verdict box and in the JSON (`complete: false`).

## Docs

| | |
|---|---|
| [Overview](https://github.com/RhythmShahriar/rhythm/wiki/Sightread) | where Sightread fits, what it catches, how it works |
| [Your first review](https://github.com/RhythmShahriar/rhythm/wiki/Sightread-First-Review) | demo, one plugin, a whole site |
| [Signal reference](https://github.com/RhythmShahriar/rhythm/wiki/Sightread-Signal-Reference) | every signal, its false-alarm guard and how to review it |
| [Allow and baseline](https://github.com/RhythmShahriar/rhythm/wiki/Sightread-Allow-And-Baseline) | the review record, ignore entries and saved reports |
| [Sources and integrity](https://github.com/RhythmShahriar/rhythm/wiki/Sightread-Sources-And-Integrity) | what each source can prove, premium plugins, mirrors |
| [With Soundcheck and Roadie](https://github.com/RhythmShahriar/rhythm/wiki/Sightread-With-Soundcheck) | install on staging and compare before and after |
| [Watch](https://github.com/RhythmShahriar/rhythm/wiki/Sightread-Watch) | fleets on a schedule, notifications |
| [CI and the GitHub Action](https://github.com/RhythmShahriar/rhythm/wiki/Sightread-CI) | `init ci`, every input and output, Dependabot and Renovate |
| [Configuration](https://github.com/RhythmShahriar/rhythm/wiki/Sightread-Configuration) | `.sightread/config.yaml`, sites files, the cache |
| [Output and reports](https://github.com/RhythmShahriar/rhythm/wiki/Sightread-Output) | terminal, JSON, Markdown, HTML, SARIF, signed reports |
| [Security model](https://github.com/RhythmShahriar/rhythm/wiki/Sightread-Security-Model) | what it runs, contacts, sends and writes |
| [CLI reference](https://github.com/RhythmShahriar/rhythm/wiki/Sightread-CLI-Reference) | every command, flag, exit code and file |
| [FAQ and honest limits](https://github.com/RhythmShahriar/rhythm/wiki/Sightread-FAQ) | common questions, errors and what a clean result doesn't prove |
| [Benchmark](https://github.com/RhythmShahriar/rhythm/wiki/Sightread-Benchmark) | 23 bad and 15 good updates, how they're judged, the results |

## Contributing

```sh
git clone https://github.com/RhythmShahriar/sightread && cd sightread
make hooks   # Conventional Commits check
make check   # lint + tests
make testbed # the fixture registries on 127.0.0.1, for end-to-end tests and the benchmark
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for how signals and their fixtures work and the [shared CONTRIBUTING](https://github.com/RhythmShahriar/.github/blob/master/CONTRIBUTING.md) for the Rhythm-wide rules. What comes next is in the [ROADMAP](ROADMAP.md). Found a vulnerability in Sightread itself? Please [report it privately](https://github.com/RhythmShahriar/sightread/security/advisories/new).

## License

Sightread's source is MIT licensed. The `rhythm-sightread` binary links the Rhythm kit, which is AGPL-3.0-only, like the other Rhythm tools.

### Third-party

The binary embeds the [Public Suffix List](https://publicsuffix.org) through `golang.org/x/net/publicsuffix`, under the Mozilla Public License 2.0. Release archives carry its license and a note on its source under `THIRD_PARTY/publicsuffix/`. The NOTICE files of the Apache-2.0 modules it links (mostly the Sigstore libraries that check a data pack's signature) are under `THIRD_PARTY/notices/`.

<p align="center"><sub>Part of <a href="https://github.com/RhythmShahriar/rhythm"><b>rhythm</b></a> · Useful ideas. Working systems.</sub></p>
