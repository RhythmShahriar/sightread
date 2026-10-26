# cli lane: user-visible behaviour

What the `cli` lane (commands, the review pipeline, watch, `--soundcheck`, the Action, packaging
and the README) shows to users, with exact texts, for the docs team and the wiki pages of PRD
section 20. `<prog>` is `rhythm-sightread` when the binary runs directly and `rhythm sightread`
through the router (kit `cli.Name()`). Every message below has a test asserting its text.

## Commands and help

Top-level help is the kit usage and fits 80 columns (golden copy
`cmd/rhythm-sightread/testdata/golden/help/top.txt`). Summary, on two lines: `What will this update
really change? Diff it against the official source` / `and rank what is new. Never runs the code.`
The list shows each command's short form; its own help page has the full usage. Commands, in this
order:

| Command | Help line | Full usage on the command's page |
|---|---|---|
| `plugin <slug>...` | review a WordPress.org plugin update | `plugin <slug>... [flags]` |
| `theme <slug>...` | review a WordPress.org theme update | `theme <slug>... [flags]` |
| `composer [<vendor/pkg>...]` | review Composer updates in composer.lock | `composer [<vendor/pkg>...] [flags]` |
| `npm [<pkg>...]` | review npm updates in the lockfile | `npm [<pkg>...] [flags]` |
| `all [<path>]` | review every update a site or project has | `all [<path>] [flags]` |
| `changes [--base <ref>]` | review every version a lockfile change moves | `changes [--base <ref>] [flags]` |
| `explain <signal-id>` | what a signal means and how to review it | `explain <signal-id> \| <report.json> <n\|fingerprint>` |
| `allow <eco:name@version>...` | record a reviewed version | `allow <eco:name@version>... --reason <text> \| --from <report.json> \| list \| remove <ref> \| import <file>` |
| `watch -l <sites.yaml>` | check sites on a schedule | `watch -l <sites.yaml> --every <d> \| --at <HH:MM> [flags] [-- <review flags>]` |
| `report <report.json>...` | render saved JSON as Markdown, HTML or SARIF | `report <report.json>... -o <file>` |
| `verify-report <report.json>` | check a signed report | `verify-report <report.json> [--key <pub>]` |
| `init [ci] [--force]` | write .sightread/config.yaml or a CI workflow | the same |
| `doctor [--json]` | check sources, cache, tokens and helpers | `doctor [--offline] [--json]` |
| `demo [--keep]` | try it on built-in packages, no network | `demo [--keep] [-o <file>]... [--open]` |
| `signals [--json]` | list every signal with its default severity | the same |
| `cache prune` | remove cached archives nothing uses | `cache prune [--older <d>]` |
| `update [--json]` | refresh signal and name data, never packages | `update [--json] [--pin <name=version,...>]` |
| `version [--json]` | print the version (kit) | the same |

Every command answers `--help` and `help <command>` on stdout with exit 0: `Usage: <prog> <cmd>
<args>`, a paragraph, flag groups and `Examples:`. Pages wrap at 80 columns. Golden copies:
`cmd/rhythm-sightread/testdata/golden/help/{direct,router}/<cmd>.txt`. An unknown command is
E20 (kit text): `<prog>: unknown command "plugn"` / `  did you mean: <prog> plugin` /
`  run '<prog> help' to see the commands`.

`plugin`, `all` and `changes` help end with: `Contacts: api.wordpress.org,
downloads.wordpress.org, plugins.svn.wordpress.org, themes.svn.wordpress.org,
repo.packagist.org, packagist.org, api.github.com, codeload.github.com, registry.npmjs.org and
api.osv.dev. It sends package names and versions only and never uploads site files.` The
Soundcheck pages end with `Arguments after -- go to rhythm-soundcheck snapshot.`

## Picker and first run

- Bare `<prog>` on an interactive terminal (stdin and stdout) with `CI` unset opens the picker.
  Off a terminal or in CI it prints the usage and exits 0.
- Picker header, then a Huh select:

  ```
    ♪ rhythm sightread 1.0.0
    What will this update really change?

    Found here: a WordPress site (23 plugins, 2 themes) and composer.lock
  ```

  "Found here" forms: `a WordPress site (1 plugin, 2 themes)`, lockfile names joined `a, b and c`,
  or `Found here: no WordPress site or lockfile`. Choices, each with its command beside it:
  `Review every available update here` (`all`), `Review one plugin or theme` (asks Plugin or Theme
  and `Its WordPress.org slug`), `Review a lockfile change against main` (`changes`), `Try it on
  built-in examples` (`demo`), `Set up CI` (`init ci`). The default is `all` when something was
  found, else `demo`. Before running it prints `→ rhythm sightread <args>`. Esc or Ctrl-C exits
  130.
- First-run note, on stderr, once per machine (marker `sightread-first-run`); a `--json`, `-q`
  or `--quiet` run prints nothing and leaves the marker for later:

  ```
  Note: Sightread downloads packages from WordPress.org, Packagist and npm and reads
  them as text. It never runs their code. A clean result is a static diff, not proof
  an update is safe. This notice is shown once.
  ```

- Read-only line: the review commands tell the terminal writer whether `--soundcheck` is on
  (`WriteOptions.Soundcheck`), so it prints `Read-only. Sightread changes nothing on your site and
  never runs the code it downloads.` or, with `--soundcheck`, `Read-only here. --soundcheck
  installs the update on the staging copy, where its code runs.` (the text is the output lane's).
- `--offline` anywhere in the arguments also turns off kit's release check.

## Review commands: flags and defaults

Shared by `plugin`, `theme`, `composer`, `npm`, `all` and `changes`.

- **Versions:** `--to <version>` (plugins and themes `latest`, composer and npm `wanted`; also
  `installed`, `x.y.z`, an npm dist-tag or `list`), `--from <version>`, `--to-file <path>`,
  `--from-file <path>`, `--path <folder>` (default `.`), `--wp <command>`,
  `--from-tuner <report>`, `--allow-downgrade`, `--pre`, `--transitive`, `--only <packages>`,
  `--skip <packages>` (comma lists, repeatable; an ecosystem ID including the `plugin` and `theme`
  shorthands, or `<eco>:<glob>`).
- **Lockfile change** (`changes`): `--base <ref>` (default `origin/$GITHUB_BASE_REF` when set,
  else the merge base with origin/HEAD), `--before <lockfile>`, `--after <lockfile>`, `--lockfile <lockfile>`
  (repeatable).
- **Fleet** (`all`): `--sites <file>`, `--rereview` (`review each installed version against the
  release before it, so new signals reach what you already run (watch does this after a signal
  data update)`).
- **Sources and integrity:** `--offline` (also `RHYTHM_OFFLINE=1`), `--allow-unverified`,
  `--allow-partial`, `--svn-check`, `--no-osv`, `--check-confusion`, `--max-size <size>`
  (default `256MB`; KB, MB, GB, KiB, MiB, GiB; unpacked at most 4 times that and 1GiB),
  `--timeout <duration>` (30s), `--deadline <duration>` (30m), `--retries <n>` (2), `--jobs <n>`
  (4; at most 4 requests per host), `--proxy <url>` (default `HTTPS_PROXY`),
  `-A, --user-agent <header>` (default `rhythm-sightread/<version>
  (+https://github.com/RhythmShahriar/sightread)`).
- **Signals:** `--signals <folder>` (repeatable), `--no-signal-updates`, `--id <ids>`,
  `--exclude-id <ids>` (globs; integrity and allow signals always stay), `--severity <level>`
  (default `info`), `--min-confidence <confidence>` (default `likely`, config `min_confidence`),
  `--min-age <duration>` (default `72h`, config `min_age`). Durations take `d` and `w` too.
- **Gate:** `--fail-on <level>` (default none, config `fail_on`), `--baseline <report>`,
  `--no-allow`, `--trust-pr-allow` (`changes`), `--config <file>`, `--no-config`.
- **Output:** `--json`, `--jsonl`, `--md`, `--html`, `--sarif` (one replaces the terminal view on
  stdout), `-o, --output <file>` (repeatable; format from `.json .jsonl .md .html .htm .sarif`),
  `--open`, `--diff`, `--max-findings <n>` (10), `--sign`, `--redact-paths` (default on when `CI`
  is set), `-q, --quiet`, `--plain` (also when stdout is not a terminal), `--no-color` (also
  `NO_COLOR`), `-v, --verbose`.
- **Soundcheck** (`plugin`, `theme`, `composer`, `npm`): `--soundcheck <url>`, `--apply
  <command>`, `--rollback`, `--soundcheck-fail-on <class>` (default `broke`; broke, new or
  changed), `--soundcheck-anyway`, `--skip-roadie-verify`, arguments after `--`.
- **Environment:** `GITHUB_TOKEN` (else `RHYTHM_GITHUB_TOKEN`), `COMPOSER_AUTH`,
  `SIGHTREAD_NPM_TOKEN_<SCOPE>` (`ACME` is `@acme`, `MY_ORG` is `@my-org`), the source bases
  `SIGHTREAD_WPORG_API`, `SIGHTREAD_WPDL_API`, `SIGHTREAD_WPSVN`, `SIGHTREAD_WPTHEMESVN`,
  `SIGHTREAD_PACKAGIST`, `SIGHTREAD_PACKAGIST_META`, `SIGHTREAD_GITHUB_API`,
  `SIGHTREAD_GITHUB_CODELOAD`, `SIGHTREAD_NPM_REGISTRY`, `SIGHTREAD_OSV_API` (they beat config
  sources), `SIGHTREAD_SMTP_PASSWORD` (watch mail).

### Review behaviour

- Same version: `akismet 5.3.5 is already the latest: nothing to compare` (exit 0; every `-o`
  file and `--json`/`--jsonl` stdout still get the report with that note); also
  `<name> <v> is already the newest <constraint> allows: nothing to compare` and `<name> <v> is
  the installed version: nothing to compare`. `--to list` prints the published versions newest
  first (a `<name>:` line before each list when several names are given).
- Progress on stderr when it is a terminal and the output is the terminal view: `reviewing 3 of
  8: woocommerce 9.3.3 → 9.4.0` (`new` as the from version of an added package).
- Not checked entries added by the pipeline (reason, text, hint): `private` / `private registry
  or repository` / `set the registry in .sightread/config.yaml sources`; `not-wporg` / `not on
  wordpress.org (no files match the wordpress.org copy)` or `not on WordPress.org (slug unknown)`
  / `give the vendor's zip with --to-file`; `too-large` / the E11 text / `raise --max-size`;
  `fetch-failed` / `could not download (<summary>)` / `run again; -v shows the request`, or `the
  run was interrupted before it was reviewed`, or `--deadline 30m0s passed before it was
  reviewed` / `run again`; a fleet site that can't be read: `couldn't read site <name>:
  <summary>` / `check its path, wp or tuner_report in the sites file`.
- Warnings: `dependency-confusion: npm:@acme/billing is private here and registry.npmjs.org
  publishes 9.0.0, a higher version` (with `--check-confusion`); `couldn't look up OSV advisories
  (<summary>): known-malicious and known-vulnerable were not checked`; a detector panic adds the
  update error `detector <name> failed (<value>); its signals were not checked`.
- Ctrl-C: the first stops starting packages and lets the ones under way finish (`stopped_by:
  "interrupted"`, `complete: false`); the second returns at once; exit 130.
- Files: every `-o` file is written whole through a temp file and a rename, mode 0600. `--sign`
  signs `<file>.json` into `<file>.json.sig` (key `<config dir>/sightread/report-key`).
  `--open` opens the first HTML output, else prints `open /abs/path/review.html in a browser`.
- Cache: verified archives are indexed under `<cache>/archives/` so a second run downloads
  nothing; each review's JSON is kept under `<cache>/runs/` (newest 20).
- Pull request rule (`changes` with a base ref, the Action's default on pull requests, unless
  `--trust-pr-allow`): the config is also read at `--base` (default `origin/HEAD`). What the
  change relaxes does not count and leaves a report note ending `: relaxed in this change, not
  counted (--trust-pr-allow counts it)`: the policy's keys (ignore, signals.severity,
  signals.domains_ok, min_confidence, fail_on, allow_file, allow_from) and, in run, `osv false`,
  `sources`, `local_files`, `trusted_keys "<key>"`, `ecosystems` and `min_age <base value>`. A
  config the base can't show or parse counts as empty; a `--config` file outside the repository
  counts as written; a config the change deleted is still read at the base. `--baseline`
  fingerprints the change added are dropped with the note `--baseline: <n> finding(s) saved in
  this change, not counted (--trust-pr-allow counts them)`. A policy without these rules stops
  the run (`the config pull request rule (policy) not linked`).
- `-v` lines: `sightread: <eco>:<name>: <error>`, `sightread: <ref>: from the archive cache` and
  `  cause: <cause>` under an error, all secret-masked.

## Errors (PRD 10) and exit codes

Exit codes: 0 ok; 1 findings at `--fail-on` or new findings at `--fail-on-new`; 2 usage; 3
couldn't fetch, verify or check (under `--fail-on` unless `--allow-partial` or
`--allow-unverified`), a failed Soundcheck run, a failed notification under `--notify-strict`, or
a review that checked nothing because of errors (whatever `--fail-on` says); 130 interrupted.
Every error is `<prog> <command>: <what happened>` with indented hint lines.

- E1: `<prog> plugin: no installed countdown-timer-ultimate under /home/ann/site` / `  name the
  site with --path /var/www/site, read it with --wp "wp --path=..." or give the version: --from
  <version>` (composer and npm: `  name the project with --path <dir> or give the version: --from
  <version>`).
- E3: `<prog> plugin: akismet has no version 9.9.9 on wordpress.org` / `  newest: 5.3.5 · see
  them all: <prog> plugin akismet --to list`.
- E5 (when the gate fails): `<prog> plugin: couldn't verify countdown-timer-ultimate 2.6.8:
  wordpress.org checksums answered 503` / `  not diffed; run again later, or --allow-unverified
  to review it anyway (the report marks it unverified)`.
- E9 with the run's count: `  reviewed 1 of 2 updates; run again in a few minutes or lower
  --jobs`.
- E12: `<prog>: .sightread/allowed.yaml: entry 3 (npm:left-pad@1.4.0) needs a reason, so the
  next person knows why it is allowed`.
- E13 (bad flag values, exit 2): `<prog>: --fail-on "severe": want none, info, low, medium, high
  or critical`; `--min-confidence "sure": want confirmed or likely`; `--severity "none": want
  info, low, medium, high or critical`; `--timeout "soon": want a duration such as 30s, 10m, 72h
  or 3d`; `--max-size "lots": want a size such as 256MB, 1GB or 512KiB`; `--jobs 0: want 1 to
  64`; `--retries 11: want 0 to 10`; `--max-findings -1: want 0 or more`; `-o "review.txt": want
  a file ending in .json, .jsonl, .md, .html or .sarif`; `--json and --md both print to stdout:
  pick one, or write the other with -o <file>`; `--open opens the HTML report, so write one with
  -o <file>.html`; `--sign signs the JSON report, so write one with -o <file>.json`; `--config
  and --no-config can't be used together`; `--soundcheck-fail-on "all": want broke, new or
  changed`; `--proxy "proxy.example": want a URL such as http://proxy.example:3128` (the value is
shown without its user info: `scheme://host`, else `***@host`); `--wp "wp
  'x": a quote is not closed`; `--only or --skip "wordpress": want an ecosystem (wp-plugin,
  wp-theme, composer, npm) or <eco>:<name>, globs allowed`; `no signal "eval-dynamik" (did you
  mean eval-dynamic?)` / `  list them: <prog> signals`; `--before and --after go together: the
  old and the new lockfile`; `--base reads the lockfiles from git and --before and --after from
  files: pick one`; `--to-file and --from-file review one package: use <prog> plugin, theme,
  composer or npm with a name`; `--from, --from-file and --to-file name one version, so give one
  package with them`; `the arguments after -- go to rhythm-soundcheck, so they need --soundcheck
  <staging-url>`; `--rereview reviews the installed versions against the release before them,
  so it takes no --to or --from`.
- Usage (kit form, exit 2): `plugin needs a slug: <prog> plugin <slug>`, `all takes one folder,
  got N`, `changes takes no arguments; name lockfiles with --lockfile`, `--to list needs a
  package name: <prog> <cmd> <name> --to list`.
- E19: `<prog> plugin: --to 5.3.1 is older than the installed 5.3.5` / `  add --allow-downgrade
  to review a downgrade`.
- E14, E15, E17, E21 and the other `--soundcheck` texts: below.

## --soundcheck

Steps: (1) HOLD stops with E17 unless `--soundcheck-anyway`; (2) production by name from config
`soundcheck.production` and the nearest `.soundcheck/config.yaml` gives E14; (3)
`rhythm-soundcheck` and `rhythm-roadie` must be on PATH (Roadie not with `--skip-roadie-verify`)
or E15; Roadie verify must pass or E15; Roadie's `production_url` and a staging host that
resolves to a production address give E14; (4) `rhythm-soundcheck snapshot <url> --name
sightread-<name>-<from> [args after -- or config soundcheck.args]`; (5) apply: the cached
verified archive, re-hashed against the reviewed sha256, through `<wp> plugin|theme install
<zip> --force`, or `--apply "<cmd>"` for Composer, npm or a remote wp; (6) `rhythm-soundcheck
compare <url> --snapshot <name> --json`; (7) `--rollback` reinstalls the verified old archive
when compare has changes at `--soundcheck-fail-on`.

- Before the review (exit 2): `--soundcheck installs one update: name one package, e.g. <prog>
  plugin <name> --soundcheck <staging-url>`; `<prog> npm: --soundcheck needs --apply "<command
  that installs the update on staging>" for Composer and npm packages`; `--soundcheck "s.test":
  want the staging site's URL, such as https://staging.shop.test`; `--apply "<cmd>": <split
  error>`; `--rollback goes with --soundcheck <staging-url>` (also `--apply`,
  `--soundcheck-anyway`, `--skip-roadie-verify`, `--soundcheck-fail-on`).
- E17 (exit 1): `<prog> plugin: countdown-timer-ultimate 2.6.8 is on HOLD, so --soundcheck won't
  install it` / `  review the findings first; --soundcheck-anyway installs it on the staging copy
  regardless`.
- E14 (exit 2): `<prog> plugin: shop.example.com is listed as production in
  .soundcheck/config.yaml` (also `in .sightread/config.yaml (soundcheck.production)` and `in the
  Roadie verify report`); `<prog> plugin: staging.shop.test resolves to 203.0.113.5, the address
  of production shop.example.com (<where>)`; hint `  --soundcheck applies the update to the site;
  point it at a staging copy (rhythm roadie copy makes one)`.
- E15 (exit 3): `<prog>: --soundcheck needs rhythm-soundcheck and rhythm-roadie` / `  install
  them with: rhythm install soundcheck roadie` (one missing: `needs rhythm-roadie` / `  install it
  with: rhythm install roadie`); `<prog>: staging.shop.test failed rhythm roadie verify (2
  real-looking emails, 1 live payment key)` / `  fix it with rhythm roadie prepare, or
  --skip-roadie-verify (the report says it was skipped)` (other reasons: `verdict <v>`, `the copy
  has no signed Roadie marker`, `outbound mail is not sealed`, `the check is older than the
  copy`); `<prog> plugin: rhythm-roadie verify couldn't run (exit 3)` (also `rhythm-soundcheck
  snapshot` and `compare`) / `  -v shows its output; nothing was installed on <host>` or `  -v
  shows its output; <name> <version> is installed on <host>, so check the site yourself`.
- E21 (exit 2): `<prog> plugin: --soundcheck can install the verified zip only through a local wp
  command` / `  for a remote staging site give --apply "<command that installs
  countdown-timer-ultimate 2.6.8>"; the report then says the applied bytes were not checked`.
- No wp command (exit 2): `<prog> plugin: --soundcheck needs the staging site's wp command to
  install the verified zip` / `  give it with --wp "wp --path=/srv/staging" (or soundcheck.wp in
  .sightread/config.yaml)`.
- Not cached (exit 3): `<prog> plugin: akismet 5.3.5 isn't in the archive cache, so --soundcheck
  can't install the reviewed bytes` / `  review it again: verified archives stay cached for 30
  days (an unverified one is never cached)`. Tampered cache (E6 code, exit 3): `<prog> plugin:
  the cached archive of akismet 5.3.5 doesn't match the reviewed sha256, so --soundcheck won't
  install it` / `  the cache changed after the review; run the review again and look at why`.
  Install failure: `<prog> plugin: couldn't install akismet 5.3.5 on staging.shop.test: wp exited
  1`.
- Report: `soundcheck` block `staging`, `roadie_verify` (`ok` or `skipped`), `snapshot`,
  `applied` (`verified archive <12 hex>` or `your command`), `broke`, `new`, `changed`, `report`,
  `rolled_back`, `error`. When Soundcheck stops after it touched the staging copy, the report is
  incomplete, `error` says why, `data.errors` has a `--soundcheck: ...` entry and `summary` is
  null if the comparison never ran; the terminal line reads `<staging>: not compared: <why>`. Notes: `the staging site ran the update; Sightread did not`;
  `--skip-roadie-verify was used: the staging copy wasn't checked by rhythm roadie verify, so
  outbound mail is not known to be sealed`; `applied by your command; the applied bytes were not
  checked against the reviewed ones`; `--rollback reinstalls only a version Sightread installed
  and reviewed; put the old version back with your own command`.
- Exit: the report is written first; changes at `--soundcheck-fail-on` exit 1; Soundcheck failing
  to run exits 3.

## Other commands

- `explain <signal-id> [--json]`, `explain <report.json> <n|fingerprint> [--json]`. Unknown ID:
  `<prog> explain: no signal "evil" (did you mean eval-dynamic?)` / `  list them: <prog>
  signals`. `<prog> explain: review.json has no finding 9 (it has 5)`, `... has no finding with
  fingerprint <fp>`, `<prog> explain: review.json: no such file`.
- `allow <eco:name@version>... --reason <text> [--by <name>] [--until <date>] [--signals <IDs>]
  [--file <file>] [--offline] [--config <file> | --no-config]` prints `allowed npm:sharp@0.33.5
  (sha256 0b7e1d2c3a4f) in .sightread/allowed.yaml`. `--by` defaults to `git config user.name`,
  then `$USER`, `%USERNAME%`, `unknown`. `allow --from <report.json> --reason <text>`. `allow list
  [--json]` (table `PACKAGE  SHA256  SIGNALS  BY  DATE  UNTIL  REASON`, or `<file> allows nothing
  yet`), `allow remove <ref>` (`removed npm:sharp@0.33.5 from .sightread/allowed.yaml`), `allow
  import <file>` (`imported 3 entries from x into .sightread/allowed.yaml`). Errors: `<prog>
  allow: --reason is required, so the next person knows why it is allowed` / `  add --reason
  "<what you checked>"`; E18 `<prog> allow: npm:left-pad@1.4.0 couldn't be verified, so it can't
  be allowed` / `  allow records a reviewed archive by its hash; review it first with <prog> npm
  left-pad --to 1.4.0`; mismatch `<prog> allow: npm:evil@2.0.0 doesn't match its published hash,
  so it can't be allowed` / `  someone between you and the registry changed it, or the release
  was edited; don't install this copy`; `--until "soon": want a date such as 2027-01-31`.
- `report <report.json>... -o <file>` merges and writes `.md .html .sarif .json`, printing `wrote
  <file>`. `report writes files: give -o <file> ending in .md, .html, .sarif or .json`.
- `verify-report <report.json> [--key <file>]... [--config <file>] [--json]`: `review.json:
  signature good, signed by <key id>` (exit 0); `<prog> verify-report: review.json: the signature
  doesn't check out (<why>)` / `  the report changed after it was signed, or its key isn't
  trusted here (add it with --key or trusted_keys)` (exit 1); a missing signature adds `  it was
  not signed: sign a review with --sign -o <file>.json` (exit 2).
- `signals [--json]`: table `ID  SEVERITY  CONFIDENCE  ECOSYSTEMS  NAME`, unignorable IDs marked
  ` (can't be ignored)`.
- `cache prune [--older <d>]` (default `30d`): `removed 2 archive indexes older than 30 days and
  14 cached files nothing uses (3.0 MiB)`. Ages under an hour read in minutes or seconds (`older
  than 45 minutes`); `--older 0` reads `removed 96 archive indexes (all of them) and ...`.
- `update [--json] [--pin name=version,...]`: one `name version` line per data pack; `update
  failed: <reason>` exits 3; `--pin: "x" isn't name=version` exits 2.
- `doctor [--offline] [--json] [--plain]`: lines `  ✓ Name             detail` (plain: `ok
  Name: detail`, `FAIL`, `warn`, `skip`) for Config, Cache, each source base, npm keys, GitHub
  token (`set (sent only to api.github.com); 4987 of 5000 requests left this hour`), git and,
  with a `soundcheck` config, rhythm-soundcheck and rhythm-roadie, then Signal data; it ends `  N
  checks passed, M failed.` and exits 1 on a failure.

## init and init ci

- `init [--force]` writes `.sightread/config.yaml` and prints `Wrote .sightread/config.yaml:
  reviews wp-plugin and composer, fails on high or worse.` then `Next steps:` (review and commit,
  `rhythm sightread all`, `rhythm sightread init ci`).
- `init ci [--fail-on high] [--sarif] [--comment] [--force]` writes
  `.github/workflows/sightread.yml` at the repository root (PRD 16's file, actions pinned by
  commit with `version: <x.y.z>` under `with:`; a dev build writes
  `RhythmShahriar/sightread@v1 # pin this to a commit SHA and set version below`). Output:

  ```
  Wrote .github/workflows/sightread.yml: reviews lockfile changes on pull requests and everything each Monday, fails on high or worse.

  Next steps:
    1. Review the file, then commit and push it:
         git add .github/workflows/sightread.yml
         git commit -m "ci: review updates with sightread"
    2. Protect .sightread/allowed.yaml with CODEOWNERS, so a pull request can't approve its own update:
         /.sightread/allowed.yaml @your-org/reviewers
    3. Dependabot and Renovate pull requests get a read-only token: the gate and the job summary still
       work while the comment and the SARIF upload are skipped with a notice.
  More: https://github.com/RhythmShahriar/rhythm/wiki/Sightread-CI
  ```

  `--fail-on none` says `never fails on findings`; `--sarif` adds `security-events: write` and a
  fourth step; outside a git repository: `No git repository found above <dir>, so the workflow
  went there.` Existing file (exit 2): `<prog> init: .github/workflows/sightread.yml exists (use
  --force to replace it)`.

## demo

`demo [--keep] [-o <file>]... [--open] [--plain] [--no-color]` serves three fictional updates on a free 127.0.0.1 port and
reviews them with the normal terminal report: `comment-guard` 4.1.2 → 4.1.3 (ROUTINE),
`share-kit` 3.2.0 → 3.2.1 (new committer, unserialize of a remote body, open REST route,
blockchain RPC host: HOLD) and npm `date-utils-lite` 1.4.0 → 1.4.1 (new postinstall that would
fetch and eval code plus the look-alike dependency `axois`: HOLD). It ends with `→ on your site:
rhythm sightread all /path/to/wordpress` and `→ in CI: rhythm sightread init ci` (with `--plain` or
when stdout is not a terminal, `next: on your site: ...` and `next: in CI: ...` right after the report's
own `next:` lines). `--keep` keeps
the temp folder and prints `kept the demo archives, cache and site in <dir>`. `-o` writes the
report as a review does (.json, .md, .html or .sarif) and `--open` opens the HTML one. Its next
steps are `→ every finding and the full diff: rhythm sightread demo -o review.html --open` and
`→ explain a finding: ...`; it never suggests an update or allow command for its made-up
packages. Anything that tries
another host fails the demo: `demo: something tried to leave the machine (<requests>); please
report it`.

## watch and notifications

- Flags: `-l, --list <file>`, `--every <duration>` (at least 1m), `--at <time>` (`02:00,14:30`),
  `--now`, `--once`, `--name <name>`, `--dir <folder>` (default `<user cache>/rhythm/sightread/
  watch/<name>`), `--keep <n>` (30, 0 keeps all), `--notify <url>` (repeatable), `--notify-min
  <level>` (high), `--notify-strict`, `--fail-on-new <level>`, `--html`, `-v`, review flags after
  `--`.
- One line per run: `2026-10-27 02:00 AEST: 6 sites, 14 updates available, 2 to review (1 hold);
  report <dir>/20261026T160000Z.json`. A review that left something out, or exited other than 0
  or 1, adds `; incomplete: 2 not checked, 1 unverified, 1 error (see <dir>/<stamp>.log)` (or
  `the run hit its --deadline`, `the review exited 3`). Without a report: `<stamp>: the review
  exited 3 without a report; see <dir>/<stamp>.log`. Problems follow indented: `  couldn't notify <scheme://host>:
  <error>`. A network failure is its short cause (`connection refused`, `timed out`); the raw error
  is printed with `-v`.
- Loop mode: `Watching the sites in <file>, every 24h; reports go to <dir>` (or `daily at 02:00,
  14:00`), `Next run 2026-10-27 02:00 AEST`, `Stopped.`. First Ctrl-C: `<prog>: stopping once
  the current review finishes; press Ctrl-C again to stop it now`. A held lock: `<stamp>:
  skipped: another run of this watch is still going (lock <dir>/watch.lock)`. A bad state file:
  `state.json couldn't be read, so it was set aside as state.json.bad; this run may repeat
  earlier notifications`. A review that rejects its flags: `<prog> watch: the review rejected its
  flags (exit 2); see <log>`.
- The first run counts every finding as new. A signal data update triggers a re-review of what
  is installed; owners and WordPress.org closures are checked every 12 hours.
- Receivers: `slack://`, `discord://`, `webhook+https://` (`webhook+http://` on loopback only),
  `smtp://` and `smtps://` (`?to=...&from=...`, password in `SIGHTREAD_SMTP_PASSWORD`). Printed as
  `scheme://host` only. Chat and mail text: `Sightread <watch>: 1 update to look at, 1 new signal
  on a version you already run, 1 owner change, 1 closed plugin or theme`, then one line per item
  (`wpforms-lite 1.9.1 → 1.9.2 HOLD on 14 sites`, `  top finding: <title>`, `new signal on a
  version you already run: ...`, `owner change: share-kit 3.2.0 on 2 sites: added
  growth-partners; removed alice`, `closed on wordpress.org: gone 2.0.0 on shop: security
  issue`), at most 25 then `…and N more`, then `Report: <path>` and, for a partial run, `Partial:
  2 not checked, 1 error; see <log>`. A failed or incomplete run is notified even with nothing
  new: `Sightread <watch>: the review is incomplete` with that line, or `Failed: the review
  exited 3 without a report; see <log>`. A failed run (no report, an error, a stop, exit 3) is
  notified every time; a run that only leaves packages out is notified when what it leaves out
  changes. Webhook payload schema `rhythm-sightread-notify/v1`.
- Usage errors (exit 2): `watch needs a sites file: <prog> watch -l <sites.yaml> --every 24h`,
  `pick a schedule: --every <interval> or --at <HH:MM>`, `pick one of --every and --at`, `--every
  10s is too often; the shortest interval is 1m`, `--at "2am": want a 24-hour time like 02:00
  (several separated by commas)`, `--once runs a single review; drop --every, --at and --now, or
  drop --once`, `--now goes with --at; --every already starts with a run`, `the watch sets -o
  itself; drop it after --`, `--notify-min=low is a watch flag; put it before --`, `watch takes no
  arguments, got "x"; review flags go after --`. SMTP texts: `put the SMTP password in
  SIGHTREAD_SMTP_PASSWORD, not in the URL` and `set SIGHTREAD_SMTP_PASSWORD to the password for
  the SMTP user`.

## GitHub Action

`RhythmShahriar/sightread@v1`, composite, every action pinned by commit. Linux and macOS runners
only: on Windows install fails with `::error::the Sightread Action runs on Linux and macOS runners,
not Windows: use runs-on: ubuntu-latest or macos-latest`. A commit ref without the `version` input
installs the latest release and warns `Sightread's version isn't pinned: the action is pinned to
commit <sha> but a commit doesn't name a release, ...`.

| Input | Default |
|---|---|
| `mode` | `changes` on pull requests, else `all` (or `package`) |
| `package` | `""` (one `eco:name@version` per line) |
| `path`, `working-directory` | `.` |
| `base` | the pull request's base branch |
| `fail-on` | `high` |
| `min-confidence`, `baseline`, `args`, `version`, `download-url` | `""` |
| `allow-partial`, `allow-unverified`, `trust-pr-allow`, `transitive`, `sarif`, `comment`, `attest` | `false` |
| `summary`, `upload`, `verify-signature` | `true` |
| `github-token` | `${{ github.token }}` |

Outputs: `exit-code`, `verdict` (worst of `hold`, `review`, `routine`, `allowed`, `unverified`,
else `none`), `updates`, `findings`, `report`, `html`, `sarif-file`, `summary`, `comment-id`,
`version`. Artifact `sightread-report` (`-2`, `-3` for later uses in one job). Notices:
`Sightread: the SARIF upload was skipped. The token needs "permissions: security-events:
write"; ...`, `Sightread: the report was not attested. The job needs "permissions: id-token:
write" and "attestations: write".`, `Sightread: couldn't comment on the pull request. The job
needs "permissions: pull-requests: write"; pull requests from forks and Dependabot only get a
read-only token, so the gate and the job summary still work without the comment.`, `Sightread's
version isn't pinned: ...`. Errors: `Sightread found updates with findings at or above
<fail-on>. ...`, `Sightread exited <n>. See the job summary.`, `unknown mode "x": use changes,
all or package`, `mode changes needs a base branch: run it on pull_request or set the base
input`, `package: line N isn't eco:name@version, e.g. npm:left-pad@1.4.0`, `package: line N: a name or
version can't start with -`, `mode package needs
the package input: one eco:name@version per line`, `download-url needs the version input: a
mirror has no latest release to look up`. The pull request comment carries the marker `<!--
rhythm-sightread -->` and is updated on later runs.

## Release artifacts

Archives `rhythm-sightread_<os>_<arch>.tar.gz` (`.zip` on Windows) for linux, darwin and windows
on amd64 and arm64, each with `README.md`, `LICENSE` and `THIRD_PARTY/publicsuffix/`
(`LICENSE`, `README.md`); `checksums.txt` with its Sigstore bundle; the data packs
`sightread-names.json` and `sightread-signals.tar.gz` listed in `checksums.txt`. A tag such as
`v1.0.0-rc1` is a prerelease. `scripts/verify-release.sh` checks a release's signature and
checksums.

## README, CONTRIBUTING and ROADMAP

- README: pitch (PRD 3), install, quick start (`rhythm install sightread`, `rhythm sr demo`,
  `rhythm sr plugin akismet --from 5.3.3`, `rhythm sr all /var/www/shop`, `rhythm sr init ci`),
  verdicts, a task table, signal groups, "verified by" per source (PRD 18 item 4), honest limits
  (PRD 18 items 1, 2, 3, 5, 6, 11, 12), contacted hosts and privacy, the Action snippet with the
  Dependabot note, exit codes, the five-tool table and the license statement (PRD 23). A test
  runs every command it shows with `--help` and checks each flag it names is in a help page.
- CONTRIBUTING: the never-run rule, adding a signal, 3 positive and 3 negative fixture pairs with
  a look-alike, fake secrets at run time, fuzz corpus rules, writing rules, commit scopes.
- ROADMAP: PRD 22's out-of-scope items.
