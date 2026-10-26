# Fetch, archives, sources and versions: user-visible changes

This lists what the fetch lane (`fetch/`, `blob/`, `archive/`, `source/`, `version/`) adds that a user can see: hosts, variables, verification wording, error texts, flags, limits, offline behaviour and the cache. Error texts are shown as the router prints them (`rhythm sightread`); the standalone binary prints `rhythm-sightread` in the same place. A hint line is indented by two spaces and shown here after ` / `.

## Contacted hosts

Sightread talks only to these hosts, over https on port 443, plus the host and port of every mirror you configure. Every hop of a redirect is checked against the list; a refused hop sends nothing.

- api.wordpress.org, downloads.wordpress.org, plugins.svn.wordpress.org, themes.svn.wordpress.org
- repo.packagist.org, packagist.org
- api.github.com, codeload.github.com, gitlab.com, bitbucket.org (Composer dist archives)
- registry.npmjs.org
- api.osv.dev

Public hosts are dialed only on public addresses: an allowed name that resolves to 169.254.x.x or a private network is refused. The configured or environment proxy is the one exception.

The same rule covers private registries: a Composer repository or an npm scope registry whose name resolves to a private network (10.x.x.x, 172.16-31.x.x, 192.168.x.x) is refused with `refused: not a public address`. Two ways around it: reach the registry through the proxy (`HTTPS_PROXY` or the configured proxy may sit on the private network), or forward a local port to it and give the registry as a loopback base such as `http://127.0.0.1:8080`, which is dialed on 127.0.0.1 only.

Example: `SIGHTREAD_NPM_REGISTRY=https://169.254.169.254 rhythm sightread npm left-pad` prints `rhythm sightread: can't reach 169.254.169.254 (refused: not a public address)` / `check the connection or HTTPS_PROXY` and exits 3.

## Mirror variables

Each `SIGHTREAD_*` variable replaces one base URL. Defaults:

| Variable | Default |
| --- | --- |
| `SIGHTREAD_WPORG_API` | `https://api.wordpress.org` |
| `SIGHTREAD_WPDL_API` | `https://downloads.wordpress.org` |
| `SIGHTREAD_WPSVN` | `https://plugins.svn.wordpress.org` |
| `SIGHTREAD_WPTHEMESVN` | `https://themes.svn.wordpress.org` |
| `SIGHTREAD_PACKAGIST` | `https://repo.packagist.org` |
| `SIGHTREAD_PACKAGIST_META` | `https://packagist.org` |
| `SIGHTREAD_GITHUB_API` | `https://api.github.com` |
| `SIGHTREAD_GITHUB_CODELOAD` | `https://codeload.github.com` |
| `SIGHTREAD_NPM_REGISTRY` | `https://registry.npmjs.org` |
| `SIGHTREAD_OSV_API` | `https://api.osv.dev` |
| `SIGHTREAD_NPM_EXTRA_KEYS` | unset; a keys JSON file added to the pinned npm keys only when the npm registry is on 127.0.0.1, ::1 or localhost |

A mirror may use plain `http://` only when its host is exactly 127.0.0.1, ::1 or localhost. Those are dialed without a proxy and reach nothing else. Composer zipballs on api.github.com or codeload.github.com and npm tarballs on registry.npmjs.org follow the GitHub and npm mirrors when those are set.

Example: `SIGHTREAD_NPM_REGISTRY=http://mirror.example rhythm sightread npm left-pad` prints `rhythm sightread: SIGHTREAD_NPM_REGISTRY "http://mirror.example" must use https` / `plain http is allowed only for a mirror on 127.0.0.1, ::1 or localhost` and exits 2 (E12).

Other E12 texts: `SIGHTREAD_<NAME> "<value>" is not a base URL` / `give one like https://mirror.example.com/npm`, `COMPOSER_AUTH is not valid JSON`, `allowed host "127.0.0.1:8080" is a loopback address`, `allowed host "https://x.example/" is not a host name`, `proxy "<p>" is not a URL`.

## Credentials and the GitHub token

Each credential goes only to its own host and port, on every hop. An `Authorization` header a redirect would carry along is dropped first. The `-v` log never shows it.

- `GITHUB_TOKEN`, else `RHYTHM_GITHUB_TOKEN`: `Authorization: Bearer` to api.github.com only (and to a `SIGHTREAD_GITHUB_API` mirror on 127.0.0.1 for tests). Never to a remote mirror, never to codeload.github.com.
- `COMPOSER_AUTH` (read as Composer reads it): `http-basic` and `bearer` per host (`host` means port 443, `host:port` is exact). `github-oauth` for `github.com` is used as the GitHub token when `GITHUB_TOKEN` is unset.
- `SIGHTREAD_NPM_TOKEN_<SCOPE>` (`@acme` reads `SIGHTREAD_NPM_TOKEN_ACME`; other characters become `_`): Bearer to that scope's registry only.

Without a token api.github.com allows 60 requests an hour. Sightread stops before sending once GitHub said none are left, or once what the run still plans to send (its estimate less what it sent) is more than GitHub said is left.

Example (E16, exit 3): `rhythm sightread composer: api.github.com allows 60 requests an hour without a token and this run needs about 111` / `set GITHUB_TOKEN (sent only to api.github.com); 23 of 111 packages were reviewed`.

## Verified by

The `verified-by` value of each package and its exact Method text:

| Source | Value | Method |
| --- | --- | --- |
| wp-plugin | `checksums` | `matches WordPress.org's own checksums (both come from WordPress.org, so this proves the copy was not changed on the way, not what the author intended)` |
| wp-plugin | `failed` | `does not match WordPress.org's own checksums` (Detail `3 files differ from WordPress.org's checksums`) |
| wp-plugin | `none` | `not verified: WordPress.org's checksums for this version are unavailable` |
| wp-plugin | `none` (archive limit) | `not verified: the archive hit a limit, so not every file could be checked against WordPress.org's checksums` |
| wp-theme | `tls` | `downloaded over TLS from WordPress.org; WordPress.org publishes no theme checksums` |
| wp-theme | `svn` | `every file matches themes.svn.wordpress.org` |
| wp-theme | `failed` | `does not match the theme's files on themes.svn.wordpress.org` |
| composer | `shasum` | `the archive's SHA-1 matches the dist.shasum its repository publishes` |
| composer | `commit` | `pinned to commit aef6ee7; Packagist publishes no archive hash for this package` |
| composer | `failed` | `the archive's SHA-1 does not match the dist.shasum its repository publishes` or `the archive is not the commit its repository pins` |
| composer | `none` | `not verified: the repository publishes neither an archive hash nor a commit for this version` |
| npm | `signature` | `SHA-512 matches dist.integrity and the registry signature verifies with a pinned npm key (this proves the registry published it, not that the content is harmless)` |
| npm | `integrity` | `SHA-512 matches the dist.integrity the registry publishes; no registry signature was checked` (older versions: `SHA-256 matches the dist.integrity ...`, `SHA-1 matches the dist.integrity ...` or `SHA-1 matches the dist.shasum the registry publishes; this version has no SHA-512 integrity`) |
| npm | `failed` | `the tarball does not match the dist.integrity the registry publishes`, `the tarball does not match the dist.shasum the registry publishes` or `the registry signature does not verify with a pinned npm key` |
| npm | `none` | `not verified: the registry publishes no hash for this version` |

The npm signing keys are pinned in `source/npm/keys.json`; a key must be both served by the registry and pinned. A private npm registry is checked by integrity only.

Example: `rhythm sightread npm left-pad --to 1.3.0` reports the candidate verified by `signature`.

## --svn-check

For themes, `--svn-check` lists `themes.svn.wordpress.org/<slug>/<v>/` and fetches every file (4 at a time, under the archive limits) to compare with the zip. A listing that names a path outside the theme folder gives `failed` with Detail `the SVN listing names a path outside the theme folder; nothing was fetched from it`. A check that can't finish stays `tls` with Detail `--svn-check could not finish: <reason>`.

Example: `rhythm sightread theme twentytwentyfour --svn-check` reports `svn` when every file matches.

## Limits and --max-size

| Limit | Default |
| --- | --- |
| Download (`--max-size`) | 256 MiB |
| Uncompressed archive | 1 GiB |
| One stored entry | 64 MiB |
| One analysed entry | 4 MiB |
| One JSON answer | 32 MiB |
| Entries per archive | 100,000 |
| Expansion ratio per entry | 200:1 (once over 1 MiB), on the compressed bytes actually read, never a header's claimed size |
| Request timeout (`--timeout`) | 30s; a download may take 20 timeouts and stops after one timeout without a byte |
| Retries (`--retries`) | 2 |
| Requests per host at once | 4 |

An entry past a per-entry limit, the ratio or the entry count is a finding and the package is not fully analysed. A whole archive past a cap is E11. Archive entries are never written by their own names: paths that escape the package, symlinks, hard links and devices are reported and not followed. A name with a colon or a Windows device name is refused too, with its own detail (`name has a colon, which Windows reads as a stream or drive`, `name is a Windows device such as NUL or COM1`) instead of `outside the package`. Nested archives are stored, never opened.

E11 (exit 3), download: `rhythm sightread npm: the 1.4.0 tarball of huge-pkg is over 256 MiB` / `raise --max-size if you expect that; a size jump this big is worth a look on its own`. Unpacked: `rhythm sightread npm: the 1.4.0 archive of huge-pkg unpacks to over 1 GiB` with the same hint. A JSON answer: `the answer of registry.npmjs.org is over 32 MiB`. A local file: `rhythm sightread: big.zip is over 256 MiB`.

Example: `rhythm sightread plugin big --to 1.0` with a 2 GiB unpacked zip prints `rhythm sightread plugin: the 1.0 archive of big unpacks to over 1 GiB` and stores nothing past the cap.

## Error texts

Exit 2 for E2, E3 and E12; exit 3 for E5, E7, E9, E10, E11 and E16.

- E2: `rhythm sightread plugin: wordpress.org has no plugin "contact-form7"` / `did you mean contact-form-7? A premium plugin has no official source: use --to-file <zip>`. Themes say `theme`. Composer: `rhythm sightread composer: packagist.org has no package "acme/nothing"` / `if it comes from a private repository, list it under sources.composer.repositories in .sightread/config.yaml`. npm: `rhythm sightread npm: registry.npmjs.org has no package "lodahs"` / `if it is private, set its scope's registry under sources.npm.scopes in .sightread/config.yaml`.
- E3: `rhythm sightread plugin: akismet has no version 9.9.9 on wordpress.org` / `newest: 5.3.5 · see them all: rhythm sightread plugin akismet --to list`. Also `rhythm sightread plugin: countdown-timer-ultimate is closed on wordpress.org (Security Issue); there is nothing to download` / `the wporg-closed finding says why; give a copy you trust with --to-file <zip>`, `rhythm sightread composer: acme/x 1.0.0 has no dist archive on packagist.org` / `Sightread reviews the archive Composer downloads; a release installed only from source can't be reviewed`, `rhythm sightread npm: left-pad 1.4.0 was unpublished from registry.npmjs.org` and `rhythm sightread npm: every version of gone was unpublished from registry.npmjs.org` / `there is nothing to download; review a copy you trust with --to-file <tgz>`.
- E5: `rhythm sightread plugin: couldn't verify countdown-timer-ultimate 2.6.8: wordpress.org checksums answered 503` / `not diffed; run again later, or --allow-unverified to review it anyway (the report marks it unverified)`. Other reasons: `wordpress.org has no checksums for this version`, `wordpress.org checksums could not be read`, `the archive hit a limit, so not every file could be checked`. A local side (`couldn't verify share-kit 3.2.0: local file`) says `not diffed; a local file has nothing to check it against: add --allow-unverified to review it (the report marks it unverified)`.
- GitHub's `/rate_limit` is read uncached (kind `rate`), so doctor shows the requests left right now.
- E7: `rhythm sightread: can't reach registry.npmjs.org (no such host)` / `check the connection or HTTPS_PROXY`. Reasons: `no such host`, `connection refused`, `refused: not a public address`, `certificate not trusted`, `timed out`, `connection dropped`, `network error`. A refused hop: `rhythm sightread: can't reach 169.254.169.254 (not an allowed registry host)` / `Sightread fetches only from the official registries and the mirrors you configure (the SIGHTREAD_* variables)`, or `rhythm sightread: can't reach example.com (only https is allowed)` / `plain http could let anyone in between swap the package; mirrors on 127.0.0.1 are the only exception`.
- E9: `rhythm sightread: api.wordpress.org asked us to slow down (429) and still did after 2 retries` / `run again in a few minutes or lower --jobs`.
- E10: `rhythm sightread composer: repo.acme.example answered 401 for acme/billing` / `set COMPOSER_AUTH (as Composer reads it); credentials go only to repo.acme.example`. For an npm scope: `set SIGHTREAD_NPM_TOKEN_ACME; it goes only to <host>`. For api.github.com: `set GITHUB_TOKEN; it goes only to api.github.com`.
- E11 and E16: see the sections above.
- A local archive that is neither zip nor tgz (E12): `rhythm sightread: notes.txt is not a zip or tgz archive` / `give the plugin, theme or package archive itself (.zip, .tgz or .tar.gz)`.

Example: `rhythm sightread plugin akismet --to 9.9.9` prints the E3 text above and exits 2.

## Offline

With `--offline` (or `RHYTHM_OFFLINE=1`) nothing is sent. Answers and archives come from the cache only, whatever their age. A miss is E7: `rhythm sightread: can't reach api.wordpress.org (offline and not cached)` or for an archive `rhythm sightread: can't reach downloads.wordpress.org (offline and hello-dolly.1.7.2.zip isn't cached)`, with the hint `with --offline only cached data and archives are used; run once without it to fill the cache`. OSV is not asked offline: `rhythm sightread: can't reach api.osv.dev (offline)`.

Example: `rhythm sightread plugin hello-dolly --offline` after one online run reviews from the cache with no request.

## Cache

Under the Sightread cache folder (kit `config.CacheDir("sightread")`):

- `meta/<kind>/<name>-<hash>.json`: registry answers. A key that could carry a credential (a query string, `@`, `=`) gets no readable name prefix.
- `meta/downloads/`: which stored blob each downloaded URL became, so `--offline` can reuse it.
- `blobs/<first two hex>/<sha256>`: file contents, stored once by SHA-256. Folders 0700, files 0600, never executable. Every read re-hashes; a blob that no longer matches is deleted and fetched again. A downloaded zip is checked before it is read. Storing the same bytes again replaces a torn or changed blob, so a bad one fails one run at most.

| Kind | Holds | Reused for |
| --- | --- | --- |
| `versions` | version lists | 10 minutes |
| `packument` | the full npm packument (publish dates) | 10 minutes |
| `meta` | per-version metadata, SVN properties, GitHub tag lookups | 7 days |
| `maintainers` | Packagist maintainers | 12 hours |
| `osv` | OSV advisory records | 6 hours |
| `keys` | npm registry signing keys | 24 hours |
| `checksums` | WordPress.org plugin checksums | forever |

Sightread never runs fetched code: no PHP, Node, npm scripts or Composer scripts. It only reads and compares files.

Example: `rhythm sightread cache prune --older 30d` removes blobs no archive index references and leftover temporary files older than 30 days.
