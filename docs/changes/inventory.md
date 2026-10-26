# Inventory and diff: what users see

This page records what the `inventory/` and `diff/` packages show to users: the files Sightread reads to learn what is installed, the commands it runs, the messages it prints and the rules it uses to compare files. Sightread only reads and compares files. It never runs package code, `composer` or `npm`. It never opens `wp-config.php`, `.env` or a database.

## Lockfiles

For Composer, Sightread reads `composer.lock`, with `composer.json` next to it to tell direct from transitive packages and `vendor/composer/installed.json` (the `config.vendor-dir` of composer.json, default `vendor`) for the install paths.

For npm it reads the first of these it finds in a folder, in this order:

1. `npm-shrinkwrap.json`
2. `package-lock.json` (lockfile versions 1, 2 and 3)
3. `pnpm-lock.yaml` (pnpm 5, 6 and 9)
4. `yarn.lock` (yarn classic and Berry)
5. `bun.lock`

`bun.lockb`, Bun's binary lockfile, can't be read. `bun.lock` next to it is read as usual.

A lockfile is capped at 64 MiB. In `pnpm-lock.yaml` and Berry `yarn.lock`, YAML aliases may expand to at most 10,000 nodes each and the document to 2,000,000 nodes and 64 levels.

### .npmrc

Only `@scope:registry=<url>` lines are read, from the project `.npmrc` and `~/.npmrc`. A user and password in the URL are dropped. Every other line, `_authToken` and `_auth` included, is skipped and never stored. A package in such a scope is private: it is reviewed only when `sources.npm.scopes` in `.sightread/config.yaml` names the scope.

A company mirror set only with `registry=` is not read. Set `sources.npm.registry` in the config instead; otherwise packages from the mirror count as tarballs and are not checked.

## WordPress

A WordPress site is a folder with `wp-includes/version.php` and `wp-content/`. Sightread looks for one up to 6 folders down, skipping `node_modules`, `vendor` and `.git`. It reads the shallowest. When it finds more than one it warns:

```
found 2 WordPress sites under <root>: read <first>, not <others>; name one with --path to read another
```

It reads the plugin and theme headers (`Plugin Name`, `Theme Name`, `Version`, `Update URI`) the way WordPress does and never runs the files.

### The --wp command

`--wp "<prefix>"` reads a site through WP-CLI. The prefix is split like a shell would split it, without running a shell: `;`, `|`, `&`, `<`, `>`, a backtick and `$(` are refused. Sightread runs only these four commands, each with a 60 second timeout and a 16 MiB output cap:

```
<prefix> plugin list --format=json --fields=name,status,version,update_version,auto_update
<prefix> theme list --format=json --fields=name,status,version,update_version,auto_update
<prefix> core version
<prefix> option get auto_update_plugins --format=json
```

When plugins update themselves, Sightread warns:

```
auto-updates are on for 3 plugins on <site>: WordPress may install them before you review (wp plugin auto-updates disable --all)
```

`<site>` is the `--path=` value of the prefix, else the prefix with secrets masked.

### Tuner reports

`--from-tuner <report.json>` reads the plugins and themes a `rhythm-tuner` report found (schemas `rhythm-tuner/v0` and `rhythm-tuner/v1`).

## Not checked

These entries list what Sightread found but did not review, with the reason, the text and the hint it prints.

| Reason | Text | Hint |
|---|---|---|
| `no-header` | plugin folder has no Plugin Name header | check the folder by hand or remove it |
| `no-header` | theme folder has no Theme Name header in style.css | check the folder by hand or remove it |
| `not-wporg` | not on WordPress.org | give the vendor's zip with --to-file |
| `private` | private registry or repository | set the registry in .sightread/config.yaml sources |
| `vcs` | git, path or tarball dependency | Sightread reviews registry releases only |
| `mu-plugin` | must-use plugins and drop-ins have no update channel | |
| `core` | WordPress core is out of scope in v1 | WordPress core updates come signed from WordPress.org |
| `unsupported-lock` | bun.lockb is Bun's binary lockfile, which Sightread can't read | run bun install --save-text-lockfile once to write bun.lock |
| `fetch-failed` | the Tuner report has no version for it | give the version with --from <version>, or read the site with --path or --wp |

A plugin is `not-wporg` when its `Update URI` points anywhere other than WordPress.org, when it is `Update URI: false` or when its folder name can't be a WordPress.org slug.

## Changes in a pull request

`rhythm-sightread changes` compares the lockfiles of a branch with the same files at a base commit.

- The base is `--base <ref>` when given. Otherwise it is `origin/$GITHUB_BASE_REF` in a GitHub Actions pull request, else `git merge-base HEAD origin/HEAD`.
- The lockfiles are those named with `--lockfile`, else every `composer.lock` and the first npm lockfile of every folder up to 6 down, skipping `node_modules`, `vendor` and `.git`.
- Git runs as `git -C <repo> -c core.fsmonitor=false -c core.hooksPath=/dev/null show --no-textconv <ref>:./<path>`, without the caller's `GIT_*` variables, with a 60 second timeout. No hook, filter or textconv driver of the repository can run.
- A ref must match `[A-Za-z0-9._/@^~-]`, be at most 200 characters, hold no `..` and not start with `-`.
- `--before <old lock> --after <new lock>` compares two files without git. The `--after` file must carry a lockfile name (`composer.lock`, `package-lock.json`, `yarn.lock` and so on) and its name sets the format of both. The `--before` file may have any name, so `git show main:package-lock.json > /tmp/old-lock.json` works; when both names are lockfile names of different kinds the run stops with `--before <a> and --after <b> are different kinds of lockfile`. The manifest next to `--before` is read only when that file carries a lockfile name.
- A bump is any package whose version, integrity, resolved URL or reference changed, plus any added package. Removed packages are not reviewed.
- A lockfile missing at the base gives the warning `<file> is not at <ref>, so every package in it counts as added`.

Git problems exit with code 2 and no E code:

```
git is needed to read <file> at <ref> and wasn't found
  install git, or give --before <old lock> --after <new lock> instead

<repo> is not in a git repository, so there is no base to compare with
  give --before <old lock> --after <new lock> instead

found no base to compare with: HEAD and origin/HEAD share no commit, or origin/HEAD is not set
  give --base <ref> (for example --base origin/main), or give --before <old lock> --after <new lock> instead

<ref> is not a commit in this repository
  fetch it first (git fetch origin), or give --before <old lock> --after <new lock> instead
```

## Errors

Each error exits with code 2.

E1, nothing installed:

```
no WordPress site under <root> (looked 6 folders down for wp-includes/version.php and wp-content)
  name the site with --path /var/www/site, read it with --wp "wp --path=..." or give the version: --from <version>

nothing installed found under <root> (looked for a WordPress site up to 6 folders down, composer.lock and npm lockfiles)
  name the site or project folder, read a site with --wp "wp --path=..." or give a Tuner report with --from-tuner <report.json>

--wp "<cmd>": <what>
  check that <cmd> plugin list works on its own
  or name the site with --path /var/www/site, or give the version: --from <version>
```

E4, no lockfile:

```
no lockfile in <dir> (looked for npm-shrinkwrap.json, package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lock)
  run your package manager once to write one; Sightread compares versions a lockfile pins
```

With `composer` the list is `(looked for composer.lock)`. A folder that is missing gives `(no such folder)` instead.

E8, a lockfile Sightread can't read:

```
bun.lockb is Bun's binary lockfile, which Sightread can't read
  run bun install --save-text-lockfile once to write bun.lock

<name> is not a lockfile Sightread reads
  want composer.lock, npm-shrinkwrap.json, package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lock

<file> can't be read: <reason>
  run your package manager once to write it again
```

## Comparing two versions

The diff pairs files by path. Beyond that:

- A removed and an added file with the same SHA-256 are a rename.
- A removed and an added text file of the same kind are a rename when they share at least 60% of their distinct non-blank lines (counted over both files together). This search runs only when each side has at most 2,000 unpaired files.
- A file whose bytes changed only from CRLF to LF line endings (or back) is reported in one line and shows no hunks.
- A binary file shows one line: `binary file changed (2.0 KiB to 3.0 MiB)`.
- Minified files and lines over 64 KiB are compared in pieces cut after `;`, `{`, `}` and `,`, so a change inside a one-line bundle shows the part that changed.

## Drift

Drift compares an installed plugin with the official copy of the same version, file by file by SHA-256. It reports the files that differ, the official files missing from the site and the files only the site has. These files are left out, since sites change them without touching code:

- `readme.txt`
- `.DS_Store`
- `*.mo` translation files
- `*.po`, `*.pot` and `*.json` translation files in a `languages` folder

Translation files ending `.l10n.php` are PHP and are always compared. File modes are not compared.

When fewer than half the official files match, the installed copy is not the package WordPress.org knows (a different plugin with the same name). Sightread then says so instead of showing a diff.
