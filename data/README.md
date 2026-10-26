# Data packs

Sightread ships two data packs, embedded in the binary and refreshed
with `rhythm-sightread update` from the latest release:

| Pack | Release asset | Holds |
|---|---|---|
| `sightread-names` | `sightread-names.json` | the popular names typosquat compares new dependencies with |
| `sightread-signals` | `sightread-signals.tar.gz` | the rule files of `detect/code/rules`, `domains-ok.json` and the version marker `signals/pack.json` |

Files here:

- `names/wp-plugins.json`: the 1,500 most installed WordPress.org plugins.
  Derived from `tuner/fingerprint/data/top-plugins.json` (taken
  2026-10-24, most installed first).
- `names/wp-themes.json`, `names/npm.json`, `names/packagist.json`: the
  most installed WordPress.org themes, the most popular npm packages and
  the most downloaded Packagist packages. The lists in this commit are a
  hand-picked seed of well known names; `go run ./data/gen` fills them to
  500, 5,000 and 2,000 names from the public sources at release prep.
- `domains-ok.json`: the known-safe hosts of PRD 12.1 (`outbound-new-domain`
  is info for them).
- `signals/pack.json`: the version of the signals pack. Bump it to
  today's date (`YYYY.MM.DD`) whenever a file under `detect/code/rules`
  or `domains-ok.json` changes, so the newer pack wins on every machine.
- `release/`: the two release assets, written by
  `go run ./data/gen --pack` from the embedded files with no network.
  `TestReleasePacksCurrent` fails while they are stale.

Every file is `{"version": "YYYY.MM.DD", ...}`: the date the data was
taken. A pack's version is the newest of its files.

## How `update` checks a pack

1. Ask the GitHub API for the latest Sightread release (or the pinned
   one with `update --pin sightread-names=1.0.1`).
2. Download `checksums.txt` and `checksums.txt.sigstore.json` and check
   the Sigstore signature: the shared `release-go.yml` workflow at
   `refs/heads/master`, building `RhythmShahriar/sightread` at that tag.
3. Download both assets and check each against `checksums.txt`, then
   parse them.
4. Only then write them, each atomically, to `<cache>/data/` with
   `packs.json`, the record of what was verified.

Offline, or on any failure, the packs already there stay and `update`
exits 3. On every run a cached pack is used only when it still hashes
to the recorded sha256 and is newer than the embedded one (or was
pinned); `--no-signal-updates` uses the embedded packs only. The packs
are data: nothing in them is ever run.
