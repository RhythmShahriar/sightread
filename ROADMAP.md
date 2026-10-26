# Roadmap

What we plan for Sightread. Plans change as we learn, so treat this as a direction, not a promise.

Have an idea or an update pattern we miss? Start a thread in [Discussions: Ideas](https://github.com/RhythmShahriar/sightread/discussions/categories/ideas). Want to help now? Pick a [good first issue](https://github.com/RhythmShahriar/sightread/labels/good%20first%20issue).

## Now

- **Sightread 1.0.** WordPress.org plugins and themes, Composer and npm; 48 signals with their false-alarm guards; verified sources; allow entries bound to the archive hash; `changes` for lockfile pull requests; `watch` for fleets; `--soundcheck` on a Roadie copy; the GitHub Action.
- **A public benchmark.** The testbed's bad, good and environment scenarios with catch rate, false alarms and speed, plus a false-alarm pass over popular real updates.

## Next

- **Into the kit.** Move the notifier, the schedule, SARIF output and the redirect allowlist into the shared Rhythm kit (0.9.0 or later), so every tool uses one copy.
- **Soundcheck reads the report.** `rhythm soundcheck wp-update --from-sightread report.json` updates ROUTINE and ALLOWED plugins first and skips the ones on HOLD.
- **Tuner points the way.** Tuner's "update available" line suggests `rhythm sightread all <dir>` before updating.

## Later

- **WordPress core updates.** Core is out of scope in 1.0; WordPress.org signs those releases.
- **Premium vendor channels.** Fetch Gravity Forms, ACF Pro and other premium plugins from their vendor's update channel instead of a zip you download with `--to-file`.
- **More ecosystems.** PyPI, RubyGems and Go modules.

## Not planned

- **A hosted service.** Sightread stays local, free and without an account.
- **Applying updates for you.** Sightread tells you what an update changes; installing it stays your decision and your tooling's job.
