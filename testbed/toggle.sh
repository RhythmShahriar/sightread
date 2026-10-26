#!/bin/sh
# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: MIT

# Sets a scenario's state for the fixture registry, which reads it on
# every request, so nothing restarts:
#
#   ./toggle.sh b01 good    withhold b01's candidate (no update offered)
#   ./toggle.sh b01 bad     publish it (the default with no state file)
#   ./toggle.sh all good    every scenario
#   ./toggle.sh status      list the withheld ones
set -eu

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
state=$here/state
mkdir -p "$state"

usage() {
	echo "usage: toggle.sh <id>|all good|bad, or toggle.sh status" >&2
	exit 2
}

if [ "${1:-}" = status ]; then
	found=0
	for f in "$state"/*; do
		[ -f "$f" ] || continue
		name=$(basename -- "$f")
		[ -d "$here/packages/$name" ] || continue
		if [ "$(cat "$f")" = good ]; then
			echo "$name: good (candidate withheld)"
			found=1
		fi
	done
	[ "$found" = 1 ] || echo "every candidate is published (all bad)"
	exit 0
fi

[ $# -eq 2 ] || usage
case $2 in
good | bad) ;;
*) usage ;;
esac

if [ "$1" = all ]; then
	for d in "$here"/packages/*/; do
		printf '%s\n' "$2" > "$state/$(basename -- "$d")"
	done
	exit 0
fi

# Scenario ids (b01) name their folder by prefix (b01-widget).
match=
for d in "$here"/packages/"$1" "$here"/packages/"$1"-*; do
	[ -d "$d" ] && match="$match $(basename -- "$d")"
done
[ -n "$match" ] || { echo "toggle.sh: no scenario folder for $1" >&2; exit 2; }
for name in $match; do
	printf '%s\n' "$2" > "$state/$name"
	echo "$name: $2"
done
