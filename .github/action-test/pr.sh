#!/usr/bin/env bash
# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: MIT

# Makes the tiny pull request action-test.yml reviews: a git repository
# whose base branch sr-base pins leftpadplus 1.0.0 in package-lock.json
# and whose checked-out head branch moves it to 1.0.1 and adds expresss
# (base/ and head/ here, the testbed's b13 pair). Its origin is a bare
# repository next to it, so the Action's fetch of the base ref works
# with no network.
#
#   pr.sh make DIR            DIR/origin.git and DIR/repo
#   pr.sh allow DIR REPORT    commits .sightread/allowed.yaml to the head
#                             only, allowing every update REPORT (a
#                             Sightread JSON report of DIR/repo) reviewed
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)

git_in() {
	git -C "$1" -c user.name="Sightread action test" -c user.email=action-test@example.invalid \
		-c commit.gpgsign=false "${@:2}"
}

make_pr() {
	local dir=${1:?usage: pr.sh make DIR}
	rm -rf "$dir"
	mkdir -p "$dir/repo"
	git init -q --bare "$dir/origin.git"
	git init -q -b sr-base "$dir/repo"
	git_in "$dir/repo" remote add origin "file://$dir/origin.git"
	cp "$here/base/package-lock.json" "$dir/repo/"
	git_in "$dir/repo" add package-lock.json
	git_in "$dir/repo" commit -q -m "chore: pin leftpadplus 1.0.0"
	git_in "$dir/repo" push -q origin sr-base
	git_in "$dir/repo" switch -q -c sr-head
	cp "$here/head/package-lock.json" "$dir/repo/"
	git_in "$dir/repo" commit -q -am "chore(deps): bump leftpadplus and add expresss"
	git_in "$dir/repo" push -q origin sr-head
	git_in "$dir/repo" log --oneline --all
}

allow() {
	local dir=${1:?usage: pr.sh allow DIR REPORT} report=${2:?usage: pr.sh allow DIR REPORT}
	mkdir -p "$dir/repo/.sightread"
	{
		echo "allowed:"
		jq -r '.data.updates[] | select(.to.sha256 != null and .to.sha256 != "") |
			"  - package: \(.ecosystem):\(.name)\n    version: \"\(.to.version)\"\n    sha256: \(.to.sha256)\n    reason: reviewed in the action test\n    by: action-test\n    date: \"2026-10-26\""' "$report"
	} >"$dir/repo/.sightread/allowed.yaml"
	cat "$dir/repo/.sightread/allowed.yaml"
	# Two updates in the report means two entries; anything less would
	# make the trust-pr-allow case pass for the wrong reason.
	test "$(grep -c '^  - package:' "$dir/repo/.sightread/allowed.yaml")" = "$(jq '.data.updates | length' "$report")"
	git_in "$dir/repo" add .sightread/allowed.yaml
	git_in "$dir/repo" commit -q -m "chore: allow the reviewed versions in this pull request"
}

case "${1:-}" in
make)
	shift
	make_pr "$@"
	;;
allow)
	shift
	allow "$@"
	;;
*)
	echo "usage: pr.sh make DIR | pr.sh allow DIR REPORT" >&2
	exit 2
	;;
esac
