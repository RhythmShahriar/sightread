#!/usr/bin/env bash
# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: MIT

# Starts what action-test.yml runs the Action against, on 127.0.0.1 only.
#
#   serve.sh registry          the testbed's fixture registry (WordPress.org,
#                              Packagist, GitHub, npm and OSV on 18900-18904)
#                              and points every later step at it through
#                              $GITHUB_ENV
#   serve.sh release DIR PORT  a release folder (release.sh) as the mirror
#                              the Action's download-url input names
#
# Run it from the repository root. Each server runs in the background
# until the job ends; its log is in $RUNNER_TEMP.
set -euo pipefail

tmp=${RUNNER_TEMP:?}

# wait_port PORT LOG waits until something listens on 127.0.0.1:PORT.
wait_port() {
	for _ in $(seq 60); do
		if (: >"/dev/tcp/127.0.0.1/$1") 2>/dev/null; then
			return 0
		fi
		sleep 0.5
	done
	echo "::error::nothing answered on 127.0.0.1:$1"
	cat "$2"
	exit 1
}

registry() {
	local state=$tmp/sr-registry-state bin=$tmp/sr-registry
	mkdir -p "$state"
	GOWORK=off go build -o "$bin" ./testbed/registry/cmd/registry
	nohup "$bin" -packages testbed/packages -state "$state" >"$tmp/sr-registry.log" 2>&1 &
	for port in 18900 18901 18902 18903 18904 18908; do
		wait_port "$port" "$tmp/sr-registry.log"
	done
	test -s "$state/ca.pem"
	test -s "$state/npm-keys.json"
	# The same variables the testbed README gives for a run by hand. The
	# Action's steps inherit them, so no request goes to a real registry.
	{
		echo "SSL_CERT_FILE=$state/ca.pem"
		echo "SIGHTREAD_NPM_EXTRA_KEYS=$state/npm-keys.json"
		echo "SIGHTREAD_WPORG_API=https://127.0.0.1:18900"
		echo "SIGHTREAD_WPDL_API=https://127.0.0.1:18900"
		echo "SIGHTREAD_WPSVN=https://127.0.0.1:18900/svn/plugins"
		echo "SIGHTREAD_WPTHEMESVN=https://127.0.0.1:18900/svn/themes"
		echo "SIGHTREAD_PACKAGIST=https://127.0.0.1:18901"
		echo "SIGHTREAD_PACKAGIST_META=https://127.0.0.1:18901"
		echo "SIGHTREAD_GITHUB_API=https://127.0.0.1:18902"
		echo "SIGHTREAD_GITHUB_CODELOAD=https://localhost:18908"
		echo "SIGHTREAD_NPM_REGISTRY=https://127.0.0.1:18903"
		echo "SIGHTREAD_OSV_API=https://127.0.0.1:18904"
		echo "RHYTHM_NO_UPDATE_CHECK=1"
	} >>"${GITHUB_ENV:?}"
	echo "fixture registry up; CA in $state/ca.pem"
}

release() {
	local dir=${1:?usage: serve.sh release DIR PORT} port=${2:?usage: serve.sh release DIR PORT}
	test -s "$dir/checksums.txt"
	nohup python3 -m http.server --bind 127.0.0.1 --directory "$dir" "$port" >"$tmp/sr-release-$port.log" 2>&1 &
	wait_port "$port" "$tmp/sr-release-$port.log"
	echo "release mirror: http://127.0.0.1:$port/ serves $dir"
}

case "${1:-}" in
registry) registry ;;
release)
	shift
	release "$@"
	;;
*)
	echo "usage: serve.sh registry | serve.sh release DIR PORT" >&2
	exit 2
	;;
esac
