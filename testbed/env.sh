# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: MIT

# shellcheck shell=sh

# Points rhythm-sightread at the fixture registry `make up` started.
# Source it from testbed/:  . ./env.sh
# It reads the registry's ports from state/port-base, so it follows
# make up PORT_BASE=<port>. Nothing it sets reaches a real registry:
# HTTPS_PROXY points at a closed port, so a missed base fails loudly.

if [ ! -f state/ca.pem ]; then
	echo "env.sh: no state/ca.pem here; run it from testbed/ after make up" >&2
	# shellcheck disable=SC2317 # exit runs only when the file was run, not sourced
	return 1 2>/dev/null || exit 1
fi
_sr_base=18900
[ -f state/port-base ] && _sr_base=$(cat state/port-base)
_sr_at="https://127.0.0.1"
export SSL_CERT_FILE="$PWD/state/ca.pem" SIGHTREAD_NPM_EXTRA_KEYS="$PWD/state/npm-keys.json"
export SIGHTREAD_WPORG_API="$_sr_at:$_sr_base" SIGHTREAD_WPDL_API="$_sr_at:$_sr_base"
export SIGHTREAD_WPSVN="$_sr_at:$_sr_base/svn/plugins" SIGHTREAD_WPTHEMESVN="$_sr_at:$_sr_base/svn/themes"
export SIGHTREAD_PACKAGIST="$_sr_at:$((_sr_base + 1))" SIGHTREAD_PACKAGIST_META="$_sr_at:$((_sr_base + 1))"
export SIGHTREAD_GITHUB_API="$_sr_at:$((_sr_base + 2))" SIGHTREAD_GITHUB_CODELOAD="https://localhost:$((_sr_base + 8))"
export SIGHTREAD_NPM_REGISTRY="$_sr_at:$((_sr_base + 3))" SIGHTREAD_OSV_API="$_sr_at:$((_sr_base + 4))"
export HTTPS_PROXY=http://127.0.0.1:23399 RHYTHM_NO_UPDATE_CHECK=1
echo "Sightread now reads WordPress.org, Packagist, GitHub, npm and OSV from 127.0.0.1:$_sr_base-$((_sr_base + 4))."
unset _sr_base _sr_at
