#!/bin/sh
# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: MIT

# Installs WordPress and the old versions of the plugins the e15 cases
# update, as www-data inside the wp container. Run by `make up` and
# again by the benchmark between cases, so it is safe to repeat: each
# run puts the old versions back.
set -eu

wp="wp --path=/var/www/html"
url=http://127.0.0.1:18907

# The entrypoint copies WordPress into the volume on first start.
i=0
until [ -f /var/www/html/wp-config.php ]; do
	i=$((i + 1))
	[ "$i" -le 60 ] || { echo "seed: wp-config.php never appeared" >&2; exit 1; }
	sleep 1
done

if ! $wp core is-installed 2>/dev/null; then
	$wp core install --url="$url" --title="Sightread testbed" \
		--admin_user=admin --admin_password=admin \
		--admin_email=admin@example.test --skip-email
fi

for slug in e15-soundcheck b01-widget; do
	dest=/var/www/html/wp-content/plugins/$slug
	rm -rf "$dest"
	cp -R "/fixtures/$slug/old" "$dest"
	$wp plugin is-active "$slug" || $wp plugin activate "$slug" >/dev/null
done
$wp plugin list --fields=name,version,status
