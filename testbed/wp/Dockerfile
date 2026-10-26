# Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
# SPDX-License-Identifier: MIT

# WordPress with WP-CLI inside, so testbed/bin/wp runs a quick
# `docker compose exec` instead of a new container each time.
FROM wordpress:cli-2.12.0-php8.3 AS cli
FROM wordpress:6.8.3-php8.3-apache
COPY --from=cli /usr/local/bin/wp /usr/local/bin/wp
