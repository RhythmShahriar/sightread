// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package notify tells people what a watch run found that is new: a
// Slack or Discord channel, a webhook of their own or an email inbox.
// A message is grouped by update ("wpforms-lite 1.9.1 → 1.9.2 HOLD on
// 14 sites"), names the top finding's title and the report path and
// never carries file contents, so a chat channel never receives package
// code or a secret.
//
// A notification URL names the backend:
//
//	slack://hooks.slack.com/services/T000/B000/XXXX    Slack incoming webhook
//	discord://discord.com/api/webhooks/123/abc         Discord webhook
//	webhook+https://hooks.example.com/sightread        JSON POST (Message)
//	smtp://user@mail.example.com:587?to=a@b.c&from=sightread@b.c
//	smtps://user@mail.example.com:465?to=a@b.c&from=sightread@b.c
//
// Webhook URLs carry their token in the path, so they are secrets: a
// Notifier prints as its scheme and host only and no error repeats the
// URL (SR-38). The SMTP password comes from SIGHTREAD_SMTP_PASSWORD.
package notify
