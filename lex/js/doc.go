// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package js is a JavaScript lexer for feature extraction. It tokenises
// code, never evaluates it.
//
// Lex covers its input exactly, runs in linear time and never fails. It
// tells regular expressions from division by the previous significant
// token, tracks template literal nesting with a stack (no recursion)
// and tolerates JSX. StringValue, TemplateText and IdentName give the
// values of literals and escaped names for constant folding.
package js
