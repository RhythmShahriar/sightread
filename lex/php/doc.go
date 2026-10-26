// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package php is a PHP lexer for feature extraction. It tokenises code,
// never evaluates it.
//
// Lex covers its input exactly (the tokens' text joined is the input),
// runs in linear time with interpolation nested at most MaxDepth deep,
// and never fails: an unterminated string, heredoc, comment or attribute
// becomes one Error token holding the rest of the file, so a caller can
// report that part as unanalysed instead of misreading it. StringValue
// and Segments give the value of string literals for constant folding.
package php
