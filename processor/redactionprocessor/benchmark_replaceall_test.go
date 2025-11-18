// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package redactionprocessor

import (
	"regexp"
	"testing"
)

// BenchmarkReplaceAllMatchedGroups_SSN benchmarks SSN redaction
func BenchmarkReplaceAllMatchedGroups_SSN(b *testing.B) {
	re := regexp.MustCompile(`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`)
	input := "My SSN is 123-45-6789 and my friend's is 987-65-4321"
	repl := func(s string) string { return "***" }

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ReplaceAllMatchedGroups(input, re, repl)
	}
}

// BenchmarkReplaceAllMatchedGroups_Email benchmarks email masking
func BenchmarkReplaceAllMatchedGroups_Email(b *testing.B) {
	re := regexp.MustCompile(`(?P<mask>[a-zA-Z0-9\._%+-]+)(?:@[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})`)
	input := "Contact user@example.com or admin@test.org for more info"
	repl := func(s string) string { return "***" }

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ReplaceAllMatchedGroups(input, re, repl)
	}
}

// BenchmarkReplaceAllMatchedGroups_MultipleMatches benchmarks multiple matches
func BenchmarkReplaceAllMatchedGroups_MultipleMatches(b *testing.B) {
	re := regexp.MustCompile(`(?P<mask>\d{6})(?:\d{4})\b`)
	input := "Account 1234567890, phone 5551234567, id 9876543210"
	repl := func(s string) string { return "******" }

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ReplaceAllMatchedGroups(input, re, repl)
	}
}

// BenchmarkReplaceAllMatchedGroups_LargeText benchmarks with large text
func BenchmarkReplaceAllMatchedGroups_LargeText(b *testing.B) {
	re := regexp.MustCompile(`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`)
	// Build a large text with multiple SSNs
	input := ""
	for i := 0; i < 100; i++ {
		input += "Here is some text with SSN 123-45-6789 and more text with 987-65-4321. "
	}
	repl := func(s string) string { return "***" }

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ReplaceAllMatchedGroups(input, re, repl)
	}
}

// BenchmarkReplaceAllMatchedGroups_NoMatch benchmarks no matches case
func BenchmarkReplaceAllMatchedGroups_NoMatch(b *testing.B) {
	re := regexp.MustCompile(`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`)
	input := "This text has no SSN patterns at all, just normal text"
	repl := func(s string) string { return "***" }

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ReplaceAllMatchedGroups(input, re, repl)
	}
}

// BenchmarkReplaceAllMatchedGroups_JSON benchmarks JSON patterns
func BenchmarkReplaceAllMatchedGroups_JSON(b *testing.B) {
	re := regexp.MustCompile(`(?i)"(?:[^"]*(?:password|token)[^"]*)"\s*:\s*"(?P<mask>(?:\\.|[^"\\])*)"`)
	input := `{"username":"john","password":"secret123","api_token":"sk-abc123def456"}`
	repl := func(s string) string { return "***" }

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ReplaceAllMatchedGroups(input, re, repl)
	}
}

// Benchmark the standard ReplaceAllStringFunc for comparison
func BenchmarkReplaceAllStringFunc_SSN(b *testing.B) {
	re := regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	input := "My SSN is 123-45-6789 and my friend's is 987-65-4321"
	repl := func(s string) string { return "***-**-****" }

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = re.ReplaceAllStringFunc(input, repl)
	}
}
