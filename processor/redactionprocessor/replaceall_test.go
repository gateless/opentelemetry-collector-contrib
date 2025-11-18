// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package redactionprocessor

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReplaceAllMatchedGroups(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		input    string
		expected string
		repl     func(string) string
	}{
		{
			name:     "SSN with named group",
			pattern:  `\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`,
			input:    "My SSN is 123-45-6789 and friend's is 987-65-4321",
			expected: "My SSN is ***6789 and friend's is ***4321",
			repl:     func(s string) string { return "***" },
		},
		{
			name:     "Email with named group",
			pattern:  `(?P<mask>[a-zA-Z0-9\._%+-]+)(?:@[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})`,
			input:    "Contact user@example.com or admin@test.org",
			expected: "Contact ***@example.com or ***@test.org",
			repl:     func(s string) string { return "***" },
		},
		{
			name:     "No matches",
			pattern:  `\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`,
			input:    "This text has no SSN patterns",
			expected: "This text has no SSN patterns",
			repl:     func(s string) string { return "***" },
		},
		{
			name:     "Multiple named groups",
			pattern:  `(?P<first>\w+)\s+(?P<last>\w+)`,
			input:    "John Doe and Jane Smith",
			// Matches "John Doe" (first="John", last="Doe") and "and Jane" (first="and", last="Jane")
			// "Jane Smith" is not matched because "Jane" was already consumed by the previous match
			expected: "XXX XXX XXX XXX Smith",
			repl:     func(s string) string { return "XXX" },
		},
		{
			name:     "Mixed named and unnamed groups",
			pattern:  `(?P<mask>\d{6})(?:\d{4})\b`,
			input:    "Account 1234567890",
			expected: "Account ******7890",
			repl:     func(s string) string { return "******" },
		},
		{
			name:     "JSON field masking",
			pattern:  `(?i)"(?:[^"]*(?:password|token)[^"]*)"\s*:\s*"(?P<mask>(?:\\.|[^"\\])*)"`,
			input:    `{"username":"john","password":"secret123"}`,
			expected: `{"username":"john","password":"***"}`,
			repl:     func(s string) string { return "***" },
		},
		{
			name:     "No named groups - should not replace",
			pattern:  `\d{3}-\d{2}-\d{4}`,
			input:    "SSN: 123-45-6789",
			expected: "SSN: 123-45-6789",
			repl:     func(s string) string { return "***" },
		},
		{
			name:     "Empty string",
			pattern:  `(?P<mask>\d+)`,
			input:    "",
			expected: "",
			repl:     func(s string) string { return "***" },
		},
		{
			name:     "Single character match",
			pattern:  `(?P<mask>a)`,
			input:    "abc",
			expected: "***bc",
			repl:     func(s string) string { return "***" },
		},
		{
			name:     "Consecutive matches",
			pattern:  `(?P<mask>\d)`,
			input:    "123",
			expected: "***",
			repl:     func(s string) string { return "*" },
		},
		{
			name:     "Unicode characters",
			pattern:  `(?P<mask>[\p{L}]+)`,
			input:    "Hello 世界 World",
			expected: "*** *** ***",
			repl:     func(s string) string { return "***" },
		},
		{
			name:     "Replacement function returns different values",
			pattern:  `(?P<mask>\d+)`,
			input:    "12 34 56",
			expected: "[12] [34] [56]",
			repl:     func(s string) string { return "[" + s + "]" },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re := regexp.MustCompile(tt.pattern)
			result := ReplaceAllMatchedGroups(tt.input, re, re.SubexpNames(), tt.repl)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestReplaceAllMatchedGroups_EdgeCases(t *testing.T) {
	t.Run("non-participating groups", func(t *testing.T) {
		// Pattern: named group for digits, required letters after
		re := regexp.MustCompile(`(?P<mask>\d+)[a-z]+`)
		input := "abc123def"
		result := ReplaceAllMatchedGroups(input, re, re.SubexpNames(), func(s string) string { return "***" })
		// The pattern matches "123def" and replaces "123" with "***", keeping "def"
		assert.Equal(t, "abc***def", result)
	})

	t.Run("nested named groups", func(t *testing.T) {
		// Nested named groups - both will be replaced
		re := regexp.MustCompile(`(?P<outer>(?P<inner>\d{3})-\d{2})-\d{4}`)
		input := "SSN: 123-45-6789"
		result := ReplaceAllMatchedGroups(input, re, re.SubexpNames(), func(s string) string { return "***" })
		// Both outer and inner groups are named, so both get replaced
		assert.NotEqual(t, "", result)
		assert.Contains(t, result, "***")
	})

	t.Run("overlapping matches", func(t *testing.T) {
		// Pattern that doesn't overlap in practice
		re := regexp.MustCompile(`(?P<mask>\d)`)
		input := "a1b2c3"
		result := ReplaceAllMatchedGroups(input, re, re.SubexpNames(), func(s string) string { return "*" })
		assert.Equal(t, "a*b*c*", result)
	})
}

func TestReplaceAllMatchedGroups_Performance(t *testing.T) {
	t.Run("large text with many matches", func(t *testing.T) {
		re := regexp.MustCompile(`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`)
		input := ""
		for i := 0; i < 100; i++ {
			input += "SSN: 123-45-6789 and 987-65-4321. "
		}
		
		result := ReplaceAllMatchedGroups(input, re, re.SubexpNames(), func(s string) string { return "***" })
		
		// Should have 200 replacements (2 per iteration * 100)
		assert.Contains(t, result, "SSN: ***6789")
		assert.NotContains(t, result, "123-45-")
		assert.NotContains(t, result, "987-65-")
	})
}

func TestReplaceAllMatchedGroups_Correctness(t *testing.T) {
	t.Run("preserves non-named groups", func(t *testing.T) {
		// Pattern: mask the user part (only word chars), keep the domain
		re := regexp.MustCompile(`\b(?P<user>\w+)(@\w+\.\w+)`)
		input := "Email: user@example.com"
		result := ReplaceAllMatchedGroups(input, re, re.SubexpNames(), func(s string) string { return "***" })
		
		assert.Equal(t, "Email: ***@example.com", result)
		assert.Contains(t, result, "@example.com")
		assert.NotContains(t, result, "user")
	})

	t.Run("handles special regex characters in replacement", func(t *testing.T) {
		re := regexp.MustCompile(`(?P<mask>\d+)`)
		input := "Number: 123"
		result := ReplaceAllMatchedGroups(input, re, re.SubexpNames(), func(s string) string { return "$$$" })

		assert.Equal(t, "Number: $$$", result)
	})

	t.Run("replacement function receives correct match", func(t *testing.T) {
		re := regexp.MustCompile(`(?P<mask>\d+)`)
		input := "12 34 56"
		var matches []string
		
		result := ReplaceAllMatchedGroups(input, re, re.SubexpNames(), func(s string) string {
			matches = append(matches, s)
			return "[" + s + "]"
		})
		
		assert.Equal(t, "[12] [34] [56]", result)
		assert.Equal(t, []string{"12", "34", "56"}, matches)
	})
}
