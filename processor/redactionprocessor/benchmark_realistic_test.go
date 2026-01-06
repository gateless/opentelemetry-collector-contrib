// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package redactionprocessor

import (
	"context"
	"fmt"
	"testing"

	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap/zaptest"
)

// BenchmarkRealisticConfig tests a realistic configuration with multiple patterns
func BenchmarkRealisticConfig(b *testing.B) {
	config := &Config{
		AllowAllKeys:   true,
		RedactAllTypes: true,
		BlockedKeyPatterns: []string{
			".*ssn.*",
			".*birth.*",
			".*email.*",
			".*street.*",
			".*address.*",
			".*token.*",
			".*secret.*",
			".*username.*",
			".*password.*",
		},
		BlockedValues: []string{
			// SSN - hyphenated form
			`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`,
			// Bare 9-digit SSN
			`\b(?P<mask>\d{5})(:?\d{4})\b`,
			// Phone - hyphenated
			`\b(?P<mask>\d{3}-\d{3}-)(:?\d{4})\b`,
			// Bare 10-digit phone
			`\b(?P<mask>\d{6})(:?\d{4})\b`,
			// Email addresses
			`(?P<mask>[a-zA-Z0-9\._%+-]+)(?:@[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})`,
			// JSON Key Patterns
			`(?i)"(?:[^"]*(?:birth|street|address|token|secret|username|password)[^"]*)"\s*:\s*"(?P<mask>(?:\\.|[^"\\])*)"`,
			// Digit blockers for account numbers
			`\b(?P<mask>[\d -]{5,100})(?:[\d -]{4})\b`,
		},
		Summary: "silent",
	}

	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		inBatch := createRealisticBatch()
		_, _ = processor.processTraces(context.Background(), inBatch)
	}
}

// BenchmarkRealisticConfigWithHits tests when patterns actually match
func BenchmarkRealisticConfigWithHits(b *testing.B) {
	config := &Config{
		AllowAllKeys:   true,
		RedactAllTypes: true,
		BlockedKeyPatterns: []string{
			".*ssn.*",
			".*birth.*",
			".*email.*",
			".*street.*",
			".*address.*",
			".*token.*",
			".*secret.*",
			".*username.*",
			".*password.*",
		},
		BlockedValues: []string{
			`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`,
			`\b(?P<mask>\d{5})(:?\d{4})\b`,
			`\b(?P<mask>\d{3}-\d{3}-)(:?\d{4})\b`,
			`\b(?P<mask>\d{6})(:?\d{4})\b`,
			`(?P<mask>[a-zA-Z0-9\._%+-]+)(?:@[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})`,
			`(?i)"(?:[^"]*(?:birth|street|address|token|secret|username|password)[^"]*)"\s*:\s*"(?P<mask>(?:\\.|[^"\\])*)"`,
			`\b(?P<mask>[\d -]{5,100})(?:[\d -]{4})\b`,
		},
		Summary: "silent",
	}

	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		inBatch := createBatchWithSensitiveData()
		_, _ = processor.processTraces(context.Background(), inBatch)
	}
}

func createRealisticBatch() ptrace.Traces {
	batch := ptrace.NewTraces()

	// Create 10 resource spans
	for i := 0; i < 10; i++ {
		rs := batch.ResourceSpans().AppendEmpty()

		rs.Resource().Attributes().PutStr("service.name", fmt.Sprintf("service-%d", i))
		rs.Resource().Attributes().PutStr("host.name", fmt.Sprintf("host-%d", i))

		ils := rs.ScopeSpans().AppendEmpty()
		// 50 spans per resource
		for j := 0; j < 50; j++ {
			span := ils.Spans().AppendEmpty()
			span.SetName(fmt.Sprintf("operation-%d", j))
			span.SetTraceID([16]byte{byte(i), byte(j), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14})
			span.SetSpanID([8]byte{byte(i), byte(j), 1, 2, 3, 4, 5, 6})

			// Realistic attributes that DON'T match sensitive patterns
			attrs := span.Attributes()
			attrs.PutStr("http.method", "GET")
			attrs.PutInt("http.status_code", 200)
			attrs.PutStr("http.url", fmt.Sprintf("/api/v1/users/%d", j))
			attrs.PutStr("user.id", fmt.Sprintf("usr_%d", j))
			attrs.PutStr("session.id", fmt.Sprintf("sess_%d_%d", i, j))
			attrs.PutStr("request.id", fmt.Sprintf("req_%d_%d", i, j))
			attrs.PutBool("cache.hit", j%2 == 0)
			attrs.PutDouble("duration.ms", float64(j*10))
			attrs.PutStr("db.system", "postgresql")
			attrs.PutStr("db.name", "appdb")
			attrs.PutStr("db.statement", "SELECT id, name FROM products WHERE category = ?")
			attrs.PutStr("component", "http")
			attrs.PutStr("peer.service", "backend-api")
			attrs.PutStr("environment", "testing")
			attrs.PutStr("version", "v2.3.1")
		}
	}

	return batch
}

func createBatchWithSensitiveData() ptrace.Traces {
	batch := ptrace.NewTraces()
	rs := batch.ResourceSpans().AppendEmpty()
	ils := rs.ScopeSpans().AppendEmpty()

	for i := 0; i < 100; i++ {
		span := ils.Spans().AppendEmpty()
		span.SetName(fmt.Sprintf("span-%d", i))
		span.SetTraceID([16]byte{byte(i), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})

		attrs := span.Attributes()
		// Attributes that will match patterns
		attrs.PutStr("user_email", fmt.Sprintf("user%d@example.com", i))
		attrs.PutStr("ssn_number", "123-45-6789")
		attrs.PutStr("phone_number", "555-123-4567")
		attrs.PutStr("account_number", "1234567890123456")
		attrs.PutStr("birth_date", "1990-01-15")
		attrs.PutStr("street_address", "123 Main Street")
		attrs.PutStr("api_token", "sk-abc123def456")
		attrs.PutStr("password_hash", "hashed_value_123")
		attrs.PutStr("username", fmt.Sprintf("user%d", i))
		
		// Mix in some normal attributes
		attrs.PutStr("request.id", fmt.Sprintf("req-%d", i))
		attrs.PutInt("http.status_code", 200)
		attrs.PutStr("service.version", "v1.0.0")
	}

	return batch
}
