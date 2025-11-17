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

// BenchmarkRealisticWorkload measures performance with a more realistic workload:
// - Multiple resource spans (10)
// - Multiple spans per resource (50)
// - More attributes per span (20)
func BenchmarkRealisticWorkload(b *testing.B) {
	config := &Config{
		AllowedKeys:   []string{"id", "group", "name", "url", "service.name", "service.version", "http.method", "http.status_code"},
		BlockedValues: []string{"4[0-9]{12}(?:[0-9]{3})?", "sk-[a-zA-Z0-9]{48}"},
		IgnoredKeys:   []string{"safe_attribute"},
		Summary:       "info", // Use info instead of debug to reduce overhead
	}

	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		inBatch := createRealisticBatch()
		_, _ = processor.processTraces(context.Background(), inBatch)
	}
}

// BenchmarkHighVolumeAttributes tests performance with many attributes
func BenchmarkHighVolumeAttributes(b *testing.B) {
	config := &Config{
		AllowAllKeys:  true,
		BlockedValues: []string{"4[0-9]{12}(?:[0-9]{3})?", "password.*", "token.*"},
		Summary:       "silent",
	}

	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		inBatch := createHighVolumeAttributesBatch()
		_, _ = processor.processTraces(context.Background(), inBatch)
	}
}

// BenchmarkComplexRegex tests performance with complex regex patterns
func BenchmarkComplexRegex(b *testing.B) {
	config := &Config{
		AllowAllKeys: true,
		BlockedValues: []string{
			"4[0-9]{12}(?:[0-9]{3})?",                                                                                                                                             // Credit card
			"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}",                                                                                                                     // Email
			"(http|https|ftp):\\/\\/([a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,4})(:[0-9]+)?\\/?([a-zA-Z0-9\\-\\._\\?\\,\\'\\/\\\\\\+&amp;%\\$#\\=~]*)",                                    // URL
			"(?i)(password|passwd|pwd|secret|token|api[_-]?key|auth)[\"']?\\s*[:=]\\s*[\"']?([^\\s\"']+)",                                                                        // Secrets
			"\\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b", // IP address
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

// BenchmarkNoRedactionNeeded tests performance when no redaction is needed
func BenchmarkNoRedactionNeeded(b *testing.B) {
	config := &Config{
		AllowAllKeys: true,
		Summary:      "silent",
	}

	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		inBatch := createRealisticBatch()
		_, _ = processor.processTraces(context.Background(), inBatch)
	}
}

func createRealisticBatch() ptrace.Traces {
	batch := ptrace.NewTraces()

	// Create 10 resource spans
	for i := 0; i < 10; i++ {
		rs := batch.ResourceSpans().AppendEmpty()

		// Add resource attributes
		rs.Resource().Attributes().PutStr("service.name", fmt.Sprintf("service-%d", i))
		rs.Resource().Attributes().PutStr("service.version", "1.0.0")
		rs.Resource().Attributes().PutStr("host.name", fmt.Sprintf("host-%d", i))

		// Create 50 spans per resource
		ils := rs.ScopeSpans().AppendEmpty()
		for j := 0; j < 50; j++ {
			span := ils.Spans().AppendEmpty()
			span.SetName(fmt.Sprintf("operation-%d", j))
			span.SetTraceID([16]byte{byte(i), byte(j), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14})
			span.SetSpanID([8]byte{byte(i), byte(j), 1, 2, 3, 4, 5, 6})

			// Add 20 attributes per span
			attrs := span.Attributes()
			attrs.PutStr("http.method", "GET")
			attrs.PutInt("http.status_code", 200)
			attrs.PutStr("http.url", fmt.Sprintf("/api/users/%d", j))
			attrs.PutStr("user.id", fmt.Sprintf("user-%d", j))
			attrs.PutStr("session.id", fmt.Sprintf("session-%d-%d", i, j))
			attrs.PutStr("request.id", fmt.Sprintf("req-%d-%d", i, j))
			attrs.PutBool("cache.hit", j%2 == 0)
			attrs.PutDouble("duration.ms", float64(j*10))
			attrs.PutStr("db.system", "postgresql")
			attrs.PutStr("db.name", "users")
			attrs.PutStr("db.operation", "SELECT")
			attrs.PutStr("safe_attribute", "some safe value")
			attrs.PutStr("trace.id", fmt.Sprintf("trace-%d", j))
			attrs.PutStr("span.kind", "server")
			attrs.PutStr("component", "http")
			attrs.PutStr("peer.service", "backend")
			attrs.PutStr("environment", "production")
			attrs.PutStr("version", "v1.2.3")
			attrs.PutStr("region", "us-west-2")
			attrs.PutStr("availability_zone", "us-west-2a")
		}
	}

	return batch
}

func createHighVolumeAttributesBatch() ptrace.Traces {
	batch := ptrace.NewTraces()
	rs := batch.ResourceSpans().AppendEmpty()
	ils := rs.ScopeSpans().AppendEmpty()

	// Create a single span with 100 attributes
	span := ils.Spans().AppendEmpty()
	span.SetName("high-volume-span")
	span.SetTraceID([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})

	attrs := span.Attributes()
	for i := 0; i < 100; i++ {
		attrs.PutStr(fmt.Sprintf("attr.%d", i), fmt.Sprintf("value-%d", i))
	}

	return batch
}

func createBatchWithSensitiveData() ptrace.Traces {
	batch := ptrace.NewTraces()
	rs := batch.ResourceSpans().AppendEmpty()
	ils := rs.ScopeSpans().AppendEmpty()

	for i := 0; i < 20; i++ {
		span := ils.Spans().AppendEmpty()
		span.SetName(fmt.Sprintf("span-%d", i))
		span.SetTraceID([16]byte{byte(i), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})

		attrs := span.Attributes()
		// Mix of sensitive and non-sensitive data
		attrs.PutStr("user.email", fmt.Sprintf("user%d@example.com", i))
		attrs.PutStr("credit.card", "4111111111111111")
		attrs.PutStr("api.key", "sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz")
		attrs.PutStr("password", "mysecretpassword123")
		attrs.PutStr("user.name", fmt.Sprintf("User %d", i))
		attrs.PutStr("request.url", "https://api.example.com/users/123/profile")
		attrs.PutStr("ip.address", "192.168.1.100")
		attrs.PutStr("safe.field", fmt.Sprintf("safe-value-%d", i))
	}

	return batch
}
