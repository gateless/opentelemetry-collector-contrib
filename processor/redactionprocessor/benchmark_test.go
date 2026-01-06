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
