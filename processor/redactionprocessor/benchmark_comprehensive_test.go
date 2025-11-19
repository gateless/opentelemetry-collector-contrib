// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package redactionprocessor

import (
	"context"
	"fmt"
	"testing"

	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.uber.org/zap/zaptest"

	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/redactionprocessor/internal/db"
	"github.com/open-telemetry/opentelemetry-collector-contrib/processor/redactionprocessor/internal/url"
)

// ============================================================================
// Logs Processing Benchmarks
// ============================================================================

func BenchmarkProcessLogs_StringBody(b *testing.B) {
	config := &Config{
		AllowAllKeys:  true,
		BlockedValues: []string{`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`},
		Summary:       "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logs := createLogsWithStringBody()
		_, _ = processor.processLogs(context.Background(), logs)
	}
}

func BenchmarkProcessLogs_MapBody(b *testing.B) {
	config := &Config{
		AllowAllKeys:  true,
		BlockedValues: []string{`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`},
		Summary:       "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logs := createLogsWithMapBody()
		_, _ = processor.processLogs(context.Background(), logs)
	}
}

func BenchmarkProcessLogs_SliceBody(b *testing.B) {
	config := &Config{
		AllowAllKeys:  true,
		BlockedValues: []string{`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`},
		Summary:       "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logs := createLogsWithSliceBody()
		_, _ = processor.processLogs(context.Background(), logs)
	}
}

func BenchmarkProcessLogs_NestedMapBody(b *testing.B) {
	config := &Config{
		AllowAllKeys:       true,
		BlockedKeyPatterns: []string{".*password.*", ".*token.*"},
		BlockedValues:      []string{`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`},
		Summary:            "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logs := createLogsWithNestedMapBody()
		_, _ = processor.processLogs(context.Background(), logs)
	}
}

func BenchmarkProcessLogs_HighVolume(b *testing.B) {
	config := &Config{
		AllowAllKeys:  true,
		BlockedValues: []string{`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`, `(?P<mask>[a-zA-Z0-9\._%+-]+)(?:@[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})`},
		Summary:       "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		logs := createHighVolumeLogBatch()
		_, _ = processor.processLogs(context.Background(), logs)
	}
}

// ============================================================================
// Metrics Processing Benchmarks
// ============================================================================

func BenchmarkProcessMetrics_Gauge(b *testing.B) {
	config := &Config{
		AllowAllKeys:  true,
		BlockedValues: []string{`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`},
		Summary:       "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics := createMetricsWithGauge()
		_, _ = processor.processMetrics(context.Background(), metrics)
	}
}

func BenchmarkProcessMetrics_Sum(b *testing.B) {
	config := &Config{
		AllowAllKeys:  true,
		BlockedValues: []string{`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`},
		Summary:       "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics := createMetricsWithSum()
		_, _ = processor.processMetrics(context.Background(), metrics)
	}
}

func BenchmarkProcessMetrics_Histogram(b *testing.B) {
	config := &Config{
		AllowAllKeys:  true,
		BlockedValues: []string{`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`},
		Summary:       "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics := createMetricsWithHistogram()
		_, _ = processor.processMetrics(context.Background(), metrics)
	}
}

func BenchmarkProcessMetrics_ExponentialHistogram(b *testing.B) {
	config := &Config{
		AllowAllKeys:  true,
		BlockedValues: []string{`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`},
		Summary:       "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics := createMetricsWithExponentialHistogram()
		_, _ = processor.processMetrics(context.Background(), metrics)
	}
}

func BenchmarkProcessMetrics_Summary(b *testing.B) {
	config := &Config{
		AllowAllKeys:  true,
		BlockedValues: []string{`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`},
		Summary:       "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics := createMetricsWithSummary()
		_, _ = processor.processMetrics(context.Background(), metrics)
	}
}

func BenchmarkProcessMetrics_AllTypes(b *testing.B) {
	config := &Config{
		AllowAllKeys:  true,
		BlockedValues: []string{`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`},
		Summary:       "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		metrics := createMetricsWithAllTypes()
		_, _ = processor.processMetrics(context.Background(), metrics)
	}
}

// ============================================================================
// Hash Function Benchmarks
// ============================================================================

func BenchmarkHashFunction_Default(b *testing.B) {
	config := &Config{
		AllowAllKeys:  true,
		BlockedValues: []string{`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`},
		HashFunction:  None,
		Summary:       "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := createBatchWithSensitiveData()
		_, _ = processor.processTraces(context.Background(), batch)
	}
}

func BenchmarkHashFunction_SHA1(b *testing.B) {
	config := &Config{
		AllowAllKeys:  true,
		BlockedValues: []string{`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`},
		HashFunction:  SHA1,
		Summary:       "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := createBatchWithSensitiveData()
		_, _ = processor.processTraces(context.Background(), batch)
	}
}

func BenchmarkHashFunction_SHA3(b *testing.B) {
	config := &Config{
		AllowAllKeys:  true,
		BlockedValues: []string{`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`},
		HashFunction:  SHA3,
		Summary:       "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := createBatchWithSensitiveData()
		_, _ = processor.processTraces(context.Background(), batch)
	}
}

func BenchmarkHashFunction_MD5(b *testing.B) {
	config := &Config{
		AllowAllKeys:  true,
		BlockedValues: []string{`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`},
		HashFunction:  MD5,
		Summary:       "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := createBatchWithSensitiveData()
		_, _ = processor.processTraces(context.Background(), batch)
	}
}

// ============================================================================
// URL Sanitization Benchmarks
// ============================================================================

func BenchmarkURLSanitization_Disabled(b *testing.B) {
	config := &Config{
		AllowAllKeys: true,
		URLSanitization: url.URLSanitizationConfig{
			Enabled: false,
		},
		Summary: "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := createBatchWithURLs()
		_, _ = processor.processTraces(context.Background(), batch)
	}
}

func BenchmarkURLSanitization_Enabled(b *testing.B) {
	config := &Config{
		AllowAllKeys: true,
		URLSanitization: url.URLSanitizationConfig{
			Enabled: true,
		},
		Summary: "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := createBatchWithURLs()
		_, _ = processor.processTraces(context.Background(), batch)
	}
}

func BenchmarkURLSanitization_SpanNames(b *testing.B) {
	config := &Config{
		AllowAllKeys: true,
		URLSanitization: url.URLSanitizationConfig{
			Enabled: true,
		},
		Summary: "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := createBatchWithURLSpanNames()
		_, _ = processor.processTraces(context.Background(), batch)
	}
}

// ============================================================================
// Database Obfuscation Benchmarks
// ============================================================================

func BenchmarkDBObfuscation_Disabled(b *testing.B) {
	config := &Config{
		AllowAllKeys: true,
		DBSanitizer:  db.DBSanitizerConfig{},
		Summary:      "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := createBatchWithDBQueries()
		_, _ = processor.processTraces(context.Background(), batch)
	}
}

func BenchmarkDBObfuscation_Enabled(b *testing.B) {
	config := &Config{
		AllowAllKeys: true,
		DBSanitizer: db.DBSanitizerConfig{
			SQLConfig: db.SQLConfig{
				Enabled:    true,
				Attributes: []string{"db.statement", "db.query"},
			},
		},
		Summary: "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := createBatchWithDBQueries()
		_, _ = processor.processTraces(context.Background(), batch)
	}
}

func BenchmarkDBObfuscation_SpanNames(b *testing.B) {
	config := &Config{
		AllowAllKeys: true,
		DBSanitizer: db.DBSanitizerConfig{
			SQLConfig: db.SQLConfig{
				Enabled: true,
			},
		},
		Summary: "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := createBatchWithDBSpanNames()
		_, _ = processor.processTraces(context.Background(), batch)
	}
}

// ============================================================================
// Configuration Scenarios Benchmarks
// ============================================================================

func BenchmarkConfig_AllowAllKeys(b *testing.B) {
	config := &Config{
		AllowAllKeys:  true,
		BlockedValues: []string{`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`},
		Summary:       "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := createRealisticBatch()
		_, _ = processor.processTraces(context.Background(), batch)
	}
}

func BenchmarkConfig_AllowedKeysList(b *testing.B) {
	config := &Config{
		AllowedKeys:   []string{"http.method", "http.status_code", "http.url", "user.id", "session.id"},
		BlockedValues: []string{`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`},
		Summary:       "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := createRealisticBatch()
		_, _ = processor.processTraces(context.Background(), batch)
	}
}

func BenchmarkConfig_RedactAllTypes(b *testing.B) {
	config := &Config{
		AllowAllKeys:   true,
		RedactAllTypes: true,
		BlockedValues:  []string{`\b(?P<mask>\d{3}-\d{2}-)(?:\d{4})\b`},
		Summary:        "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := createBatchWithMixedTypes()
		_, _ = processor.processTraces(context.Background(), batch)
	}
}

func BenchmarkConfig_AllowedValuesRegex(b *testing.B) {
	config := &Config{
		AllowAllKeys:  true,
		BlockedValues: []string{`\d+`}, // Block all numbers
		AllowedValues: []string{`^(200|201|404|500)$`}, // Except HTTP status codes
		Summary:       "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := createRealisticBatch()
		_, _ = processor.processTraces(context.Background(), batch)
	}
}

func BenchmarkConfig_SummaryDebug(b *testing.B) {
	config := &Config{
		AllowAllKeys:       true,
		BlockedKeyPatterns: []string{".*token.*", ".*password.*"},
		Summary:            "debug",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := createBatchWithSensitiveData()
		_, _ = processor.processTraces(context.Background(), batch)
	}
}

func BenchmarkConfig_SummaryInfo(b *testing.B) {
	config := &Config{
		AllowAllKeys:       true,
		BlockedKeyPatterns: []string{".*token.*", ".*password.*"},
		Summary:            "info",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := createBatchWithSensitiveData()
		_, _ = processor.processTraces(context.Background(), batch)
	}
}

func BenchmarkConfig_SummarySilent(b *testing.B) {
	config := &Config{
		AllowAllKeys:       true,
		BlockedKeyPatterns: []string{".*token.*", ".*password.*"},
		Summary:            "silent",
	}
	processor, _ := newRedaction(context.Background(), config, zaptest.NewLogger(b))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		batch := createBatchWithSensitiveData()
		_, _ = processor.processTraces(context.Background(), batch)
	}
}

// ============================================================================
// Helper Functions for Creating Test Data
// ============================================================================

func createLogsWithStringBody() plog.Logs {
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()

	for i := 0; i < 100; i++ {
		log := sl.LogRecords().AppendEmpty()
		log.Body().SetStr(fmt.Sprintf("User SSN: 123-45-6789, Request ID: %d", i))
		log.Attributes().PutStr("service.name", "test-service")
	}

	return logs
}

func createLogsWithMapBody() plog.Logs {
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()

	for i := 0; i < 100; i++ {
		log := sl.LogRecords().AppendEmpty()
		bodyMap := log.Body().SetEmptyMap()
		bodyMap.PutStr("message", fmt.Sprintf("Request %d processed", i))
		bodyMap.PutStr("user_id", fmt.Sprintf("user-%d", i))
		bodyMap.PutStr("ssn", "123-45-6789")
		log.Attributes().PutStr("service.name", "test-service")
	}

	return logs
}

func createLogsWithSliceBody() plog.Logs {
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()

	for i := 0; i < 100; i++ {
		log := sl.LogRecords().AppendEmpty()
		bodySlice := log.Body().SetEmptySlice()
		bodySlice.AppendEmpty().SetStr(fmt.Sprintf("Event %d", i))
		bodySlice.AppendEmpty().SetStr("SSN: 123-45-6789")
		log.Attributes().PutStr("service.name", "test-service")
	}

	return logs
}

func createLogsWithNestedMapBody() plog.Logs {
	logs := plog.NewLogs()
	rl := logs.ResourceLogs().AppendEmpty()
	sl := rl.ScopeLogs().AppendEmpty()

	for i := 0; i < 50; i++ {
		log := sl.LogRecords().AppendEmpty()
		bodyMap := log.Body().SetEmptyMap()
		bodyMap.PutStr("message", fmt.Sprintf("Request %d", i))

		userMap := bodyMap.PutEmptyMap("user")
		userMap.PutStr("name", "John Doe")
		userMap.PutStr("email", "john@example.com")
		userMap.PutStr("password", "secret123")

		credMap := bodyMap.PutEmptyMap("credentials")
		credMap.PutStr("api_token", "sk-abc123def456")
		credMap.PutStr("refresh_token", "rt-xyz789")

		log.Attributes().PutStr("service.name", "test-service")
	}

	return logs
}

func createHighVolumeLogBatch() plog.Logs {
	logs := plog.NewLogs()

	for i := 0; i < 10; i++ {
		rl := logs.ResourceLogs().AppendEmpty()
		rl.Resource().Attributes().PutStr("service.name", fmt.Sprintf("service-%d", i))

		sl := rl.ScopeLogs().AppendEmpty()
		for j := 0; j < 100; j++ {
			log := sl.LogRecords().AppendEmpty()
			log.Body().SetStr(fmt.Sprintf("Log message %d with email user%d@example.com and SSN 123-45-6789", j, j))
			log.Attributes().PutStr("user.id", fmt.Sprintf("user-%d", j))
			log.Attributes().PutInt("http.status_code", 200)
		}
	}

	return logs
}

func createMetricsWithGauge() pmetric.Metrics {
	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()

	for i := 0; i < 50; i++ {
		metric := sm.Metrics().AppendEmpty()
		metric.SetName(fmt.Sprintf("gauge_metric_%d", i))
		gauge := metric.SetEmptyGauge()

		for j := 0; j < 10; j++ {
			dp := gauge.DataPoints().AppendEmpty()
			dp.SetIntValue(int64(j * 100))
			dp.Attributes().PutStr("label", fmt.Sprintf("value-%d", j))
			dp.Attributes().PutStr("user_ssn", "123-45-6789")
		}
	}

	return metrics
}

func createMetricsWithSum() pmetric.Metrics {
	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()

	for i := 0; i < 50; i++ {
		metric := sm.Metrics().AppendEmpty()
		metric.SetName(fmt.Sprintf("sum_metric_%d", i))
		sum := metric.SetEmptySum()

		for j := 0; j < 10; j++ {
			dp := sum.DataPoints().AppendEmpty()
			dp.SetIntValue(int64(j * 100))
			dp.Attributes().PutStr("label", fmt.Sprintf("value-%d", j))
			dp.Attributes().PutStr("user_email", "user@example.com")
		}
	}

	return metrics
}

func createMetricsWithHistogram() pmetric.Metrics {
	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()

	for i := 0; i < 50; i++ {
		metric := sm.Metrics().AppendEmpty()
		metric.SetName(fmt.Sprintf("histogram_metric_%d", i))
		histogram := metric.SetEmptyHistogram()

		for j := 0; j < 10; j++ {
			dp := histogram.DataPoints().AppendEmpty()
			dp.SetCount(uint64(j * 10))
			dp.SetSum(float64(j * 100))
			dp.Attributes().PutStr("label", fmt.Sprintf("value-%d", j))
		}
	}

	return metrics
}

func createMetricsWithExponentialHistogram() pmetric.Metrics {
	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()

	for i := 0; i < 50; i++ {
		metric := sm.Metrics().AppendEmpty()
		metric.SetName(fmt.Sprintf("exp_histogram_metric_%d", i))
		expHistogram := metric.SetEmptyExponentialHistogram()

		for j := 0; j < 10; j++ {
			dp := expHistogram.DataPoints().AppendEmpty()
			dp.SetCount(uint64(j * 10))
			dp.SetSum(float64(j * 100))
			dp.Attributes().PutStr("label", fmt.Sprintf("value-%d", j))
		}
	}

	return metrics
}

func createMetricsWithSummary() pmetric.Metrics {
	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()

	for i := 0; i < 50; i++ {
		metric := sm.Metrics().AppendEmpty()
		metric.SetName(fmt.Sprintf("summary_metric_%d", i))
		summary := metric.SetEmptySummary()

		for j := 0; j < 10; j++ {
			dp := summary.DataPoints().AppendEmpty()
			dp.SetCount(uint64(j * 10))
			dp.SetSum(float64(j * 100))
			dp.Attributes().PutStr("label", fmt.Sprintf("value-%d", j))
		}
	}

	return metrics
}

func createMetricsWithAllTypes() pmetric.Metrics {
	metrics := pmetric.NewMetrics()
	rm := metrics.ResourceMetrics().AppendEmpty()
	sm := rm.ScopeMetrics().AppendEmpty()

	// Gauge
	gaugeMetric := sm.Metrics().AppendEmpty()
	gaugeMetric.SetName("gauge_metric")
	gauge := gaugeMetric.SetEmptyGauge()
	for i := 0; i < 20; i++ {
		dp := gauge.DataPoints().AppendEmpty()
		dp.SetIntValue(int64(i))
		dp.Attributes().PutStr("id", fmt.Sprintf("id-%d", i))
	}

	// Sum
	sumMetric := sm.Metrics().AppendEmpty()
	sumMetric.SetName("sum_metric")
	sum := sumMetric.SetEmptySum()
	for i := 0; i < 20; i++ {
		dp := sum.DataPoints().AppendEmpty()
		dp.SetIntValue(int64(i * 10))
		dp.Attributes().PutStr("id", fmt.Sprintf("id-%d", i))
	}

	// Histogram
	histMetric := sm.Metrics().AppendEmpty()
	histMetric.SetName("histogram_metric")
	hist := histMetric.SetEmptyHistogram()
	for i := 0; i < 20; i++ {
		dp := hist.DataPoints().AppendEmpty()
		dp.SetCount(uint64(i * 10))
		dp.Attributes().PutStr("id", fmt.Sprintf("id-%d", i))
	}

	// Exponential Histogram
	expHistMetric := sm.Metrics().AppendEmpty()
	expHistMetric.SetName("exp_histogram_metric")
	expHist := expHistMetric.SetEmptyExponentialHistogram()
	for i := 0; i < 20; i++ {
		dp := expHist.DataPoints().AppendEmpty()
		dp.SetCount(uint64(i * 10))
		dp.Attributes().PutStr("id", fmt.Sprintf("id-%d", i))
	}

	// Summary
	summaryMetric := sm.Metrics().AppendEmpty()
	summaryMetric.SetName("summary_metric")
	summary := summaryMetric.SetEmptySummary()
	for i := 0; i < 20; i++ {
		dp := summary.DataPoints().AppendEmpty()
		dp.SetCount(uint64(i * 10))
		dp.Attributes().PutStr("id", fmt.Sprintf("id-%d", i))
	}

	return metrics
}

func createBatchWithURLs() ptrace.Traces {
	batch := ptrace.NewTraces()
	rs := batch.ResourceSpans().AppendEmpty()
	ils := rs.ScopeSpans().AppendEmpty()

	for i := 0; i < 100; i++ {
		span := ils.Spans().AppendEmpty()
		span.SetName(fmt.Sprintf("span-%d", i))
		span.SetTraceID([16]byte{byte(i), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})

		attrs := span.Attributes()
		attrs.PutStr("http.url", fmt.Sprintf("https://api.example.com/users/123e4567-e89b-12d3-a456-426614174000/profile?timestamp=%d", i))
		attrs.PutStr("http.target", fmt.Sprintf("/api/v1/orders/uuid-here-%d/items", i))
		attrs.PutStr("request.path", fmt.Sprintf("/users/12345/documents/67890/view?session=%d", i))
	}

	return batch
}

func createBatchWithURLSpanNames() ptrace.Traces {
	batch := ptrace.NewTraces()
	rs := batch.ResourceSpans().AppendEmpty()
	ils := rs.ScopeSpans().AppendEmpty()

	for i := 0; i < 100; i++ {
		span := ils.Spans().AppendEmpty()
		span.SetName(fmt.Sprintf("GET /api/users/123e4567-e89b-12d3-a456-%012d/profile", i))
		span.SetKind(ptrace.SpanKindServer)
		span.SetTraceID([16]byte{byte(i), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
	}

	return batch
}

func createBatchWithDBQueries() ptrace.Traces {
	batch := ptrace.NewTraces()
	rs := batch.ResourceSpans().AppendEmpty()
	ils := rs.ScopeSpans().AppendEmpty()

	for i := 0; i < 100; i++ {
		span := ils.Spans().AppendEmpty()
		span.SetName(fmt.Sprintf("span-%d", i))
		span.SetTraceID([16]byte{byte(i), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})

		attrs := span.Attributes()
		attrs.PutStr("db.statement", fmt.Sprintf("SELECT * FROM users WHERE id = %d AND ssn = '123-45-6789'", i))
		attrs.PutStr("db.system", "postgresql")
		attrs.PutStr("db.query", fmt.Sprintf("INSERT INTO orders (user_id, total) VALUES (%d, 99.99)", i))
	}

	return batch
}

func createBatchWithDBSpanNames() ptrace.Traces {
	batch := ptrace.NewTraces()
	rs := batch.ResourceSpans().AppendEmpty()
	ils := rs.ScopeSpans().AppendEmpty()

	for i := 0; i < 100; i++ {
		span := ils.Spans().AppendEmpty()
		span.SetName(fmt.Sprintf("SELECT * FROM users WHERE id = %d", i))
		span.SetKind(ptrace.SpanKindClient)
		span.SetTraceID([16]byte{byte(i), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})

		attrs := span.Attributes()
		attrs.PutStr("db.system", "postgresql")
	}

	return batch
}

func createBatchWithMixedTypes() ptrace.Traces {
	batch := ptrace.NewTraces()
	rs := batch.ResourceSpans().AppendEmpty()
	ils := rs.ScopeSpans().AppendEmpty()

	for i := 0; i < 100; i++ {
		span := ils.Spans().AppendEmpty()
		span.SetName(fmt.Sprintf("span-%d", i))
		span.SetTraceID([16]byte{byte(i), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})

		attrs := span.Attributes()
		attrs.PutStr("string_attr", fmt.Sprintf("value-%d with SSN 123-45-6789", i))
		attrs.PutInt("int_attr", int64(i))
		attrs.PutDouble("double_attr", float64(i)*1.5)
		attrs.PutBool("bool_attr", i%2 == 0)

		// Add a map
		mapAttr := attrs.PutEmptyMap("map_attr")
		mapAttr.PutStr("nested", "123-45-6789")

		// Add a slice
		sliceAttr := attrs.PutEmptySlice("slice_attr")
		sliceAttr.AppendEmpty().SetStr("123-45-6789")
	}

	return batch
}
