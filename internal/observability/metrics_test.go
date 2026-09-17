package observability

import (
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xenos76/https-wrench/internal/certinfo"
	"github.com/xenos76/https-wrench/internal/requests"
)

func TestMetrics_RecordRun(t *testing.T) {
	t.Parallel()

	cfg := MetricsFilterConfig{
		IncludeTLS:       true,
		IncludeCertChain: true,
		StripQuery:       true,
		CustomLabels: map[string]string{
			"env": "test",
		},
	}

	m := NewMetrics(cfg)
	require.NotNil(t, m)
	require.NotNil(t, m.Registry())

	matched := true
	res := &requests.Result{
		Requests: []requests.RequestResult{
			{
				Name: "test-probe",
				Responses: []requests.ResponseResult{
					{
						URL:               "https://example.com:8443/test?token=secret123",
						TransportAddress:  "127.0.0.1:8443",
						DurationMs:        125.5,
						StatusCode:        200,
						Body:              "OK response",
						BodyRegexpMatched: &matched,
						TLS: &requests.ResponseTLSResult{
							Version:     "TLS 1.3",
							CipherSuite: "TLS_AES_128_GCM_SHA256",
							KeyExchange: "X25519MLKEM768",
							Certificates: []certinfo.CertInfo{
								{
									Index:           0,
									Subject:         "CN=example.com",
									DaysUntilExpiry: 45.2,
									NotAfter:        time.Now().Add(45 * 24 * time.Hour).Format(time.RFC3339),
								},
							},
						},
					},
				},
			},
		},
	}

	responseMap := map[string][]requests.ResponseData{
		"test-probe": {
			{
				Request: requests.RequestConfig{
					RequestMethod:           "GET",
					ResponseBodyMatchRegexp: "OK (response)",
				},
				ResponseBody:     "OK response",
				TransportAddress: "127.0.0.1:8443",
			},
		},
	}

	m.RecordRun(res, responseMap, 150*time.Millisecond)

	mfs, err := m.Registry().Gather()
	require.NoError(t, err)
	require.NotEmpty(t, mfs)

	names := make(map[string]bool)
	for _, mf := range mfs {
		names[*mf.Name] = true
	}

	assert.True(t, names["https_wrench_probe_success"])
	assert.True(t, names["https_wrench_probe_duration_seconds"])
	assert.True(t, names["https_wrench_probe_last_duration_seconds"])
	assert.True(t, names["https_wrench_probe_status_code"])
	assert.True(t, names["https_wrench_probe_body_matches"])
	assert.True(t, names["https_wrench_probe_response_size_bytes"])
	assert.True(t, names["https_wrench_probe_requests_total"])
	assert.True(t, names["https_wrench_ssl_earliest_cert_expiry_seconds"])
	assert.True(t, names["https_wrench_ssl_cert_days_until_expiry"])
	assert.True(t, names["https_wrench_ssl_cert_valid"])
	assert.True(t, names["https_wrench_ssl_tls_version_info"])
	assert.True(t, names["https_wrench_scrape_collector_duration_seconds"])

	probeSuccessMF := findMetricFamily(mfs, "https_wrench_probe_success")
	require.NotNil(t, probeSuccessMF)
	require.NotEmpty(t, probeSuccessMF.Metric)
	successLabels := metricLabels(probeSuccessMF.Metric[0])
	assert.Equal(t, "/test", successLabels["uri"], "query string should be stripped from uri label")
	assert.Equal(t, "example.com:8443", successLabels["host"])
	assert.Equal(t, "test", successLabels["env"], "custom label should be applied")

	probeBodyMF := findMetricFamily(mfs, "https_wrench_probe_body_matches")
	require.NotNil(t, probeBodyMF)
	require.NotEmpty(t, probeBodyMF.Metric)
	bodyLabels := metricLabels(probeBodyMF.Metric[0])
	assert.Equal(t, "OK (response)", bodyLabels["regexp"])
	assert.Equal(t, "response", bodyLabels["matched_value"])
	assert.InDelta(t, 1.0, *probeBodyMF.Metric[0].Gauge.Value, 0.0001)

	probeRequestsMF := findMetricFamily(mfs, "https_wrench_probe_requests_total")
	require.NotNil(t, probeRequestsMF)
	require.NotEmpty(t, probeRequestsMF.Metric)
	reqLabels := metricLabels(probeRequestsMF.Metric[0])
	assert.Equal(t, "matched", reqLabels["body_match"])
}

func findMetricFamily(mfs []*dto.MetricFamily, name string) *dto.MetricFamily {
	for _, mf := range mfs {
		if mf != nil && mf.Name != nil && *mf.Name == name {
			return mf
		}
	}
	return nil
}

func metricLabels(m *dto.Metric) map[string]string {
	labels := make(map[string]string, len(m.Label))
	for _, lp := range m.Label {
		labels[*lp.Name] = *lp.Value
	}
	return labels
}

func TestExtractMatchedValue(t *testing.T) {
	t.Parallel()

	assert.Empty(t, extractMatchedValue("", "body", ""))
	assert.Empty(t, extractMatchedValue("abc", "", ""))
	assert.Empty(t, extractMatchedValue("[invalid", "body", ""))

	// Submatch / capture group extraction
	assert.Equal(t, "1.2.3", extractMatchedValue(`version:\s*([0-9.]+)`, "version: 1.2.3", ""))

	// Full match when no capture group
	assert.Equal(t, "status: ok", extractMatchedValue(`status:\s*ok`, "system status: ok in region", ""))

	// Fallback body when primary body is empty
	assert.Equal(t, "fallback", extractMatchedValue(`(fallback)`, "", "fallback"))

	// Truncation at 64 runes
	longStr := "a" + string(make([]byte, 100))
	for i := range 100 {
		longStr += "x"
		_ = i
	}

	res := extractMatchedValue(`(a.*)`, longStr, "")
	assert.Len(t, []rune(res), maxMatchedValueLength)
}

func TestMetrics_PushTracking(t *testing.T) {
	t.Parallel()

	m := NewMetrics(MetricsFilterConfig{})
	m.RecordPushSuccess("test_exporter", time.Now())
	m.RecordPushError("test_exporter")

	mfs, err := m.Registry().Gather()
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, mf := range mfs {
		names[*mf.Name] = true
	}

	assert.True(t, names["https_wrench_push_last_timestamp_seconds"])
	assert.True(t, names["https_wrench_push_errors_total"])
}
