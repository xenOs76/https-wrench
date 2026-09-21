package observability

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xenos76/https-wrench/internal/certinfo"
	"github.com/xenos76/https-wrench/internal/requests"
)

func buildTestProbeResult(matched *bool) (*requests.Result, map[string][]requests.ResponseData) {
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
						BodyRegexpMatched: matched,
						TransferredBytes:  11,
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
				TransferredBytes: 11,
				TransportAddress: "127.0.0.1:8443",
			},
		},
	}

	return res, responseMap
}

func assertRecordedMetricFamilies(t *testing.T, mfs []*dto.MetricFamily) {
	t.Helper()

	names := make(map[string]bool)
	for _, mf := range mfs {
		names[*mf.Name] = true
	}

	expected := []string{
		"https_wrench_probe_success",
		"https_wrench_probe_duration_seconds",
		"https_wrench_probe_last_duration_seconds",
		"https_wrench_probe_status_code",
		"https_wrench_probe_body_matches",
		"https_wrench_probe_response_size_bytes",
		"https_wrench_probe_requests_total",
		"https_wrench_ssl_earliest_cert_expiry_seconds",
		"https_wrench_ssl_cert_days_until_expiry",
		"https_wrench_ssl_cert_valid",
		"https_wrench_ssl_tls_version_info",
		"https_wrench_scrape_collector_duration_seconds",
	}

	for _, name := range expected {
		assert.True(t, names[name], "metric %s should be present", name)
	}
}

func assertRecordedMetricLabels(t *testing.T, mfs []*dto.MetricFamily) {
	t.Helper()

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
	assert.NotContains(t, bodyLabels, "matched_value")
	assert.InDelta(t, 1.0, *probeBodyMF.Metric[0].Gauge.Value, 0.0001)

	sslDaysMF := findMetricFamily(mfs, "https_wrench_ssl_cert_days_until_expiry")
	require.NotNil(t, sslDaysMF)
	require.NotEmpty(t, sslDaysMF.Metric)
	sslDaysLabels := metricLabels(sslDaysMF.Metric[0])
	assert.Equal(t, "0", sslDaysLabels["chain_index"])
	assert.NotContains(t, sslDaysLabels, "subject")

	sslValidMF := findMetricFamily(mfs, "https_wrench_ssl_cert_valid")
	require.NotNil(t, sslValidMF)
	require.NotEmpty(t, sslValidMF.Metric)
	sslValidLabels := metricLabels(sslValidMF.Metric[0])
	assert.Equal(t, "0", sslValidLabels["chain_index"])
	assert.NotContains(t, sslValidLabels, "subject")

	probeRequestsMF := findMetricFamily(mfs, "https_wrench_probe_requests_total")
	require.NotNil(t, probeRequestsMF)
	require.NotEmpty(t, probeRequestsMF.Metric)
	reqLabels := metricLabels(probeRequestsMF.Metric[0])
	assert.Equal(t, "matched", reqLabels["body_match"])

	probeSizeMF := findMetricFamily(mfs, "https_wrench_probe_response_size_bytes")
	require.NotNil(t, probeSizeMF)
	require.NotEmpty(t, probeSizeMF.Metric)
	assert.InDelta(t, 11.0, *probeSizeMF.Metric[0].Gauge.Value, 0.0001)
}

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
	res, responseMap := buildTestProbeResult(&matched)

	m.RecordRun(res, responseMap, 150*time.Millisecond)

	mfs, err := m.Registry().Gather()
	require.NoError(t, err)
	require.NotEmpty(t, mfs)

	assertRecordedMetricFamilies(t, mfs)
	assertRecordedMetricLabels(t, mfs)
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

func TestMetrics_RecordRun_TLSFallbackFromResponse(t *testing.T) {
	t.Parallel()

	cfg := MetricsFilterConfig{
		IncludeTLS:       true,
		IncludeCertChain: true,
	}

	m := NewMetrics(cfg)
	require.NotNil(t, m)

	mockCert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "fallback.example.com"},
		SerialNumber: big.NewInt(999),
	}

	res := &requests.Result{
		Requests: []requests.RequestResult{
			{
				Name: "tls-fallback-probe",
				Responses: []requests.ResponseResult{
					{
						URL:              "https://fallback.example.com/status",
						TransportAddress: "127.0.0.1:8443",
						StatusCode:       200,
						TLS:              nil, // printResponseCertificates was false!
					},
				},
			},
		},
	}

	responseMap := map[string][]requests.ResponseData{
		"tls-fallback-probe": {
			{
				URL: "https://fallback.example.com/status",
				Response: &http.Response{
					StatusCode: 200,
					TLS: &tls.ConnectionState{
						Version:          tls.VersionTLS13,
						CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
						PeerCertificates: []*x509.Certificate{mockCert},
					},
				},
			},
		},
	}

	m.RecordRun(res, responseMap, 50*time.Millisecond)

	mfs, err := m.Registry().Gather()
	require.NoError(t, err)

	names := make(map[string]bool)
	for _, mf := range mfs {
		names[*mf.Name] = true
	}

	assert.True(
		t,
		names["https_wrench_ssl_tls_version_info"],
		"TLS version info metric should be generated from response fallback",
	)
	assert.True(
		t,
		names["https_wrench_ssl_cert_days_until_expiry"],
		"Cert expiry metric should be generated from response fallback",
	)
	assert.True(
		t,
		names["https_wrench_ssl_cert_valid"],
		"Cert valid metric should be generated from response fallback",
	)
}

func assertProbeSuccessVal(
	t *testing.T,
	statusCode int,
	reqConfig requests.RequestConfig,
	respResult requests.ResponseResult,
	expected float64,
) {
	t.Helper()

	m := NewMetrics(MetricsFilterConfig{})
	res := &requests.Result{
		Requests: []requests.RequestResult{
			{
				Name: "test-probe",
				Responses: []requests.ResponseResult{
					{
						URL:                      "https://example.com/check",
						TransportAddress:         "127.0.0.1:443",
						StatusCode:               statusCode,
						ValidStatusCodes:         respResult.ValidStatusCodes,
						BodyFailRegexpMatched:    respResult.BodyFailRegexpMatched,
						HeaderMatchRegexpMatched: respResult.HeaderMatchRegexpMatched,
						HeaderFailRegexpMatched:  respResult.HeaderFailRegexpMatched,
					},
				},
			},
		},
	}
	responseMap := map[string][]requests.ResponseData{
		"test-probe": {
			{
				Request: reqConfig,
			},
		},
	}

	m.RecordRun(res, responseMap, 10*time.Millisecond)

	mfs, err := m.Registry().Gather()
	require.NoError(t, err)

	probeSuccessMF := findMetricFamily(mfs, "https_wrench_probe_success")
	require.NotNil(t, probeSuccessMF)
	require.NotEmpty(t, probeSuccessMF.Metric)
	assert.InDelta(t, expected, *probeSuccessMF.Metric[0].Gauge.Value, 0.0001)
}

func TestMetrics_RecordRun_ValidStatusCodes(t *testing.T) {
	t.Run("404 marked as success when in validStatusCodes", func(t *testing.T) {
		assertProbeSuccessVal(t, 404,
			requests.RequestConfig{ValidStatusCodes: []int{404}},
			requests.ResponseResult{StatusCode: 404, ValidStatusCodes: []int{404}},
			1.0,
		)
	})

	t.Run("200 marked as failure when only 404 in validStatusCodes", func(t *testing.T) {
		assertProbeSuccessVal(t, 200,
			requests.RequestConfig{ValidStatusCodes: []int{404}},
			requests.ResponseResult{StatusCode: 200, ValidStatusCodes: []int{404}},
			0.0,
		)
	})
}

func TestMetrics_RecordRun_RegexValidations(t *testing.T) {
	trueVal := true
	falseVal := false

	t.Run("failure when body fail regex matches", func(t *testing.T) {
		assertProbeSuccessVal(t, 200,
			requests.RequestConfig{ResponseBodyFailRegexp: "error"},
			requests.ResponseResult{StatusCode: 200, BodyFailRegexpMatched: &trueVal},
			0.0,
		)
	})

	t.Run("success when body fail regex does not match", func(t *testing.T) {
		assertProbeSuccessVal(t, 200,
			requests.RequestConfig{ResponseBodyFailRegexp: "error"},
			requests.ResponseResult{StatusCode: 200, BodyFailRegexpMatched: &falseVal},
			1.0,
		)
	})

	t.Run("failure when header match regex fails", func(t *testing.T) {
		assertProbeSuccessVal(t, 200,
			requests.RequestConfig{ResponseHeaderMatchRegexp: map[string]string{"Content-Type": "json"}},
			requests.ResponseResult{StatusCode: 200, HeaderMatchRegexpMatched: &falseVal},
			0.0,
		)
	})

	t.Run("failure when header fail regex matches", func(t *testing.T) {
		assertProbeSuccessVal(t, 200,
			requests.RequestConfig{ResponseHeaderFailRegexp: map[string]string{"Server": "apache"}},
			requests.ResponseResult{StatusCode: 200, HeaderFailRegexpMatched: &trueVal},
			0.0,
		)
	})
}
