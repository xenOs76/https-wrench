package observability

import (
	"log/slog"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/xenos76/https-wrench/internal/certinfo"
	"github.com/xenos76/https-wrench/internal/requests"
)

// Metrics manages the Prometheus registry and metric collectors for https-wrench.
type Metrics struct {
	mu  sync.RWMutex
	reg *prometheus.Registry
	cfg MetricsFilterConfig

	probeSuccess       *prometheus.GaugeVec
	probeDuration      *prometheus.HistogramVec
	probeLastDuration  *prometheus.GaugeVec
	probeStatusCode    *prometheus.GaugeVec
	probeBodyMatches   *prometheus.GaugeVec
	probeResponseSize  *prometheus.GaugeVec
	probeRequestsTotal *prometheus.CounterVec

	sslEarliestExpiry  *prometheus.GaugeVec
	sslDaysUntilExpiry *prometheus.GaugeVec
	sslCertValid       *prometheus.GaugeVec
	sslTLSVersionInfo  *prometheus.GaugeVec

	collectorDuration prometheus.Gauge
	pushLastTimestamp *prometheus.GaugeVec
	pushErrorsTotal   *prometheus.CounterVec
}

// NewMetrics initializes an isolated Prometheus registry and metric descriptors.
func NewMetrics(cfg MetricsFilterConfig) *Metrics {
	rawReg := prometheus.NewRegistry()

	var reg prometheus.Registerer = rawReg

	if len(cfg.CustomLabels) > 0 {
		labels := make(prometheus.Labels, len(cfg.CustomLabels))
		for k, v := range cfg.CustomLabels {
			labels[k] = v
		}

		reg = prometheus.WrapRegistererWith(labels, rawReg)
	}

	m := &Metrics{
		reg: rawReg,
		cfg: cfg,
	}

	m.initProbeMetrics()
	m.initSSLMetrics()
	m.initInternalMetrics()
	m.registerAll(reg)

	return m
}

func (m *Metrics) initProbeMetrics() {
	m.probeSuccess = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "https_wrench_probe_success",
			Help: "Displays whether a probe was successful (1 for success, 0 for failure).",
		},
		[]string{"request_name", "host", "uri", "method", "transport_address"},
	)

	m.probeDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "https_wrench_probe_duration_seconds",
			Help:    "Probe latency in seconds.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"request_name", "host", "uri", "method"},
	)

	m.probeLastDuration = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "https_wrench_probe_last_duration_seconds",
			Help: "Latency of the most recent probe in seconds.",
		},
		[]string{"request_name", "host", "uri", "method"},
	)

	m.probeStatusCode = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "https_wrench_probe_status_code",
			Help: "HTTP response status code.",
		},
		[]string{"request_name", "host", "uri"},
	)

	m.probeBodyMatches = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "https_wrench_probe_body_matches",
			Help: "Whether response body matched regex (1 for match, 0 for mismatch).",
		},
		[]string{"request_name", "host", "uri", "regexp"},
	)

	m.probeResponseSize = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "https_wrench_probe_response_size_bytes",
			Help: "Size of the response body in bytes.",
		},
		[]string{"request_name", "host", "uri"},
	)

	m.probeRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "https_wrench_probe_requests_total",
			Help: "Total number of probe requests executed.",
		},
		[]string{"request_name", "host", "uri", "status_code", "result", "body_match"},
	)
}

func (m *Metrics) initSSLMetrics() {
	m.sslEarliestExpiry = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "https_wrench_ssl_earliest_cert_expiry_seconds",
			Help: "Earliest certificate expiration timestamp in seconds since unix epoch.",
		},
		[]string{"request_name", "host"},
	)

	m.sslDaysUntilExpiry = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "https_wrench_ssl_cert_days_until_expiry",
			Help: "Number of days until certificate expires.",
		},
		[]string{"request_name", "host", "chain_index"},
	)

	m.sslCertValid = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "https_wrench_ssl_cert_valid",
			Help: "Whether certificate is currently valid (1 for valid, 0 for expired/invalid).",
		},
		[]string{"request_name", "host", "chain_index"},
	)

	m.sslTLSVersionInfo = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "https_wrench_ssl_tls_version_info",
			Help: "Negotiated TLS connection parameters (always 1).",
		},
		[]string{"request_name", "host", "tls_version", "cipher_suite", "key_exchange"},
	)
}

func (m *Metrics) initInternalMetrics() {
	m.collectorDuration = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "https_wrench_scrape_collector_duration_seconds",
			Help: "Time taken by https-wrench to execute a probe cycle.",
		},
	)

	m.pushLastTimestamp = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "https_wrench_push_last_timestamp_seconds",
			Help: "Unix timestamp in seconds of the last successful push.",
		},
		[]string{"exporter"},
	)

	m.pushErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "https_wrench_push_errors_total",
			Help: "Total number of errors encountered while pushing metrics.",
		},
		[]string{"exporter"},
	)
}

func (m *Metrics) registerAll(reg prometheus.Registerer) {
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.probeSuccess,
		m.probeDuration,
		m.probeLastDuration,
		m.probeStatusCode,
		m.probeBodyMatches,
		m.probeResponseSize,
		m.probeRequestsTotal,
		m.sslEarliestExpiry,
		m.sslDaysUntilExpiry,
		m.sslCertValid,
		m.sslTLSVersionInfo,
		m.collectorDuration,
		m.pushLastTimestamp,
		m.pushErrorsTotal,
	)
}

// Registry returns the underlying Prometheus registry.
func (m *Metrics) Registry() *prometheus.Registry {
	return m.reg
}

// RecordRun updates all metric values based on the result of an executed probe cycle.
func (m *Metrics) RecordRun(
	result *requests.Result,
	responseMap map[string][]requests.ResponseData,
	cycleDuration time.Duration,
) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.collectorDuration.Set(cycleDuration.Seconds())

	if result == nil {
		return
	}

	for _, reqRes := range result.Requests {
		reqName := reqRes.Name
		rdList := responseMap[reqName]

		for i, respRes := range reqRes.Responses {
			var rd requests.ResponseData
			if i < len(rdList) {
				rd = rdList[i]
			}

			m.recordSingleResponse(reqName, respRes, rd)
		}
	}
}

func (m *Metrics) recordSingleResponse(
	reqName string,
	respRes requests.ResponseResult,
	rd requests.ResponseData,
) {
	parsedHost, parsedURI := m.parseURLComponents(respRes.URL)

	method := rd.Request.RequestMethod
	if method == "" {
		method = "GET"
	}

	transportAddr := respRes.TransportAddress
	statusCode := respRes.StatusCode
	statusCodeStr := strconv.Itoa(statusCode)

	isHealthy := respRes.Error == "" && (statusCode >= 200 && statusCode < 400)
	if respRes.BodyRegexpMatched != nil && !*respRes.BodyRegexpMatched {
		isHealthy = false
	}

	successVal := 0.0
	resultStr := "failure"

	if isHealthy {
		successVal = 1.0
		resultStr = "success"
	}

	bodyMatchStr := "none"

	if respRes.BodyRegexpMatched != nil {
		if *respRes.BodyRegexpMatched {
			bodyMatchStr = "matched"
		} else {
			bodyMatchStr = "mismatched"
		}
	}

	durationSec := respRes.DurationMs / 1000.0

	m.probeSuccess.WithLabelValues(reqName, parsedHost, parsedURI, method, transportAddr).Set(successVal)
	m.probeDuration.WithLabelValues(reqName, parsedHost, parsedURI, method).Observe(durationSec)
	m.probeLastDuration.WithLabelValues(reqName, parsedHost, parsedURI, method).Set(durationSec)
	m.probeStatusCode.WithLabelValues(reqName, parsedHost, parsedURI).Set(float64(statusCode))
	m.probeResponseSize.WithLabelValues(reqName, parsedHost, parsedURI).Set(float64(respRes.TransferredBytes))
	m.probeRequestsTotal.WithLabelValues(reqName, parsedHost, parsedURI, statusCodeStr, resultStr, bodyMatchStr).Inc()

	if respRes.BodyRegexpMatched != nil {
		matchVal := 0.0
		if *respRes.BodyRegexpMatched {
			matchVal = 1.0
		}

		regexpPattern := rd.Request.ResponseBodyMatchRegexp
		matchedValue := extractMatchedValue(regexpPattern, rd.ResponseBody, respRes.Body)

		m.probeBodyMatches.WithLabelValues(reqName, parsedHost, parsedURI, regexpPattern).Set(matchVal)

		slog.Info(
			"probe body regex match",
			"request_name", reqName,
			"host", parsedHost,
			"uri", parsedURI,
			"regexp", regexpPattern,
			"matched", *respRes.BodyRegexpMatched,
			"matched_value", matchedValue,
		)
	}

	if m.cfg.IncludeTLS && respRes.TLS != nil {
		m.recordTLSMetrics(reqName, parsedHost, respRes.TLS)
	}
}

const maxMatchedValueLength = 64

func extractMatchedValue(pattern, body, fallbackBody string) string {
	if pattern == "" {
		return ""
	}

	content := body
	if content == "" {
		content = fallbackBody
	}

	if content == "" {
		return ""
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}

	submatches := re.FindStringSubmatch(content)

	var matched string
	if len(submatches) > 1 {
		matched = submatches[1]
	} else if len(submatches) == 1 {
		matched = submatches[0]
	}

	runes := []rune(matched)
	if len(runes) > maxMatchedValueLength {
		return string(runes[:maxMatchedValueLength])
	}

	return string(runes)
}

func (m *Metrics) recordTLSMetrics(reqName, host string, tlsRes *requests.ResponseTLSResult) {
	if tlsRes.Version != "" {
		m.sslTLSVersionInfo.WithLabelValues(
			reqName, host, tlsRes.Version, tlsRes.CipherSuite, tlsRes.KeyExchange,
		).Set(1.0)
	}

	earliestExpiryUnix := m.recordCertificates(reqName, host, tlsRes.Certificates)
	if earliestExpiryUnix > 0 {
		m.sslEarliestExpiry.WithLabelValues(reqName, host).Set(float64(earliestExpiryUnix))
	}
}

func (m *Metrics) recordCertificates(reqName, host string, certs []certinfo.CertInfo) int64 {
	var earliestExpiryUnix int64

	for _, cert := range certs {
		if !m.cfg.IncludeCertChain && cert.Index > 0 {
			continue
		}

		m.recordSingleCertificate(reqName, host, cert)

		expiry := parseCertExpiry(cert)
		if expiry > 0 && (earliestExpiryUnix == 0 || expiry < earliestExpiryUnix) {
			earliestExpiryUnix = expiry
		}
	}

	return earliestExpiryUnix
}

func (m *Metrics) recordSingleCertificate(reqName, host string, cert certinfo.CertInfo) {
	chainIndexStr := strconv.Itoa(cert.Index)

	m.sslDaysUntilExpiry.WithLabelValues(
		reqName, host, chainIndexStr,
	).Set(cert.DaysUntilExpiry)

	validVal := 0.0
	if cert.DaysUntilExpiry > 0 {
		validVal = 1.0
	}

	m.sslCertValid.WithLabelValues(
		reqName, host, chainIndexStr,
	).Set(validVal)

	slog.Info(
		"certificate subject details",
		"request_name", reqName,
		"host", host,
		"chain_index", cert.Index,
		"subject", cert.Subject,
		"days_until_expiry", cert.DaysUntilExpiry,
	)
}

func parseCertExpiry(cert certinfo.CertInfo) int64 {
	if notAfter, err := time.Parse(time.RFC3339, cert.NotAfter); err == nil {
		return notAfter.Unix()
	}

	if cert.DaysUntilExpiry > 0 {
		return time.Now().Add(time.Duration(cert.DaysUntilExpiry*24) * time.Hour).Unix()
	}

	return 0
}

// RecordPushSuccess updates the push timestamp metric.
func (m *Metrics) RecordPushSuccess(exporter string, at time.Time) {
	m.pushLastTimestamp.WithLabelValues(exporter).Set(float64(at.Unix()))
}

// RecordPushError increments the push error counter.
func (m *Metrics) RecordPushError(exporter string) {
	m.pushErrorsTotal.WithLabelValues(exporter).Inc()
}

func (m *Metrics) parseURLComponents(rawURL string) (host, uri string) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, ""
	}

	host = parsed.Host

	uri = parsed.RequestURI()
	if m.cfg.StripQuery {
		if idx := strings.Index(uri, "?"); idx != -1 {
			uri = uri[:idx]
		}
	}

	if uri == "" {
		uri = "/"
	}

	return host, uri
}
