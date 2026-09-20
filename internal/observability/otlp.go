package observability

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	dto "github.com/prometheus/client_model/go"
	otlpcollectormetricsv1 "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	otlpcommonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	otlpmetricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
	otlpresourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"
)

// PushOTLPConfig configures OpenTelemetry OTLP push.
type PushOTLPConfig struct {
	Enabled  bool              `mapstructure:"enabled"`
	Endpoint string            `mapstructure:"endpoint"`
	Protocol string            `mapstructure:"protocol"`
	Insecure bool              `mapstructure:"insecure"`
	Timeout  time.Duration     `mapstructure:"timeout"`
	Headers  map[string]string `mapstructure:"headers"`
}

// OTLPExporter pushes metrics to an OpenTelemetry OTLP/HTTP endpoint.
type OTLPExporter struct {
	cfg    PushOTLPConfig
	client *http.Client
	url    string
}

// NewOTLPExporter creates a new exporter for OpenTelemetry OTLP/HTTP.
func NewOTLPExporter(cfg PushOTLPConfig) *OTLPExporter {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultPushTimeout
	}

	endpoint := cfg.Endpoint
	if !strings.HasSuffix(endpoint, "/v1/metrics") {
		if strings.HasSuffix(endpoint, "/") {
			endpoint += "v1/metrics"
		} else {
			endpoint += "/v1/metrics"
		}
	}

	return &OTLPExporter{
		cfg: cfg,
		url: endpoint,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// Name returns the identifier of the OTLP exporter.
func (*OTLPExporter) Name() string {
	return "otlp"
}

// Close releases any idle connections.
func (e *OTLPExporter) Close() error {
	e.client.CloseIdleConnections()
	return nil
}

// Export serializes metric families into an OTLP ExportMetricsServiceRequest and sends it via HTTP POST.
func (e *OTLPExporter) Export(ctx context.Context, metricFamilies []*dto.MetricFamily) error {
	reqData := buildOTLPRequest(metricFamilies)
	if reqData == nil || len(reqData.ResourceMetrics) == 0 {
		return nil
	}

	payload, err := proto.Marshal(reqData)
	if err != nil {
		return fmt.Errorf("observability: failed to marshal OTLP request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("observability: failed to create OTLP HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	httpReq.Header.Set("User-Agent", "https-wrench-observability")

	for k, v := range e.cfg.Headers {
		httpReq.Header.Set(k, v)
	}

	resp, err := e.client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("observability: OTLP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))

		return fmt.Errorf(
			"observability: OTLP endpoint returned HTTP %d: %s",
			resp.StatusCode,
			stringsTrim(string(body)),
		)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	return checkOTLPResponse(body)
}

func checkOTLPResponse(body []byte) error {
	if len(body) == 0 {
		return nil
	}

	var respProto otlpcollectormetricsv1.ExportMetricsServiceResponse

	if err := proto.Unmarshal(body, &respProto); err != nil {
		return nil
	}

	ps := respProto.GetPartialSuccess()
	if ps == nil || ps.GetRejectedDataPoints() <= 0 {
		return nil
	}

	if msg := ps.GetErrorMessage(); msg != "" {
		return fmt.Errorf(
			"observability: OTLP export partially rejected (%d data points): %s",
			ps.GetRejectedDataPoints(),
			msg,
		)
	}

	return fmt.Errorf(
		"observability: OTLP export partially rejected (%d data points)",
		ps.GetRejectedDataPoints(),
	)
}

func buildOTLPRequest(metricFamilies []*dto.MetricFamily) *otlpmetricsv1.MetricsData {
	var otlpMetrics []*otlpmetricsv1.Metric

	nowNano := uint64(time.Now().UnixNano())

	for _, mf := range metricFamilies {
		if mf == nil || mf.Name == nil {
			continue
		}

		m := convertMetricFamilyToOTLP(mf, nowNano)
		if m != nil {
			otlpMetrics = append(otlpMetrics, m)
		}
	}

	if len(otlpMetrics) == 0 {
		return nil
	}

	resMetrics := &otlpmetricsv1.ResourceMetrics{
		Resource: &otlpresourcev1.Resource{
			Attributes: []*otlpcommonv1.KeyValue{
				{
					Key: "service.name",
					Value: &otlpcommonv1.AnyValue{
						Value: &otlpcommonv1.AnyValue_StringValue{StringValue: "https-wrench"},
					},
				},
			},
		},
		ScopeMetrics: []*otlpmetricsv1.ScopeMetrics{
			{
				Scope: &otlpcommonv1.InstrumentationScope{
					Name:    "https-wrench",
					Version: "1.0.0",
				},
				Metrics: otlpMetrics,
			},
		},
	}

	return &otlpmetricsv1.MetricsData{
		ResourceMetrics: []*otlpmetricsv1.ResourceMetrics{resMetrics},
	}
}

func convertMetricFamilyToOTLP(mf *dto.MetricFamily, fallbackNano uint64) *otlpmetricsv1.Metric {
	name := *mf.Name

	help := ""
	if mf.Help != nil {
		help = *mf.Help
	}

	otlpMetric := &otlpmetricsv1.Metric{
		Name:        name,
		Description: help,
	}

	switch mf.GetType() {
	case dto.MetricType_GAUGE, dto.MetricType_UNTYPED:
		otlpMetric.Data = convertGaugeToOTLP(mf.Metric, fallbackNano)
	case dto.MetricType_COUNTER:
		otlpMetric.Data = convertCounterToOTLP(mf.Metric, fallbackNano)
	case dto.MetricType_HISTOGRAM:
		otlpMetric.Data = convertHistogramToOTLP(mf.Metric, fallbackNano)
	default:
		return nil
	}

	return otlpMetric
}

func metricTimestamp(m *dto.Metric, fallbackNano uint64) uint64 {
	if m.TimestampMs != nil && *m.TimestampMs > 0 {
		return uint64(*m.TimestampMs) * 1_000_000
	}

	return fallbackNano
}

func convertGaugeToOTLP(metrics []*dto.Metric, fallbackNano uint64) *otlpmetricsv1.Metric_Gauge {
	var dps []*otlpmetricsv1.NumberDataPoint

	for _, m := range metrics {
		val := 0.0
		if m.Gauge != nil && m.Gauge.Value != nil {
			val = *m.Gauge.Value
		} else if m.Untyped != nil && m.Untyped.Value != nil {
			val = *m.Untyped.Value
		}

		dps = append(dps, &otlpmetricsv1.NumberDataPoint{
			Attributes:   toOTLPAttributes(m.Label),
			TimeUnixNano: metricTimestamp(m, fallbackNano),
			Value:        &otlpmetricsv1.NumberDataPoint_AsDouble{AsDouble: val},
		})
	}

	return &otlpmetricsv1.Metric_Gauge{
		Gauge: &otlpmetricsv1.Gauge{DataPoints: dps},
	}
}

func convertCounterToOTLP(metrics []*dto.Metric, fallbackNano uint64) *otlpmetricsv1.Metric_Sum {
	var dps []*otlpmetricsv1.NumberDataPoint

	for _, m := range metrics {
		val := 0.0
		if m.Counter != nil && m.Counter.Value != nil {
			val = *m.Counter.Value
		}

		dps = append(dps, &otlpmetricsv1.NumberDataPoint{
			Attributes:   toOTLPAttributes(m.Label),
			TimeUnixNano: metricTimestamp(m, fallbackNano),
			Value:        &otlpmetricsv1.NumberDataPoint_AsDouble{AsDouble: val},
		})
	}

	return &otlpmetricsv1.Metric_Sum{
		Sum: &otlpmetricsv1.Sum{
			DataPoints:             dps,
			AggregationTemporality: otlpmetricsv1.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
			IsMonotonic:            true,
		},
	}
}

func convertHistogramToOTLP(metrics []*dto.Metric, fallbackNano uint64) *otlpmetricsv1.Metric_Histogram {
	var dps []*otlpmetricsv1.HistogramDataPoint

	for _, m := range metrics {
		if m.Histogram == nil {
			continue
		}

		h := m.Histogram
		bounds, counts := extractHistogramBuckets(h)

		sumVal := 0.0
		if h.SampleSum != nil {
			sumVal = *h.SampleSum
		}

		countVal := uint64(0)
		if h.SampleCount != nil {
			countVal = *h.SampleCount
		}

		dps = append(dps, &otlpmetricsv1.HistogramDataPoint{
			Attributes:     toOTLPAttributes(m.Label),
			TimeUnixNano:   metricTimestamp(m, fallbackNano),
			Count:          countVal,
			Sum:            &sumVal,
			BucketCounts:   counts,
			ExplicitBounds: bounds,
		})
	}

	return &otlpmetricsv1.Metric_Histogram{
		Histogram: &otlpmetricsv1.Histogram{
			DataPoints:             dps,
			AggregationTemporality: otlpmetricsv1.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE,
		},
	}
}

func extractHistogramBuckets(h *dto.Histogram) ([]float64, []uint64) {
	var (
		bounds    []float64
		counts    []uint64
		lastCount uint64
	)

	for _, b := range h.Bucket {
		if b != nil && b.UpperBound != nil && b.CumulativeCount != nil {
			bounds = append(bounds, *b.UpperBound)
			cumCount := *b.CumulativeCount
			delta := cumCount - lastCount
			counts = append(counts, delta)
			lastCount = cumCount
		}
	}

	sampleCount := uint64(0)
	if h.SampleCount != nil {
		sampleCount = *h.SampleCount
	}

	var infCount uint64
	if sampleCount > lastCount {
		infCount = sampleCount - lastCount
	}

	counts = append(counts, infCount)

	return bounds, counts
}

func toOTLPAttributes(labelPairs []*dto.LabelPair) []*otlpcommonv1.KeyValue {
	if len(labelPairs) == 0 {
		return nil
	}

	attrs := make([]*otlpcommonv1.KeyValue, 0, len(labelPairs))
	for _, lp := range labelPairs {
		if lp != nil && lp.Name != nil && lp.Value != nil {
			attrs = append(attrs, &otlpcommonv1.KeyValue{
				Key: *lp.Name,
				Value: &otlpcommonv1.AnyValue{
					Value: &otlpcommonv1.AnyValue_StringValue{StringValue: *lp.Value},
				},
			})
		}
	}

	return attrs
}
