package observability

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/golang/snappy"
	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/encoding/protowire"
)

// PushPrometheusConfig configures Prometheus remote_write push.
type PushPrometheusConfig struct {
	Enabled        bool              `mapstructure:"enabled"`
	RemoteWriteURL string            `mapstructure:"remoteWriteUrl"`
	Timeout        time.Duration     `mapstructure:"timeout"`
	Headers        map[string]string `mapstructure:"headers"`
	BasicAuthUser  string            `mapstructure:"basicAuthUser"`
	BasicAuthPass  string            `mapstructure:"basicAuthPassword"`
	BearerToken    string            `mapstructure:"bearerToken"`
}

// RemoteWriteExporter pushes metrics to a Prometheus remote_write compatible endpoint.
type RemoteWriteExporter struct {
	cfg    PushPrometheusConfig
	client *http.Client
}

// NewRemoteWriteExporter creates an exporter for Prometheus remote_write.
func NewRemoteWriteExporter(cfg PushPrometheusConfig) *RemoteWriteExporter {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultPushTimeout
	}

	return &RemoteWriteExporter{
		cfg: cfg,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// Name returns the identifier of the remote_write exporter.
func (*RemoteWriteExporter) Name() string {
	return "prometheus_remote_write"
}

// Close closes any idle connections.
func (e *RemoteWriteExporter) Close() error {
	e.client.CloseIdleConnections()
	return nil
}

// Export serializes metric families into a snappy-compressed protobuf payload and pushes to the endpoint.
func (e *RemoteWriteExporter) Export(ctx context.Context, metricFamilies []*dto.MetricFamily) error {
	nowMs := time.Now().UnixMilli()

	seriesList := extractTimeSeries(metricFamilies, nowMs)
	if len(seriesList) == 0 {
		return nil
	}

	rawProto := encodeWriteRequest(seriesList)
	compressed := snappy.Encode(nil, rawProto)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.RemoteWriteURL, bytes.NewReader(compressed))
	if err != nil {
		return fmt.Errorf("observability: failed to create remote_write request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("Content-Encoding", "snappy")
	req.Header.Set("User-Agent", "https-wrench-observability")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")

	for k, v := range e.cfg.Headers {
		req.Header.Set(k, v)
	}

	if e.cfg.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+e.cfg.BearerToken)
	} else if e.cfg.BasicAuthUser != "" {
		req.SetBasicAuth(e.cfg.BasicAuthUser, e.cfg.BasicAuthPass)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return fmt.Errorf("observability: remote_write request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return fmt.Errorf(
			"observability: remote_write server returned HTTP %d: %s",
			resp.StatusCode,
			stringsTrim(string(body)),
		)
	}

	return nil
}

func stringsTrim(s string) string {
	return bytes.NewBufferString(s).String()
}

func extractTimeSeries(metricFamilies []*dto.MetricFamily, fallbackTimestampMs int64) [][]byte {
	var seriesList [][]byte

	for _, mf := range metricFamilies {
		if mf == nil || mf.Name == nil {
			continue
		}

		name := *mf.Name
		for _, m := range mf.Metric {
			if m == nil {
				continue
			}

			seriesList = append(seriesList, extractMetricSeries(name, m, fallbackTimestampMs)...)
		}
	}

	return seriesList
}

func extractMetricSeries(name string, m *dto.Metric, fallbackTimestampMs int64) [][]byte {
	ts := fallbackTimestampMs
	if m.TimestampMs != nil && *m.TimestampMs > 0 {
		ts = *m.TimestampMs
	}

	baseLabels := extractLabels(name, m.Label)

	switch {
	case m.Gauge != nil && m.Gauge.Value != nil:
		return [][]byte{encodeTimeSeries(baseLabels, *m.Gauge.Value, ts)}
	case m.Counter != nil && m.Counter.Value != nil:
		return [][]byte{encodeTimeSeries(baseLabels, *m.Counter.Value, ts)}
	case m.Untyped != nil && m.Untyped.Value != nil:
		return [][]byte{encodeTimeSeries(baseLabels, *m.Untyped.Value, ts)}
	case m.Histogram != nil:
		return extractHistogramSeries(name, m.Histogram, m.Label, ts)
	default:
		return nil
	}
}

func extractLabels(name string, labelPairs []*dto.LabelPair) [][2]string {
	labels := make([][2]string, 0, len(labelPairs)+1)
	labels = append(labels, [2]string{"__name__", name})

	for _, lp := range labelPairs {
		if lp != nil && lp.Name != nil && lp.Value != nil {
			labels = append(labels, [2]string{*lp.Name, *lp.Value})
		}
	}

	slices.SortFunc(labels, func(a, b [2]string) int {
		return strings.Compare(a[0], b[0])
	})

	return labels
}

func extractHistogramSeries(name string, h *dto.Histogram, labelPairs []*dto.LabelPair, ts int64) [][]byte {
	var result [][]byte

	// 1. Buckets: name + "_bucket" with label "le"
	for _, b := range h.Bucket {
		if b == nil || b.UpperBound == nil || b.CumulativeCount == nil {
			continue
		}

		bucketLabels := extractLabels(name+"_bucket", labelPairs)
		bucketLabels = append(bucketLabels, [2]string{"le", strconv.FormatFloat(*b.UpperBound, 'f', -1, 64)})
		slices.SortFunc(bucketLabels, func(a, b [2]string) int {
			return strings.Compare(a[0], b[0])
		})

		result = append(result, encodeTimeSeries(bucketLabels, float64(*b.CumulativeCount), ts))
	}

	// 2. Sum: name + "_sum"
	if h.SampleSum != nil {
		sumLabels := extractLabels(name+"_sum", labelPairs)
		result = append(result, encodeTimeSeries(sumLabels, *h.SampleSum, ts))
	}

	// 3. Count: name + "_count"
	if h.SampleCount != nil {
		countLabels := extractLabels(name+"_count", labelPairs)
		result = append(result, encodeTimeSeries(countLabels, float64(*h.SampleCount), ts))
	}

	return result
}

func encodeLabel(name, value string) []byte {
	var b []byte

	b = protowire.AppendTag(b, 1, protowire.BytesType)
	b = protowire.AppendString(b, name)
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	b = protowire.AppendString(b, value)

	return b
}

func encodeSample(value float64, timestampMs int64) []byte {
	var b []byte

	b = protowire.AppendTag(b, 1, protowire.Fixed64Type)
	b = protowire.AppendFixed64(b, math.Float64bits(value))
	b = protowire.AppendTag(b, 2, protowire.VarintType)
	b = protowire.AppendVarint(b, uint64(timestampMs))

	return b
}

func encodeTimeSeries(labels [][2]string, value float64, timestampMs int64) []byte {
	var b []byte
	for _, lbl := range labels {
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendBytes(b, encodeLabel(lbl[0], lbl[1]))
	}

	b = protowire.AppendTag(b, 2, protowire.BytesType)
	b = protowire.AppendBytes(b, encodeSample(value, timestampMs))

	return b
}

func encodeWriteRequest(series [][]byte) []byte {
	var b []byte
	for _, s := range series {
		b = protowire.AppendTag(b, 1, protowire.BytesType)
		b = protowire.AppendBytes(b, s)
	}

	return b
}
