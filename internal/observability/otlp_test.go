package observability

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	otlpmetricsv1 "go.opentelemetry.io/proto/otlp/metrics/v1"
	"google.golang.org/protobuf/proto"
)

func TestOTLPExporter(t *testing.T) {
	t.Parallel()

	t.Run("successful export", func(t *testing.T) {
		var receivedReq otlpmetricsv1.MetricsData

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/v1/metrics", r.URL.Path)
			assert.Equal(t, "application/x-protobuf", r.Header.Get("Content-Type"))
			assert.Equal(t, "custom-val", r.Header.Get("X-Custom"))

			body, err := io.ReadAll(r.Body)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			if unmarshalErr := proto.Unmarshal(body, &receivedReq); unmarshalErr != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}

			w.WriteHeader(http.StatusOK)
		}))
		defer ts.Close()

		m := NewMetrics(MetricsFilterConfig{})
		m.RecordPushSuccess("test", time.Now())
		mfs, err := m.Registry().Gather()
		require.NoError(t, err)

		exp := NewOTLPExporter(PushOTLPConfig{
			Enabled:  true,
			Endpoint: ts.URL, // will auto-append /v1/metrics
			Timeout:  2 * time.Second,
			Headers: map[string]string{
				"X-Custom": "custom-val",
			},
		})
		defer exp.Close()

		require.Equal(t, "otlp", exp.Name())

		exportErr := exp.Export(context.Background(), mfs)
		require.NoError(t, exportErr)

		require.NotEmpty(t, receivedReq.ResourceMetrics)
		require.NotEmpty(t, receivedReq.ResourceMetrics[0].ScopeMetrics)
		require.NotEmpty(t, receivedReq.ResourceMetrics[0].ScopeMetrics[0].Metrics)
	})

	t.Run("server error returns error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("invalid OTLP payload"))
		}))
		defer ts.Close()

		m := NewMetrics(MetricsFilterConfig{})
		mfs, _ := m.Registry().Gather()

		exp := NewOTLPExporter(PushOTLPConfig{
			Enabled:  true,
			Endpoint: ts.URL + "/v1/metrics",
		})
		defer exp.Close()

		err := exp.Export(context.Background(), mfs)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 400")
	})
}

func TestExtractHistogramBuckets_IncludesInfBucket(t *testing.T) {
	t.Parallel()

	bound1 := 0.1
	count1 := uint64(2)
	bound2 := 0.5
	count2 := uint64(5)
	sampleCount := uint64(9)

	h := &dto.Histogram{
		SampleCount: &sampleCount,
		Bucket: []*dto.Bucket{
			{UpperBound: &bound1, CumulativeCount: &count1},
			{UpperBound: &bound2, CumulativeCount: &count2},
		},
	}

	bounds, counts := extractHistogramBuckets(h)

	assert.Equal(t, []float64{0.1, 0.5}, bounds)
	// BucketCounts has one more entry than ExplicitBounds:
	// delta 0: 2, delta 1: 5-2=3, +Inf: 9-5=4
	assert.Equal(t, []uint64{2, 3, 4}, counts)
	assert.Len(t, counts, len(bounds)+1)
}
