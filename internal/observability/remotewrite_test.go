package observability

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/snappy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemoteWriteExporter(t *testing.T) {
	t.Parallel()

	t.Run("successful export", func(t *testing.T) {
		var (
			receivedHeaders  http.Header
			decompressedBody []byte
		)

		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			receivedHeaders = r.Header.Clone()
			body, _ := io.ReadAll(r.Body)

			var err error

			decompressedBody, err = snappy.Decode(nil, body)
			if err != nil {
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

		exp := NewRemoteWriteExporter(PushPrometheusConfig{
			Enabled:        true,
			RemoteWriteURL: ts.URL,
			Timeout:        2 * time.Second,
			BearerToken:    "test-token",
			Headers: map[string]string{
				"X-Custom-Tenant": "tenant-1",
			},
		})
		defer exp.Close()

		require.Equal(t, "prometheus_remote_write", exp.Name())

		exportErr := exp.Export(context.Background(), mfs)
		require.NoError(t, exportErr)

		assert.Equal(t, "application/x-protobuf", receivedHeaders.Get("Content-Type"))
		assert.Equal(t, "snappy", receivedHeaders.Get("Content-Encoding"))
		assert.Equal(t, "Bearer test-token", receivedHeaders.Get("Authorization"))
		assert.Equal(t, "tenant-1", receivedHeaders.Get("X-Custom-Tenant"))
		assert.NotEmpty(t, decompressedBody)
	})

	t.Run("server error returns error", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte("internal database error"))
		}))
		defer ts.Close()

		m := NewMetrics(MetricsFilterConfig{})
		mfs, _ := m.Registry().Gather()

		exp := NewRemoteWriteExporter(PushPrometheusConfig{
			Enabled:        true,
			RemoteWriteURL: ts.URL,
		})
		defer exp.Close()

		exportErr := exp.Export(context.Background(), mfs)
		require.Error(t, exportErr)
		assert.Contains(t, exportErr.Error(), "internal database error")
	})
}
