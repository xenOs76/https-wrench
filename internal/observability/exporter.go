// Package observability implements continuous synthetic HTTPS probing and metrics
// exposition via Prometheus pull, Prometheus remote_write push, and OpenTelemetry OTLP/HTTP.
package observability

import (
	"context"

	dto "github.com/prometheus/client_model/go"
)

// Exporter represents a destination for pushing collected metrics.
type Exporter interface {
	// Name returns the identifier of the exporter (e.g., "prometheus_remote_write", "otlp").
	Name() string
	// Export sends the metric families to the target destination.
	Export(ctx context.Context, metricFamilies []*dto.MetricFamily) error
	// Close releases any resources or connections associated with the exporter.
	Close() error
}
