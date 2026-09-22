// Package observability implements continuous synthetic HTTPS probing and metrics
// exposition via Prometheus pull, Prometheus remote_write push, and OpenTelemetry OTLP/HTTP.
package observability

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	dto "github.com/prometheus/client_model/go"
	"github.com/xenos76/https-wrench/internal/requests"
)

// Runner manages the execution loop, metric updates, and propagation for observability mode.
type Runner struct {
	mu             sync.RWMutex
	cfg            Config
	reqMeta        *requests.RequestsMetaConfig
	metrics        *Metrics
	server         *Server
	exporters      []Exporter
	out            io.Writer
	logger         atomic.Pointer[slog.Logger]
	configPath     string
	lastConfigHash [32]byte
	reloadFn       func() (*Config, *requests.RequestsMetaConfig, error)
	intervalCh     chan time.Duration
}

// NewRunner creates an initialized Runner instance.
func NewRunner(cfg Config, reqMeta *requests.RequestsMetaConfig) (*Runner, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	logger := cfg.Logging.BuildLogger(nil)
	metrics := NewMetrics(cfg.Metrics, logger)

	var server *Server
	if cfg.Pull.Enabled {
		server = NewServer(cfg.Pull, metrics.Registry(), logger)
	}

	var exporters []Exporter
	if cfg.Push.Prometheus.Enabled {
		exporters = append(exporters, NewRemoteWriteExporter(cfg.Push.Prometheus))
	}

	if cfg.Push.OTLP.Enabled {
		exporters = append(exporters, NewOTLPExporter(cfg.Push.OTLP))
	}

	r := &Runner{
		cfg:        cfg,
		reqMeta:    reqMeta,
		metrics:    metrics,
		server:     server,
		exporters:  exporters,
		intervalCh: make(chan time.Duration, 1),
	}
	r.logger.Store(logger)

	return r, nil
}

// output returns the designated output writer or falls back to os.Stdout.
func (r *Runner) output() io.Writer {
	if r.out != nil {
		return r.out
	}

	return os.Stdout
}

// SetOutput configures a custom output writer for runner log messages and rebuilds internal loggers.
func (r *Runner) SetOutput(w io.Writer) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.out = w
	newLogger := r.cfg.Logging.BuildLogger(w)
	r.logger.Store(newLogger)

	if r.metrics != nil {
		r.metrics.SetLogger(newLogger)
	}

	if r.server != nil {
		r.server.SetLogger(newLogger)
	}
}

// Logger returns the active structured logger.
func (r *Runner) Logger() *slog.Logger {
	if l := r.logger.Load(); l != nil {
		return l
	}

	return slog.Default()
}

// SetLogger configures a custom logger for the runner and updates internal components.
func (r *Runner) SetLogger(l *slog.Logger) {
	if l == nil {
		l = slog.Default()
	}

	r.logger.Store(l)

	if r.metrics != nil {
		r.metrics.SetLogger(l)
	}

	if r.server != nil {
		r.server.SetLogger(l)
	}
}

// SetReloader configures the dynamic reload function and the path of the config file to watch.
func (r *Runner) SetReloader(configPath string, fn func() (*Config, *requests.RequestsMetaConfig, error)) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.configPath = configPath
	r.reloadFn = fn

	if configPath != "" {
		if content, err := os.ReadFile(configPath); err == nil {
			r.lastConfigHash = sha256.Sum256(content)
		}
	}
}

// Reload re-reads and applies configuration changes dynamically without dropping state.
func (r *Runner) Reload() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.reloadFn == nil {
		return errors.New("observability: no reload function configured")
	}

	newCfg, newReqMeta, err := r.reloadFn()
	if err != nil {
		r.Logger().Error("configuration reload failed", "error", err)
		return err
	}

	if err := r.applyNewConfig(newCfg, newReqMeta); err != nil {
		r.Logger().Error("configuration reload failed", "error", err)
		return err
	}

	if r.configPath != "" {
		if content, err := os.ReadFile(r.configPath); err == nil {
			r.lastConfigHash = sha256.Sum256(content)
		}
	}

	r.Logger().Info("configuration reloaded successfully")

	return nil
}

// validateReloadConfig ensures the new configuration is valid and does not alter immutable settings.
func (r *Runner) validateReloadConfig(newCfg *Config) error {
	if err := newCfg.Validate(); err != nil {
		return fmt.Errorf("observability: invalid reload config: %w", err)
	}

	if !isPullConfigEqual(r.cfg.Pull, newCfg.Pull) {
		return errors.New(
			"observability: reload does not support modifying pull configuration (address, path, enabled)",
		)
	}

	if !isMetricsConfigEqual(r.cfg.Metrics, newCfg.Metrics) {
		return errors.New(
			"observability: reload does not support modifying metrics configuration (labels, filters)",
		)
	}

	return nil
}

// applyLoggingUpdate rebuilds and disseminates new loggers if logging settings changed.
func (r *Runner) applyLoggingUpdate(newLogging LoggingConfig) {
	if isLoggingConfigEqual(r.cfg.Logging, newLogging) {
		return
	}

	newLogger := newLogging.BuildLogger(r.out)
	r.logger.Store(newLogger)
	r.metrics.SetLogger(newLogger)

	if r.server != nil {
		r.server.SetLogger(newLogger)
	}
}

// applyNewConfig validates and applies reloaded configuration, rejecting runtime modifications to immutable settings.
func (r *Runner) applyNewConfig(newCfg *Config, newReqMeta *requests.RequestsMetaConfig) error {
	if newCfg != nil {
		if err := r.validateReloadConfig(newCfg); err != nil {
			return err
		}

		r.applyLoggingUpdate(newCfg.Logging)

		oldInterval := r.cfg.Interval
		r.cfg = *newCfg
		r.updateExporters(newCfg.Push)

		if newCfg.Interval > 0 && newCfg.Interval != oldInterval {
			select {
			case r.intervalCh <- newCfg.Interval:
			default:
			}
		}
	}

	if newReqMeta != nil {
		r.reqMeta = newReqMeta
	}

	return nil
}

// isPullConfigEqual compares two PullConfig instances for value equality.
func isPullConfigEqual(a, b PullConfig) bool {
	if a.Enabled != b.Enabled {
		return false
	}

	if !a.Enabled {
		return true
	}

	return a.Address == b.Address && a.Path == b.Path &&
		a.ReloadToken == b.ReloadToken && a.ReloadSecret == b.ReloadSecret
}

// isMetricsConfigEqual compares two MetricsFilterConfig instances for value and custom label equality.
func isMetricsConfigEqual(a, b MetricsFilterConfig) bool {
	if a.IncludeTLS != b.IncludeTLS ||
		a.IncludeCertChain != b.IncludeCertChain ||
		a.StripQuery != b.StripQuery {
		return false
	}

	return maps.Equal(a.CustomLabels, b.CustomLabels)
}

// updateExporters replaces active push exporters with new instances based on updated PushConfig.
func (r *Runner) updateExporters(push PushConfig) {
	var newExporters []Exporter
	if push.Prometheus.Enabled {
		newExporters = append(newExporters, NewRemoteWriteExporter(push.Prometheus))
	}

	if push.OTLP.Enabled {
		newExporters = append(newExporters, NewOTLPExporter(push.OTLP))
	}

	for _, old := range r.exporters {
		_ = old.Close()
	}

	r.exporters = newExporters
}

// checkFileModification computes the SHA256 hash of the watched config file and reloads if changed.
func (r *Runner) checkFileModification() {
	r.mu.RLock()
	path := r.configPath
	lastHash := r.lastConfigHash
	r.mu.RUnlock()

	if path == "" {
		return
	}

	content, err := os.ReadFile(path)
	if err != nil {
		return
	}

	currentHash := sha256.Sum256(content)
	if currentHash == lastHash {
		return
	}

	if err := r.Reload(); err != nil {
		r.Logger().Warn(
			"configuration file changed on disk but failed to reload; retaining current configuration",
			"error",
			err,
		)
	}
}

// Metrics returns the Metrics collector used by this runner.
func (r *Runner) Metrics() *Metrics {
	return r.metrics
}

// Server returns the pull HTTP server, if initialized.
func (r *Runner) Server() *Server {
	return r.server
}

// Exporters returns the list of registered push exporters.
func (r *Runner) Exporters() []Exporter {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Exporter, len(r.exporters))
	copy(result, r.exporters)

	return result
}

// Run executes the immediate first probe cycle, starts the pull server if enabled,
// and continues probing at the configured interval until the context is canceled.
func (r *Runner) Run(ctx context.Context) error {
	if r.server != nil {
		r.server.RegisterReloadHandler(r.Reload)

		if err := r.server.Start(); err != nil {
			return err
		}

		r.Logger().Info(
			"scrape server listening",
			"address",
			r.server.Addr(),
			"path",
			r.cfg.Pull.Path,
		)
	}

	for _, exp := range r.Exporters() {
		r.Logger().Info("push exporter registered", "exporter", exp.Name())
	}

	r.mu.RLock()
	interval := r.cfg.Interval
	timeout := r.cfg.Timeout
	r.mu.RUnlock()

	r.Logger().Info(
		"starting probe loop",
		"interval",
		interval.String(),
		"timeout",
		timeout.String(),
	)

	// Immediate initial execution
	r.ExecuteCycle(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	hupCh := make(chan os.Signal, 1)

	signal.Notify(hupCh, syscall.SIGHUP)
	defer signal.Stop(hupCh)

	for {
		select {
		case <-ctx.Done():
			r.Logger().Info("stopping runner")
			r.shutdown()

			return nil

		case <-hupCh:
			r.Logger().Info("SIGHUP received, reloading configuration")
			_ = r.Reload()

		case newInterval := <-r.intervalCh:
			ticker.Reset(newInterval)
			r.Logger().Info("probe interval updated", "interval", newInterval.String())

		case <-ticker.C:
			r.ExecuteCycle(ctx)
		}
	}
}

// ExecuteCycle runs a single probe round, records metrics, and pushes to enabled exporters.
func (r *Runner) ExecuteCycle(ctx context.Context) {
	r.checkFileModification()

	r.mu.RLock()
	timeout := r.cfg.Timeout
	reqMeta := r.reqMeta
	exporters := r.exporters
	r.mu.RUnlock()

	cycleCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	result, responseMap, err := reqMeta.ExecuteWithWriter(cycleCtx, io.Discard)
	duration := time.Since(start)

	if err != nil {
		r.Logger().Warn("probe cycle returned error", "error", err)
	}

	r.metrics.RecordRun(result, responseMap, duration)
	r.logCycleSummary(result, responseMap, duration)

	if len(exporters) == 0 {
		return
	}

	mfs, gatherErr := r.metrics.Registry().Gather()
	if gatherErr != nil {
		r.Logger().Error("failed to gather metrics", "error", gatherErr)
		return
	}

	r.dispatchPushes(ctx, exporters, mfs, timeout)
}

// logCycleSummary logs an aggregated cycle summary at Info level and target failures at Debug level.
func (r *Runner) logCycleSummary(
	result *requests.Result,
	responseMap map[string][]requests.ResponseData,
	duration time.Duration,
) {
	if result == nil {
		return
	}

	totalReqs := len(result.Requests)
	totalResps := 0
	successes := 0
	failures := 0

	for _, reqRes := range result.Requests {
		rdList := responseMap[reqRes.Name]

		for i, respRes := range reqRes.Responses {
			totalResps++

			var rd requests.ResponseData
			if i < len(rdList) {
				rd = rdList[i]
			}

			if isResponseHealthy(respRes.StatusCode, respRes, rd) {
				successes++
			} else {
				failures++

				r.Logger().Debug(
					"probe target failure",
					"request_name", reqRes.Name,
					"url", respRes.URL,
					"status_code", respRes.StatusCode,
					"error", respRes.Error,
				)
			}
		}
	}

	r.Logger().Info(
		"probe cycle completed",
		"requests", totalReqs,
		"responses", totalResps,
		"successes", successes,
		"failures", failures,
		"duration_ms", duration.Milliseconds(),
	)
}

// dispatchPushes concurrently exports metric families to all registered push destinations with a per-exporter timeout.
func (r *Runner) dispatchPushes(
	ctx context.Context,
	exporters []Exporter,
	mfs []*dto.MetricFamily,
	timeout time.Duration,
) {
	var wg sync.WaitGroup

	for _, exp := range exporters {
		e := exp

		wg.Go(func() {
			exportCtx, expCancel := context.WithTimeout(ctx, timeout)
			defer expCancel()

			if err := e.Export(exportCtx, mfs); err != nil {
				r.Logger().Error("push exporter error", "exporter", e.Name(), "error", err)
				r.metrics.RecordPushError(e.Name())
			} else {
				r.metrics.RecordPushSuccess(e.Name(), time.Now())
			}
		})
	}

	wg.Wait()
}

// shutdown gracefully stops the pull scrape server and closes all active push exporters.
func (r *Runner) shutdown() {
	if r.server != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := r.server.Shutdown(shutdownCtx); err != nil {
			r.Logger().Error("server shutdown error", "error", err)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, exp := range r.exporters {
		_ = exp.Close()
	}
}
