package observability

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
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

	metrics := NewMetrics(cfg.Metrics)

	var server *Server
	if cfg.Pull.Enabled {
		server = NewServer(cfg.Pull, metrics.Registry())
	}

	var exporters []Exporter
	if cfg.Push.Prometheus.Enabled {
		exporters = append(exporters, NewRemoteWriteExporter(cfg.Push.Prometheus))
	}

	if cfg.Push.OTLP.Enabled {
		exporters = append(exporters, NewOTLPExporter(cfg.Push.OTLP))
	}

	return &Runner{
		cfg:        cfg,
		reqMeta:    reqMeta,
		metrics:    metrics,
		server:     server,
		exporters:  exporters,
		intervalCh: make(chan time.Duration, 1),
	}, nil
}

func (r *Runner) output() io.Writer {
	if r.out != nil {
		return r.out
	}

	return os.Stdout
}

// SetOutput configures a custom output writer for runner log messages.
func (r *Runner) SetOutput(w io.Writer) {
	r.out = w
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
		fmt.Fprintf(r.output(), "observability: reload failed: %v\n", err)
		return err
	}

	r.applyNewConfig(newCfg, newReqMeta)

	if r.configPath != "" {
		if content, err := os.ReadFile(r.configPath); err == nil {
			r.lastConfigHash = sha256.Sum256(content)
		}
	}

	fmt.Fprintln(r.output(), "observability: configuration reloaded successfully")
	return nil
}

func (r *Runner) applyNewConfig(newCfg *Config, newReqMeta *requests.RequestsMetaConfig) {
	if newCfg != nil {
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
}

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
		fmt.Fprintf(
			r.output(),
			"observability: config file changed on disk but failed to reload: %v (retaining current configuration)\n",
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

		fmt.Fprintf(
			r.output(),
			"observability: scrape server listening on http://%s%s\n",
			r.server.Addr(),
			r.cfg.Pull.Path,
		)
	}

	for _, exp := range r.Exporters() {
		fmt.Fprintf(r.output(), "observability: push exporter %q registered\n", exp.Name())
	}

	r.mu.RLock()
	interval := r.cfg.Interval
	timeout := r.cfg.Timeout
	r.mu.RUnlock()

	fmt.Fprintf(
		r.output(),
		"observability: starting probe loop with interval %s (timeout: %s)\n",
		interval,
		timeout,
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
			fmt.Fprintln(r.output(), "observability: stopping runner...")
			r.shutdown()
			return nil

		case <-hupCh:
			fmt.Fprintln(r.output(), "observability: SIGHUP received, reloading configuration...")
			_ = r.Reload()

		case newInterval := <-r.intervalCh:
			ticker.Reset(newInterval)
			fmt.Fprintf(r.output(), "observability: probe interval updated to %s\n", newInterval)

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
		fmt.Fprintf(r.output(), "observability: probe cycle returned error: %v\n", err)
	}

	r.metrics.RecordRun(result, responseMap, duration)

	if len(exporters) == 0 {
		return
	}

	mfs, gatherErr := r.metrics.Registry().Gather()
	if gatherErr != nil {
		fmt.Fprintf(r.output(), "observability: failed to gather metrics: %v\n", gatherErr)
		return
	}

	r.dispatchPushes(ctx, exporters, mfs, timeout)
}

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
				fmt.Fprintf(r.output(), "observability: push exporter %q error: %v\n", e.Name(), err)
				r.metrics.RecordPushError(e.Name())
			} else {
				r.metrics.RecordPushSuccess(e.Name(), time.Now())
			}
		})
	}

	wg.Wait()
}

func (r *Runner) shutdown() {
	if r.server != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := r.server.Shutdown(shutdownCtx); err != nil {
			fmt.Fprintf(r.output(), "observability: server shutdown error: %v\n", err)
		}
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for _, exp := range r.exporters {
		_ = exp.Close()
	}
}
