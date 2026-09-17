package observability

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Server is an embedded HTTP server for exposing Prometheus pull metrics.
type Server struct {
	httpServer *http.Server
	listener   net.Listener
	mux        *http.ServeMux
	cfg        PullConfig
	reg        *prometheus.Registry
}

// NewServer initializes an HTTP server for scraping metrics.
func NewServer(cfg PullConfig, reg *prometheus.Registry) *Server {
	if cfg.Address == "" {
		cfg.Address = DefaultPullAddress
	}

	if cfg.Path == "" {
		cfg.Path = DefaultPullPath
	}

	mux := http.NewServeMux()

	mux.Handle(cfg.Path, promhttp.HandlerFor(reg, promhttp.HandlerOpts{
		EnableOpenMetrics: true,
	}))

	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK\n"))
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK\n"))
	})

	srv := &http.Server{
		Addr:              cfg.Address,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	return &Server{
		httpServer: srv,
		mux:        mux,
		cfg:        cfg,
		reg:        reg,
	}
}

// RegisterReloadHandler registers an HTTP POST /-/reload endpoint for dynamic configuration reloads.
func (s *Server) RegisterReloadHandler(fn func() error) {
	if s.mux == nil {
		return
	}

	s.mux.HandleFunc("/-/reload", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := fn(); err != nil {
			http.Error(w, fmt.Sprintf("Reload failed: %v", err), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Configuration reloaded successfully\n"))
	})
}

// Start binds the listener and begins serving HTTP requests in the background.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", s.cfg.Address)
	if err != nil {
		return fmt.Errorf("observability: failed to listen on %s: %w", s.cfg.Address, err)
	}

	s.listener = ln

	go func() {
		if serveErr := s.httpServer.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			fmt.Printf("observability: scrape server error: %v\n", serveErr)
		}
	}()

	return nil
}

// Addr returns the actual bound network address of the server (useful for tests using :0).
func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}

	return s.cfg.Address
}

// Shutdown gracefully stops the pull server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s.httpServer == nil {
		return nil
	}

	return s.httpServer.Shutdown(ctx)
}
