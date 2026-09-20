package observability

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
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

		if !s.isAuthorizedReload(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
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

func (s *Server) isAuthorizedReload(r *http.Request) bool {
	return isAuthorizedReload(r, s.cfg)
}

func isAuthorizedReload(r *http.Request, cfg ...PullConfig) bool {
	var pullCfg PullConfig
	if len(cfg) > 0 {
		pullCfg = cfg[0]
	}

	expected := pullCfg.ReloadAuthToken()
	if expected != "" {
		authHeader := r.Header.Get("Authorization")
		if verifyReloadCredential(authHeader, expected) {
			return true
		}
	}

	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}

	return ip.IsLoopback()
}

func verifyReloadCredential(authHeader, expected string) bool {
	if authHeader == "" || expected == "" {
		return false
	}

	trimmed := strings.TrimSpace(authHeader)
	if subtle.ConstantTimeCompare([]byte(trimmed), []byte(expected)) == 1 {
		return true
	}

	if len(trimmed) > 7 && strings.EqualFold(trimmed[:7], "bearer ") {
		token := strings.TrimSpace(trimmed[7:])
		if subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1 {
			return true
		}
	}

	return false
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
