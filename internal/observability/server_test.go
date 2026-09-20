package observability

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPullServer(t *testing.T) {
	t.Parallel()

	m := NewMetrics(MetricsFilterConfig{})
	srv := NewServer(PullConfig{
		Enabled: true,
		Address: "127.0.0.1:0",
		Path:    "/metrics",
	}, m.Registry())

	require.NoError(t, srv.Start())
	defer func() {
		_ = srv.Shutdown(context.Background())
	}()

	addr := srv.Addr()
	require.NotEmpty(t, addr)

	client := &http.Client{Timeout: 2 * time.Second}

	// Test /healthz
	resp, err := client.Get("http://" + addr + "/healthz")
	require.NoError(t, err)

	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Equal(t, "OK\n", string(body))

	// Test /readyz
	respReady, err := client.Get("http://" + addr + "/readyz")
	require.NoError(t, err)

	defer respReady.Body.Close()

	assert.Equal(t, http.StatusOK, respReady.StatusCode)

	// Test /metrics
	respMetrics, err := client.Get("http://" + addr + "/metrics")
	require.NoError(t, err)

	defer respMetrics.Body.Close()

	assert.Equal(t, http.StatusOK, respMetrics.StatusCode)
	metricsBody, _ := io.ReadAll(respMetrics.Body)
	assert.Contains(t, string(metricsBody), "https_wrench_")
}

func TestPullServer_ReloadHandler(t *testing.T) {
	t.Parallel()

	m := NewMetrics(MetricsFilterConfig{})
	srv := NewServer(PullConfig{
		Enabled: true,
		Address: "127.0.0.1:0",
		Path:    "/metrics",
	}, m.Registry())

	reloadCalls := 0

	var reloadErr error

	srv.RegisterReloadHandler(func() error {
		reloadCalls++
		return reloadErr
	})

	require.NoError(t, srv.Start())
	defer func() {
		_ = srv.Shutdown(context.Background())
	}()

	addr := srv.Addr()
	client := &http.Client{Timeout: 2 * time.Second}

	// 1. GET /-/reload should return 405 Method Not Allowed
	respGet, err := client.Get("http://" + addr + "/-/reload")
	require.NoError(t, err)

	defer respGet.Body.Close()

	assert.Equal(t, http.StatusMethodNotAllowed, respGet.StatusCode)

	// 2. POST /-/reload with successful reload
	respPost, err := client.Post("http://"+addr+"/-/reload", "text/plain", nil)
	require.NoError(t, err)

	defer respPost.Body.Close()

	assert.Equal(t, http.StatusOK, respPost.StatusCode)
	assert.Equal(t, 1, reloadCalls)

	// 3. POST /-/reload with reload error
	reloadErr = assert.AnError
	respErr, err := client.Post("http://"+addr+"/-/reload", "text/plain", nil)
	require.NoError(t, err)

	defer respErr.Body.Close()

	assert.Equal(t, http.StatusInternalServerError, respErr.StatusCode)
	assert.Equal(t, 2, reloadCalls)
}

func TestPullServer_ReloadAuthorization(t *testing.T) {
	t.Parallel()

	m := NewMetrics(MetricsFilterConfig{})
	srv := NewServer(PullConfig{
		Enabled: true,
		Address: "127.0.0.1:0",
		Path:    "/metrics",
	}, m.Registry())

	reloadCalls := 0

	srv.RegisterReloadHandler(func() error {
		reloadCalls++
		return nil
	})

	// 1. Untrusted remote address without Authorization is rejected with 403 Forbidden
	reqRemote := httptest.NewRequest(http.MethodPost, "/-/reload", nil)
	reqRemote.RemoteAddr = "192.168.1.100:54321"

	recRemote := httptest.NewRecorder()
	srv.mux.ServeHTTP(recRemote, reqRemote)

	assert.Equal(t, http.StatusForbidden, recRemote.Code)
	assert.Equal(t, 0, reloadCalls)

	// 2. Untrusted remote address with Authorization header is accepted
	reqAuth := httptest.NewRequest(http.MethodPost, "/-/reload", nil)
	reqAuth.RemoteAddr = "192.168.1.100:54321"
	reqAuth.Header.Set("Authorization", "Bearer reload-secret")

	recAuth := httptest.NewRecorder()
	srv.mux.ServeHTTP(recAuth, reqAuth)

	assert.Equal(t, http.StatusOK, recAuth.Code)
	assert.Equal(t, 1, reloadCalls)

	// 3. Trusted loopback remote address is accepted without Authorization
	reqLoopback := httptest.NewRequest(http.MethodPost, "/-/reload", nil)
	reqLoopback.RemoteAddr = "127.0.0.1:54321"

	recLoopback := httptest.NewRecorder()
	srv.mux.ServeHTTP(recLoopback, reqLoopback)

	assert.Equal(t, http.StatusOK, recLoopback.Code)
	assert.Equal(t, 2, reloadCalls)
}
