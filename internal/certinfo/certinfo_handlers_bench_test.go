package certinfo

import (
	"crypto/tls"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

func BenchmarkProbeCiphersConcurrently(b *testing.B) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	b.Cleanup(server.Close)

	u, err := url.Parse(server.URL)
	require.NoError(b, err)

	cc, err := New()
	require.NoError(b, err)

	cc.SetTLSInsecure(true)
	cc.SetTLSServerName("example.com")

	err = cc.SetTLSEndpoint(b.Context(), u.Host)
	require.NoError(b, err)

	cc.ProbedProtocols = map[string]bool{
		"TLS 1.3": true,
		"TLS 1.2": true,
		"TLS 1.1": false,
		"TLS 1.0": false,
	}

	suites := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)

	b.ReportAllocs()

	for b.Loop() {
		_ = cc.probeCiphersConcurrently(b.Context(), suites)
	}
}
