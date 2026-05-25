package requests

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPrintResponseData(t *testing.T) {
	t.Parallel()

	rd := ResponseData{
		URL: "https://example.com/",
		Request: RequestConfig{
			PrintResponseHeaders:    true,
			PrintResponseBody:       true,
			ResponseBodyMatchRegexp: "ok",
		},
		Response: &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{"Server": []string{"test"}},
		},
		ResponseBody:              "ok",
		ResponseBodyRegexpMatched: true,
	}

	require.Empty(t, capturePrintResponseData(rd, false))

	rd.Error = errors.New("dial failed")
	out := capturePrintResponseData(rd, true)
	require.Contains(t, out, "dial failed")
	require.Contains(t, out, "Error:")

	rd.Error = nil
	rd.Request.PrintResponseCertificates = true
	rd.Response.TLS = &tls.ConnectionState{
		Version:     tls.VersionTLS13,
		CipherSuite: tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates: []*x509.Certificate{
			{Subject: pkix.Name{CommonName: "example.com"}},
		},
	}
	out = capturePrintResponseData(rd, true)
	require.Contains(t, out, "TLS:")
	require.Contains(t, out, "https://example.com/")
	require.Contains(t, out, "200")
	require.Contains(t, out, "Headers:")
	require.Contains(t, out, "Body:")
	require.Contains(t, out, "BodyRegexpMatch:")
}

func capturePrintResponseData(rd ResponseData, verbose bool) string {
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	rd.PrintResponseData(verbose)

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer

	_, _ = io.Copy(&buf, r)
	_ = r.Close()

	return buf.String()
}
