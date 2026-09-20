package requests

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xenos76/https-wrench/internal/view"
)

func sampleResultData() (*RequestsMetaConfig, map[string][]ResponseData) {
	cfg := &RequestsMetaConfig{
		Requests: []RequestConfig{
			{
				Name:                      "test-req",
				TransportOverrideURL:      "https://127.0.0.1:8443",
				PrintResponseHeaders:      true,
				PrintResponseBody:         true,
				PrintResponseCertificates: true,
				ResponseBodyMatchRegexp:   "ok",
			},
		},
	}

	mockCert := &x509.Certificate{
		Subject:      pkix.Name{CommonName: "test.example.com"},
		SerialNumber: big.NewInt(12345),
	}

	matched := true
	responseMap := map[string][]ResponseData{
		"test-req": {
			{
				URL:              "https://example.com/api",
				TransportAddress: "127.0.0.1:8443",
				Request:          cfg.Requests[0],
				Response: &http.Response{
					StatusCode: http.StatusOK,
					Status:     "200 OK",
					Header: http.Header{
						"Content-Type": []string{"application/json"},
						"Server":       []string{"mock-server"},
					},
					TLS: &tls.ConnectionState{
						Version:          tls.VersionTLS13,
						CipherSuite:      tls.TLS_AES_128_GCM_SHA256,
						PeerCertificates: []*x509.Certificate{mockCert},
					},
				},
				ResponseBody:              "{\"status\":\"ok\"}",
				ResponseContentType:       "json",
				ResponseBodyRegexpMatched: matched,
				TransferredBytes:          15,
			},
			{
				URL:              "https://example.com/fail",
				TransportAddress: "127.0.0.1:8443",
				Request:          cfg.Requests[0],
				Error:            errors.New("connection reset"),
			},
		},
	}

	return cfg, responseMap
}

func TestRequests_BuildResult(t *testing.T) {
	t.Parallel()

	cfg, responseMap := sampleResultData()

	result, err := BuildResult(responseMap, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, ResultSchemaVersion, result.SchemaVersion)
	assert.Equal(t, resultCommand, result.Command)
	require.Len(t, result.Requests, 1)

	reqRes := result.Requests[0]
	assert.Equal(t, "test-req", reqRes.Name)
	assert.Equal(t, "https://127.0.0.1:8443", reqRes.TransportOverrideURL)
	require.Len(t, reqRes.Responses, 2)

	// Successful response assertions
	okResp := reqRes.Responses[0]
	assert.Equal(t, "https://example.com/api", okResp.URL)
	assert.Equal(t, 200, okResp.StatusCode)
	assert.Equal(t, "200 OK", okResp.Status)
	assert.Empty(t, okResp.Error)
	assert.NotNil(t, okResp.BodyRegexpMatched)
	assert.True(t, *okResp.BodyRegexpMatched)
	assert.JSONEq(t, "{\"status\":\"ok\"}", okResp.Body)
	assert.Equal(t, "json", okResp.ContentType)
	assert.Equal(t, int64(15), okResp.TransferredBytes)
	require.NotNil(t, okResp.TLS)
	assert.Equal(t, "TLS 1.3", okResp.TLS.Version)
	assert.Equal(t, "TLS_AES_128_GCM_SHA256", okResp.TLS.CipherSuite)
	require.Len(t, okResp.TLS.Certificates, 1)
	assert.Contains(t, okResp.TLS.Certificates[0].Subject, "test.example.com")
	assert.Contains(t, okResp.Headers, "Content-Type")

	// Error response assertions
	errResp := reqRes.Responses[1]
	assert.Equal(t, "https://example.com/fail", errResp.URL)
	assert.Equal(t, "connection reset", errResp.Error)
	assert.Equal(t, 0, errResp.StatusCode)
}

func TestRequests_EncodeJSON(t *testing.T) {
	t.Parallel()

	cfg, responseMap := sampleResultData()
	result, err := BuildResult(responseMap, cfg)
	require.NoError(t, err)

	payload, err := EncodeJSON(result)
	require.NoError(t, err)
	require.NotEmpty(t, payload)

	assert.NotContains(t, string(payload), "\x1b[", "JSON must not contain ANSI escape codes")

	var unmarshaled map[string]any
	require.NoError(t, json.Unmarshal(payload, &unmarshaled))
	assert.Equal(t, "1", unmarshaled["schemaVersion"])
	assert.Equal(t, "requests", unmarshaled["command"])
}

func TestRequests_BuildDoc(t *testing.T) {
	t.Parallel()

	cfg, responseMap := sampleResultData()
	result, err := BuildResult(responseMap, cfg)
	require.NoError(t, err)

	doc := BuildDoc(result)

	var buf bytes.Buffer

	err = view.Render(&buf, doc, view.Options{Plain: true})
	require.NoError(t, err)

	plainOutput := buf.String()
	assert.Contains(t, plainOutput, "Requests")
	assert.Contains(t, plainOutput, "Request: test-req")
	assert.Contains(t, plainOutput, "https://example.com/api")
	assert.Contains(t, plainOutput, "StatusCode: 200 OK")
	assert.Contains(t, plainOutput, "TLS")
	assert.Contains(t, plainOutput, "Headers")
	assert.Contains(t, plainOutput, "BodyRegexpMatch: true")
	assert.Contains(t, plainOutput, "connection reset")
	assert.NotContains(t, plainOutput, "\x1b[", "Plain view output must not contain ANSI escape codes")
}

func TestRequests_BuildResultErrors(t *testing.T) {
	t.Parallel()

	_, err := BuildResult(nil, nil)
	require.Error(t, err)

	_, err = EncodeJSON(nil)
	require.Error(t, err)
}

func TestRequests_BuildResult_ResponseBodyNotPrintedByDefault(t *testing.T) {
	t.Parallel()

	cfg := &RequestsMetaConfig{
		Requests: []RequestConfig{
			{
				Name:                    "regex-only",
				PrintResponseBody:       false,
				ResponseBodyMatchRegexp: "ok",
			},
		},
	}

	matched := true
	responseMap := map[string][]ResponseData{
		"regex-only": {
			{
				URL:     "https://example.com/api",
				Request: cfg.Requests[0],
				Response: &http.Response{
					StatusCode: http.StatusOK,
					Status:     "200 OK",
				},
				ResponseBody:              "{\"status\":\"ok\"}",
				ResponseContentType:       "json",
				ResponseBodyRegexpMatched: matched,
			},
		},
	}

	result, err := BuildResult(responseMap, cfg)
	require.NoError(t, err)
	require.NotNil(t, result)
	require.Len(t, result.Requests, 1)
	require.Len(t, result.Requests[0].Responses, 1)

	resp := result.Requests[0].Responses[0]
	assert.Empty(t, resp.Body)
	assert.NotNil(t, resp.BodyRegexpMatched)
	assert.True(t, *resp.BodyRegexpMatched)

	doc := BuildDoc(result)

	var buf bytes.Buffer

	require.NoError(t, view.Render(&buf, doc, view.Options{Plain: true}))
	assert.Contains(t, buf.String(), "BodyRegexpMatch: true")
	assert.NotContains(t, buf.String(), "Body:")
}

func TestRequests_BuildResult_DuplicateRequestName(t *testing.T) {
	t.Parallel()

	cfg := &RequestsMetaConfig{
		Requests: []RequestConfig{
			{Name: "duplicate-name"},
			{Name: "duplicate-name"},
		},
	}

	_, err := BuildResult(nil, cfg)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrDuplicateRequestName)

	var dupErr *DuplicateRequestNameError
	require.ErrorAs(t, err, &dupErr)
	assert.Equal(t, "duplicate-name", dupErr.Name)
}

func TestRequests_ExecuteWithWriter_DuplicateRequestName(t *testing.T) {
	t.Parallel()

	rmc, err := NewRequestsMetaConfig()
	require.NoError(t, err)

	rmc.Requests = []RequestConfig{
		{Name: "same-name"},
		{Name: "same-name"},
	}

	_, _, err = rmc.ExecuteWithWriter(context.Background(), io.Discard)
	require.Error(t, err)
	require.ErrorIs(t, err, ErrDuplicateRequestName)

	var dupErr *DuplicateRequestNameError
	require.ErrorAs(t, err, &dupErr)
	assert.Equal(t, "same-name", dupErr.Name)
}

func TestRequests_SingleResponseDoc_StatusTones(t *testing.T) {
	t.Parallel()

	tests := []struct {
		statusCode   int
		statusStr    string
		err          string
		expectedTone view.Tone
	}{
		{statusCode: 200, statusStr: "200 OK", expectedTone: view.ToneStatus2xx},
		{statusCode: 204, statusStr: "204 No Content", expectedTone: view.ToneStatus2xx},
		{statusCode: 301, statusStr: "301 Moved Permanently", expectedTone: view.ToneStatus3xx},
		{statusCode: 302, statusStr: "302 Found", expectedTone: view.ToneStatus3xx},
		{statusCode: 400, statusStr: "400 Bad Request", expectedTone: view.ToneStatus4xx},
		{statusCode: 404, statusStr: "404 Not Found", expectedTone: view.ToneStatus4xx},
		{statusCode: 500, statusStr: "500 Internal Server Error", expectedTone: view.ToneStatus5xx},
		{statusCode: 503, statusStr: "503 Service Unavailable", expectedTone: view.ToneStatus5xx},
		{statusCode: 0, err: "dial tcp: connection refused", expectedTone: view.ToneStatus5xx},
	}

	for _, tc := range tests {
		tt := tc
		t.Run(tt.statusStr, func(t *testing.T) {
			t.Parallel()

			doc := SingleResponseDoc(ResponseResult{
				StatusCode: tt.statusCode,
				Status:     tt.statusStr,
				Error:      tt.err,
			})

			var foundKV *view.KV

			for _, node := range doc.Nodes {
				if kv, ok := node.(view.KV); ok && kv.Key == "StatusCode" {
					foundKV = &kv
					break
				}
			}

			require.NotNil(t, foundKV)
			assert.Equal(t, tt.expectedTone, foundKV.Tone)
		})
	}
}
