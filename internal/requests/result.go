/*
Copyright © 2026 Zeno Belli xeno@os76.xyz
*/

package requests

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"slices"

	"github.com/xenos76/https-wrench/internal/certinfo"
)

const (
	// ResultSchemaVersion is the JSON export schema version for requests results.
	ResultSchemaVersion = "1"
	resultCommand       = "requests"
)

// Result is the serializable requests report (source of truth for JSON and console Doc).
type Result struct {
	SchemaVersion string          `json:"schemaVersion"`
	Command       string          `json:"command"`
	Requests      []RequestResult `json:"requests"`
}

// RequestResult represents the outcome of a configured RequestConfig.
type RequestResult struct {
	Name                 string           `json:"name"`
	TransportOverrideURL string           `json:"transportOverrideUrl,omitempty"`
	Responses            []ResponseResult `json:"responses"`
}

// ResponseResult holds the results and metadata of a single HTTP response.
type ResponseResult struct {
	URL               string              `json:"url"`
	TransportAddress  string              `json:"transportAddress,omitempty"`
	DurationMs        float64             `json:"durationMs,omitempty"`
	StatusCode        int                 `json:"statusCode"`
	Status            string              `json:"status,omitempty"`
	Error             string              `json:"error,omitempty"`
	Headers           map[string][]string `json:"headers,omitempty"`
	Body              string              `json:"body,omitempty"`
	ContentType       string              `json:"contentType,omitempty"`
	BodyRegexpMatched *bool               `json:"bodyRegexpMatched,omitempty"`
	TransferredBytes  int64               `json:"transferredBytes,omitempty"`
	TLS               *ResponseTLSResult  `json:"tls,omitempty"`
}

// ResponseTLSResult holds negotiated TLS parameters and certificate details.
type ResponseTLSResult struct {
	Version            string              `json:"version,omitempty"`
	CipherSuite        string              `json:"cipherSuite,omitempty"`
	KeyExchange        string              `json:"keyExchange,omitempty"`
	Certificates       []certinfo.CertInfo `json:"certificates,omitempty"`
	CertificatesFilter []map[int][]string  `json:"certificatesFilter,omitempty"`
}

// BuildResult gathers a serializable report from execution response data and configuration.
func BuildResult(responseMap map[string][]ResponseData, cfg *RequestsMetaConfig) (*Result, error) {
	if cfg == nil {
		return nil, errors.New("requests: nil meta config")
	}

	seenNames := make(map[string]struct{}, len(cfg.Requests))
	for _, reqCfg := range cfg.Requests {
		if _, exists := seenNames[reqCfg.Name]; exists {
			return nil, &DuplicateRequestNameError{Name: reqCfg.Name}
		}

		seenNames[reqCfg.Name] = struct{}{}
	}

	res := &Result{
		SchemaVersion: ResultSchemaVersion,
		Command:       resultCommand,
		Requests:      make([]RequestResult, 0, len(cfg.Requests)),
	}

	for _, reqCfg := range cfg.Requests {
		res.Requests = append(res.Requests, buildRequestResult(reqCfg, responseMap[reqCfg.Name]))
	}

	return res, nil
}

func buildRequestResult(reqCfg RequestConfig, rdList []ResponseData) RequestResult {
	reqRes := RequestResult{
		Name:                 reqCfg.Name,
		TransportOverrideURL: reqCfg.TransportOverrideURL,
		Responses:            make([]ResponseResult, 0, len(rdList)),
	}

	for _, rd := range rdList {
		reqRes.Responses = append(reqRes.Responses, buildResponseResult(rd))
	}

	return reqRes
}

func buildResponseResult(rd ResponseData) ResponseResult {
	respRes := ResponseResult{
		URL:              rd.URL,
		TransportAddress: rd.TransportAddress,
		TransferredBytes: rd.TransferredBytes,
	}

	if rd.Duration > 0 {
		respRes.DurationMs = float64(rd.Duration.Microseconds()) / 1000.0
	}

	if rd.Error != nil {
		respRes.Error = rd.Error.Error()
		return respRes
	}

	if rd.Response != nil {
		respRes.StatusCode = rd.Response.StatusCode
		respRes.Status = rd.Response.Status

		if rd.Request.PrintResponseHeaders || len(rd.Request.ResponseHeadersFilter) > 0 {
			respRes.Headers = filterHeadersMap(rd.Response.Header, rd.Request.ResponseHeadersFilter)
		}

		if rd.Request.ResponseBodyMatchRegexp != "" {
			matched := rd.ResponseBodyRegexpMatched
			respRes.BodyRegexpMatched = &matched
		}

		if rd.Request.PrintResponseBody {
			respRes.Body = rd.ResponseBody
			respRes.ContentType = rd.ResponseContentType
		}

		if rd.Request.PrintResponseCertificates && rd.Response.TLS != nil {
			respRes.TLS = BuildResponseTLSResult(rd.Response.TLS, rd.Request.ResponseCertificatesFilter)
		}
	}

	return respRes
}

// BuildResponseTLSResult constructs a ResponseTLSResult from a tls.ConnectionState and optional certificates filter.
func BuildResponseTLSResult(respTLS *tls.ConnectionState, filter []map[int][]string) *ResponseTLSResult {
	if respTLS == nil {
		return nil
	}

	return &ResponseTLSResult{
		Version:            TLSVersionName(respTLS.Version),
		CipherSuite:        cipherSuiteName(respTLS.CipherSuite),
		KeyExchange:        respTLS.CurveID.String(),
		Certificates:       certinfo.CertInfos(respTLS.PeerCertificates),
		CertificatesFilter: filter,
	}
}

// EncodeJSON writes the result as indented JSON with no ANSI escape sequences.
func EncodeJSON(r *Result) ([]byte, error) {
	if r == nil {
		return nil, errors.New("requests: nil result")
	}

	return json.MarshalIndent(r, "", "  ")
}

func filterHeadersMap(headers map[string][]string, filter []string) map[string][]string {
	if len(filter) == 0 {
		out := make(map[string][]string, len(headers))
		for k, v := range headers {
			out[k] = append([]string(nil), v...)
		}

		return out
	}

	out := make(map[string][]string)

	for k, v := range headers {
		if slices.Contains(filter, k) {
			out[k] = append([]string(nil), v...)
		}
	}

	return out
}
