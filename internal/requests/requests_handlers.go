package requests

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss/table"
	proxyproto "github.com/pires/go-proxyproto"
	"github.com/xenos76/https-wrench/internal/certinfo"
	"github.com/xenos76/https-wrench/internal/style"
)

// String returns the response header as a string.
func (h ResponseHeader) String() string {
	return string(h)
}

// Parse validates that the URI starts with a slash.
func (u URI) Parse() bool {
	// URIs must start with a slash as in /uri
	matched, err := regexp.Match(`^\/.*`, []byte(u))
	if err != nil {
		return false
	}

	return matched
}

// TLSVersionName returns a human-readable name for the given TLS version constant.
func TLSVersionName(v uint16) string {
	switch v {
	case tls.VersionSSL30:
		return "SSL 3.0"
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown (0x%x)", v)
	}
}

// cipherSuiteName returns a human-readable name for the given TLS cipher suite ID.
func cipherSuiteName(id uint16) string {
	cs := tls.CipherSuiteName(id)
	if strings.Contains(cs, "0x") {
		return fmt.Sprintf("Unknown (0x%x)", id)
	}

	return cs
}

// filterResponseHeaders filters and formats HTTP headers for display based on the provided filter list.
func filterResponseHeaders(headers http.Header, filter []string) string {
	var outputStr string

	var outputMap map[string][]string

	sl := style.HeadKeyP3.Render
	sv := style.HeadValue.Italic(true).Render
	t := style.LGTable
	headersFiltered := make(map[string][]string)

	if len(filter) > 0 {
		for k, v := range headers {
			if present := slices.Contains(filter, k); present {
				headersFiltered[k] = v
			}
		}

		outputMap = headersFiltered
	} else {
		outputMap = headers
	}

	for k, v := range outputMap {
		values := strings.Join(v, ", ")
		t.Row(sl(k), sv(values))
	}

	outputStr = t.Render()
	t.ClearRows()

	return outputStr
}

// getUrlsFromHost generates a list of full URLs for a host based on its Name and URIList.
func getUrlsFromHost(h Host) ([]string, error) {
	var list []string

	if len(h.URIList) == 0 {
		s := httpClientDefaultScheme + "://" + h.Name
		list = append(list, s)

		return list, nil
	}

	for _, uri := range h.URIList {
		if parsed := uri.Parse(); !parsed {
			return nil, &InvalidURIError{URI: string(uri), Host: h.Name}
		}

		s := fmt.Sprintf("%s://%s%s", httpClientDefaultScheme, h.Name, uri)
		list = append(list, s)
	}

	return list, nil
}

// transportAddressFromURLString extracts and normalizes the host:port address from a transport URL.
func transportAddressFromURLString(transportURL string) (string, error) {
	var addr string

	if transportURL == emptyString {
		return emptyString, &EmptyArgError{Name: "transportURL"}
	}

	// Add HTTPS scheme if missing from transportURL
	if match, _ := regexp.MatchString("^https://", transportURL); !match {
		transportURL = "https://" + transportURL
	}

	overrideURL, err := url.Parse(transportURL)
	if err != nil {
		return "", err
	}

	addr = overrideURL.Host

	// Add default HTTPS port if a port is missing from transportURL
	if match, _ := regexp.MatchString("\\:\\d+$", addr); !match {
		addr += ":443"
	}

	return addr, nil
}

// proxyProtoHeaderFromRequest generates a PROXY protocol v2 header for the given request and server name.
func proxyProtoHeaderFromRequest(r RequestConfig, serverName string) (proxyproto.Header, error) {
	if !r.EnableProxyProtocolV2 {
		return proxyproto.Header{}, ErrProxyProtoDisabled
	}

	headerSrcIP := net.ParseIP(proxyProtoDefaultSrcIPv4)
	headerSrcPort := proxyProtoDefaultSrcPort
	headerTransportProtocol := proxyproto.TCPv4

	reqURL, err := url.Parse(serverName)
	if err != nil {
		return proxyproto.Header{}, err
	}

	if len(r.TransportOverrideURL) > 0 {
		reqURL, err = url.Parse(r.TransportOverrideURL)
		if err != nil {
			return proxyproto.Header{}, fmt.Errorf(
				"failed to parse transport override url: %w",
				err)
		}
	}

	reqHostname := reqURL.Hostname()
	reqPort := reqURL.Port()

	if reqPort == emptyString {
		reqPort = "443"
	}

	headerDstPort, err := strconv.Atoi(reqPort)
	if err != nil {
		return proxyproto.Header{}, fmt.Errorf("failed to parse transport override port: %w", err)
	}

	headerDstIPs, err := net.LookupIP(reqHostname)
	if err != nil {
		return proxyproto.Header{}, fmt.Errorf(
			"failed to resolve transport override hostname's IPs': %w",
			err)
	}

	headerDstIP := net.ParseIP(headerDstIPs[0].String())
	if headerDstIP.To4() == nil {
		headerTransportProtocol = proxyproto.TCPv6
		headerSrcIP = net.ParseIP(proxyProtoDefaultSrcIPv6)
	}

	header := proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: headerTransportProtocol,
		SourceAddr:        &net.TCPAddr{IP: headerSrcIP, Port: headerSrcPort},
		DestinationAddr:   &net.TCPAddr{IP: headerDstIP, Port: headerDstPort},
	}

	return header, nil
}

// HandleRequests iterates through all configured requests and processes them, returning a map of response data.
func HandleRequests(
	ctx context.Context,
	w io.Writer,
	cfg *RequestsMetaConfig,
) (map[string][]ResponseData, error) {
	responseDataMap := make(map[string][]ResponseData)

	cfg.PrintCmd(w)

	for _, r := range cfg.Requests {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		responseDataList, err := processHTTPRequestsByHost(
			ctx,
			w,
			r,
			cfg.CACertsPool,
			cfg.RequestVerbose,
		)
		if err != nil {
			return nil, err
		}

		responseDataMap[r.Name] = responseDataList
	}

	return responseDataMap, nil
}

// ImportResponseBody reads the response body, handles regex matching, and applies syntax highlighting if applicable.
func (rd *ResponseData) ImportResponseBody() {
	if len(rd.ResponseBody) > 0 {
		return
	}

	body, err := io.ReadAll(rd.Response.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)

		return
	}

	// Early evaluation of regexp match against raw body bytes.
	// It will fail if evaluated against a syntax highlighted body.
	if rd.Request.ResponseBodyMatchRegexp != "" {
		re, err := regexp.Compile(rd.Request.ResponseBodyMatchRegexp)
		if err != nil {
			fmt.Print(fmt.Errorf("unable to compile responseBodyMatchRegexp: %w", err))
		} else if re.Match(body) {
			rd.ResponseBodyRegexpMatched = true
		}
	}

	contentType := rd.Response.Header.Get("Content-Type")

	for _, item := range contentTypeMatchingItems {
		rex := regexp.MustCompile(item.regexp)

		code := string(body)

		if item.language == "json" {
			var prettyJSON bytes.Buffer

			err := json.Indent(&prettyJSON, body, "", "  ")
			if err != nil {
				_, _ = prettyJSON.Write(body)
			}

			code = prettyJSON.String()
		}

		if matched := rex.MatchString(contentType); matched {
			rd.ResponseBody = style.CodeSyntaxHighlight(item.language, code)
			return
		}
	}

	rd.ResponseBody = string(body)
}

// PrintResponseData prints the collected response data (status, headers, body) if verbose mode is enabled.
//
//nolint:revive
func (rd ResponseData) PrintResponseData(w io.Writer, isVerbose bool) {
	if !isVerbose {
		return
	}

	fmt.Fprintln(w, style.LgSprintf(style.ItemKey,
		"- Url: %s",
		style.URL.Render(rd.URL)),
	)

	fmt.Fprint(w, style.LgSprintf(style.ItemKeyP3, "StatusCode: "))

	if rd.Error != nil {
		fmt.Fprintln(w, style.LgSprintf(style.StatusError, "0"))
		fmt.Fprintln(w, style.LgSprintf(
			style.ItemKeyP3,
			"Error: %s",
			style.Error.Render(rd.Error.Error()),
		))
		fmt.Fprintln(w)

		return
	}

	fmt.Fprintln(w, style.LgSprintf(style.Status,
		"%v",
		style.StatusCodeParse(rd.Response.StatusCode)))

	if rd.Request.PrintResponseCertificates {
		RenderTLSData(w, rd.Response, rd.Request.ResponseCertificatesFilter)
	}

	if rd.Request.PrintResponseHeaders {
		headersStr := filterResponseHeaders(
			rd.Response.Header,
			rd.Request.ResponseHeadersFilter)

		fmt.Fprintln(w, style.LgSprintf(style.ItemKeyP3, "Headers: "))
		fmt.Fprintln(w, headersStr)
	}

	if rd.Request.ResponseBodyMatchRegexp != "" {
		fmt.Fprint(w, style.LgSprintf(style.ItemKeyP3, "BodyRegexpMatch: "))
		fmt.Fprintln(w, rd.ResponseBodyRegexpMatched)
	}

	if rd.Request.PrintResponseBody {
		fmt.Fprintln(w, style.LgSprintf(style.ItemKeyP3, "Body:"))
		fmt.Fprintln(w, rd.ResponseBody)
	}

	fmt.Fprintln(w)
}

// RenderTLSData prints TLS version, cipher suite, and peer certificates for an HTTP response.
// An optional filter can be provided to only print specific certificate indices and fields.
func RenderTLSData(w io.Writer, r *http.Response, filter ...[]map[int][]string) {
	respTLS := r.TLS
	sl := style.CertKeyP4.Render
	sv := style.CertValue.Render

	fmt.Fprintln(w, style.LgSprintf(style.ItemKeyP3, "TLS:"))

	if respTLS == nil {
		fmt.Fprintln(
			w,
			style.LgSprintf(style.CertKeyP4,
				"%s",
				style.Error.Render("No TLS connection state available"),
			),
		)

		return
	}

	t := table.New().Border(style.LGDefBorder)
	t.Row(
		sl("Version"),
		sv(TLSVersionName(respTLS.Version)),
	)
	t.Row(
		sl("CipherSuite"),
		sv(cipherSuiteName(respTLS.CipherSuite)),
	)
	t.Row(
		sl("Key Exchange"),
		sv(respTLS.CurveID.String()),
	)
	fmt.Fprintln(w, t.Render())
	t.ClearRows()

	var f []map[int][]string
	if len(filter) > 0 {
		f = filter[0]
	}

	certinfo.CertsToTables(w, respTLS.PeerCertificates, f)
}
