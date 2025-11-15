package requests

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
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

func (h ResponseHeader) String() string {
	return string(h)
}

func (u URI) Parse() bool {
	matched, err := regexp.Match(`^\/.*`, []byte(u))
	if err != nil {
		return false
	}

	return matched
}

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

func cipherSuiteName(id uint16) string {
	cs := tls.CipherSuiteName(id)
	if cs == "" {
		return fmt.Sprintf("Unknown (0x%x)", id)
	}

	return cs
}

func parseResponseHeaders(headers http.Header, filter []string) string {
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

func getUrlsFromHost(h Host) []string {
	var list []string

	if len(h.URIList) == 0 {
		s := httpClientDefaultScheme + "://" + h.Name
		list = append(list, s)

		return list
	}

	for _, uri := range h.URIList {
		if parsed := uri.Parse(); !parsed {
			fmt.Printf("Invalid uri %s for host %s", uri, h.Name)

			break
		}

		s := fmt.Sprintf("%s://%s%s", httpClientDefaultScheme, h.Name, uri)
		list = append(list, s)
	}

	return list
}

func transportAddressFromRequest(r RequestConfig) (string, error) {
	addr, err := transportAddressFromURLString(r.TransportOverrideURL)
	if err != nil {
		return emptyString, err
	}

	return addr, nil
}

func transportAddressFromURLString(transportURL string) (string, error) {
	var addr string

	overrideURL, err := url.Parse(transportURL)
	if err != nil {
		return "", err
	}

	addr = overrideURL.Host

	if match, _ := regexp.MatchString("\\:\\d+$", addr); !match {
		addr += ":443"
	}

	return addr, nil
}

func proxyProtoHeaderFromRequest(r RequestConfig, serverName string) (proxyproto.Header, error) {
	if !r.EnableProxyProtocolV2 {
		return proxyproto.Header{}, errors.New("proxy protocol v2 is not enabled for this request")
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

func HandleRequests(cfg *RequestsMetaConfig) (map[string][]ResponseData, error) {
	responseDataMap := make(map[string][]ResponseData)

	cfg.PrintCmd()

	for _, r := range cfg.Requests {
		responseDataList, err := processHTTPRequestsByHost(
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
		}

		if re.Match(body) {
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
				prettyJSON.Write(body)
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

func (rd ResponseData) PrintResponseData(isVerbose bool) {
	if !isVerbose {
		return
	}

	fmt.Println(style.LgSprintf(style.ItemKey,
		"- Url: %s",
		style.URL.Render(rd.URL)),
	)

	fmt.Print(style.LgSprintf(style.ItemKeyP3, "StatusCode: "))

	if rd.Error != nil {
		fmt.Println(style.LgSprintf(style.StatusError, "0"))
		fmt.Println(style.LgSprintf(
			style.ItemKeyP3,
			"Error: %s",
			style.Error.Render(rd.Error.Error())),
		)
		fmt.Println()
	}

	if rd.Error == nil {
		fmt.Println(style.LgSprintf(style.Status,
			"%v",
			style.StatusCodeParse(rd.Response.StatusCode)))

		if rd.Request.PrintResponseCertificates {
			RenderTLSData(rd.Response)
		}

		if rd.Request.PrintResponseHeaders {
			headersStr := parseResponseHeaders(
				rd.Response.Header,
				rd.Request.ResponseHeadersFilter)

			fmt.Println(style.LgSprintf(style.ItemKeyP3, "Headers: "))
			fmt.Println(headersStr)
		}

		if rd.Request.ResponseBodyMatchRegexp != "" {
			fmt.Print(style.LgSprintf(style.ItemKeyP3, "BodyRegexpMatch: "))
			fmt.Println(rd.ResponseBodyRegexpMatched)
		}

		if rd.Request.PrintResponseBody {
			fmt.Println(style.LgSprintf(style.ItemKeyP3, "Body:"))
			fmt.Println(rd.ResponseBody)
		}

		fmt.Println()
	}
}

func RenderTLSData(r *http.Response) {
	respTLS := r.TLS
	sl := style.CertKeyP4.Render
	sv := style.CertValue.Render

	fmt.Println(style.LgSprintf(style.ItemKeyP3, "TLS:"))

	if respTLS == nil {
		fmt.Println(style.LgSprintf(style.CertKeyP4,
			"%s",
			style.Error.Render("No TLS connection state available")))

		return
	}

	t := table.New().Border(style.LGDefBorder)
	t.Row(sl("Version"), sv(TLSVersionName(respTLS.Version)))
	t.Row(sl("CipherSuite"), sv(cipherSuiteName(respTLS.CipherSuite)))
	fmt.Println(t.Render())
	t.ClearRows()

	certinfo.CertsToTables(respTLS.PeerCertificates)
}
