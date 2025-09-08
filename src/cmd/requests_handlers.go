package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	proxyproto "github.com/pires/go-proxyproto"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

func (h ResponseHeader) String() string {
	return string(h)
}

func (u Uri) Parse() bool {
	matched, err := regexp.Match(`^\/.*`, []byte(u))
	if err != nil {
		return false
	}
	return matched
}

func tlsVersionName(v uint16) string {
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

func printCertInfo(cert *x509.Certificate, depth int) {
	prefix := ""
	for i := 0; i < depth; i++ {
		prefix += "  "
	}
	fmt.Printf("%sSubject: %s\n", prefix, cert.Subject)
	fmt.Printf("%sIssuer: %s\n", prefix, cert.Issuer)
	fmt.Printf("%sValid From: %s\n", prefix, cert.NotBefore.Format(time.RFC1123))
	fmt.Printf("%sValid To:   %s\n", prefix, cert.NotAfter.Format(time.RFC1123))
	fmt.Printf("%sDNS Names:  %v\n", prefix, cert.DNSNames)
	// fmt.Printf("%sEmail:      %v\n", prefix, cert.EmailAddresses)
	// fmt.Printf("%sIP Addrs:   %v\n", prefix, cert.IPAddresses)
	fmt.Println()
}

func parseResponseHeaders(headers http.Header, filter []string) string {
	var outputStr string
	var outputMap map[string][]string
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
		outputStr += fmt.Sprintf("%s: %s\n", k, v)
	}
	return outputStr
}

func getUrlsFromHost(h Host) []string {
	var list []string

	if len(h.UriList) == 0 {
		s := fmt.Sprintf("https://%s", h.Name)
		list = append(list, s)
		return list
	}

	for _, uri := range h.UriList {
		if parsed := uri.Parse(); !parsed {
			fmt.Printf("Invalid uri %s for host %s", uri, h)
			break
		}
		s := fmt.Sprintf("https://%s%s", h.Name, uri)
		list = append(list, s)
	}
	return list
}

func transportAddressFromRequest(r RequestConfig) (string, error) {
	var addr string
	overrideURL, err := url.Parse(r.TransportOverrideUrl)
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
		return proxyproto.Header{}, fmt.Errorf("proxy protocol v2 is not enabled for this request")
	}

	headerScrIP := net.ParseIP(proxyProtoDefaultSrcIPv4)
	headerScrPort := proxyProtoDefaultSrcPort
	headerTransportProtocol := proxyproto.TCPv4

	reqUrl, err := url.Parse(serverName)
	if err != nil {
		return proxyproto.Header{}, err
	}

	if len(r.TransportOverrideUrl) > 0 {
		reqUrl, err = url.Parse(r.TransportOverrideUrl)
		if err != nil {
			return proxyproto.Header{}, fmt.Errorf("failed to parse transport override url: %w", err)
		}
	}

	reqHostname := reqUrl.Hostname()
	reqPort := reqUrl.Port()

	if reqPort == "" {
		reqPort = "443"
	}

	headerDstPort, err := strconv.Atoi(reqPort)
	if err != nil {
		return proxyproto.Header{}, fmt.Errorf("failed to parse transport override port: %w", err)
	}

	headerDstIPs, err := net.LookupIP(reqHostname)
	if err != nil {
		return proxyproto.Header{}, fmt.Errorf("failed to resolve transport override hostname's IPs': %w", err)
	}

	headerDstIP := net.ParseIP(headerDstIPs[0].String())
	if headerDstIP.To4() == nil {
		headerTransportProtocol = proxyproto.TCPv6
		headerScrIP = net.ParseIP(proxyProtoDefaultSrcIPv6)
	}

	header := proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: headerTransportProtocol,
		SourceAddr:        &net.TCPAddr{IP: headerScrIP, Port: headerScrPort},
		DestinationAddr:   &net.TCPAddr{IP: headerDstIP, Port: headerDstPort},
	}

	return header, nil
}

func buildHTTPClient(r RequestConfig, serverName string) (*http.Client, string, error) {

	var transportAddress string
	clientTimeout := httpClientTimeout

	if r.ClientTimeout > 0 {
		clientTimeout = r.ClientTimeout
	}

	tlsClientConfig := &tls.Config{
		ServerName: serverName,
	}

	if rootCAs != nil {
		tlsClientConfig = &tls.Config{
			RootCAs: rootCAs,
		}
	}

	if r.Insecure {
		tlsClientConfig = &tls.Config{
			InsecureSkipVerify: true,
		}
	}

	transport := &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          transportMaxIdleConns,
		IdleConnTimeout:       transportIdleConnTimeout * time.Second,
		TLSHandshakeTimeout:   transportTLSHandshakeTimeout * time.Second,
		ResponseHeaderTimeout: transportResponseHeaderTimeout * time.Second,
		ExpectContinueTimeout: transportExpectContinueTimeout * time.Second,
		TLSClientConfig:       tlsClientConfig,
	}

	if len(r.TransportOverrideUrl) > 0 {
		tAddr, err := transportAddressFromRequest(r)
		if err != nil {
			return nil, "", fmt.Errorf("failed to parse transport override url: %w", err)
		}
		transportAddress = tAddr

		dialer := &net.Dialer{
			Timeout:   clientTimeout * time.Second,
			KeepAlive: httpClientKeepalive * time.Second,
		}

		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			conn, err := dialer.DialContext(ctx, network, transportAddress)
			if err != nil {
				return nil, err
			}

			if r.EnableProxyProtocolV2 {

				header := proxyproto.Header{}
				header, err = proxyProtoHeaderFromRequest(r, serverName)
				if err != nil {
					return nil, fmt.Errorf("failed to create proxy header from request: %w", err)
				}

				if r.RequestDebug {
					fmt.Printf("Sending PROXY header: %+v\n", header)
				}

				if _, err := header.WriteTo(conn); err != nil {
					conn.Close()
					return nil, fmt.Errorf("failed to write PROXY header: %w", err)
				}
			}
			return conn, err
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   clientTimeout * time.Second,
	}, transportAddress, nil
}

func handleRequests(cfg *Config) (map[string][]ResponseData, error) {

	respDataMap := make(map[string][]ResponseData)
	clientMethod := httpClientDefaultMethod

	if len(cfg.CaBundle) > 0 {
		caCerts, err := getRootCertsFromString(cfg.CaBundle)
		if err != nil {
			return nil, fmt.Errorf("failed to load CA bundle: %w", err)
		}
		rootCAs = caCerts
	}

	for _, r := range cfg.Requests {

		var respDataList []ResponseData
		requestBodyReader := bytes.NewReader(httpClientDefaultRequestBody)

		if len(r.RequestMethod) > 0 {
			clientMethod = strings.ToUpper(r.RequestMethod)
		}

		if len(r.RequestBody) > 0 {
			requestBodyReader = bytes.NewReader([]byte(r.RequestBody))
		}

		if cfg.Verbose {
			fmt.Print(lgSprintf(styleTitleKey, "Request:"))
			fmt.Println(lgSprintf(styleTitle, "%s", r.Name))

			if r.TransportOverrideUrl != "" {
				fmt.Print(lgSprintf(styleItemKey, "Via:"))
				fmt.Println(lgSprintf(styleVia, "%s", r.TransportOverrideUrl))
			}
		}

		for _, host := range r.Hosts {

			client, transportAddress, err := buildHTTPClient(r, host.Name)
			if err != nil {
				return nil, fmt.Errorf("failed to build HTTP client: %w", err)
			}

			urlList := getUrlsFromHost(host)

			for _, reqUrl := range urlList {

				ua := httpUserAgent
				req, err := http.NewRequest(clientMethod, reqUrl, requestBodyReader)
				if err != nil {
					return nil, fmt.Errorf("failed to create request: %w", err)
				}

				if len(r.UserAgent) > 0 {
					ua = r.UserAgent
				}
				req.Header.Add("User-Agent", ua)

				for _, header := range r.RequestHeaders {
					req.Header.Add(header.Key, header.Value)
				}

				rd := ResponseData{
					PrintResponseBody:         r.PrintResponseBody,
					PrintResponseHeaders:      r.PrintResponseHeaders,
					PrintResponseCertificates: r.PrintResponseCertificates,
					ResponseHeadersFilter:     r.ResponseHeadersFilter,
					TransportAddress:          transportAddress,
					Url:                       reqUrl,
				}

				if r.RequestDebug {
					reqDump, err := httputil.DumpRequestOut(req, true)
					if err != nil {
						log.Fatal(err)
					}
					fmt.Printf("Requesting url: %s\n", reqUrl)
					fmt.Printf("Request dump:\n%s\n", string(reqDump))
				}

				resp, err := client.Do(req)
				if err != nil {
					rd.Error = err
					respDataList = append(respDataList, rd)
					if cfg.Verbose {
						rd.PrintResponseData()
					}
					continue
				}
				defer func() {
					if err := resp.Body.Close(); err != nil {
						fmt.Print(fmt.Errorf("unable to close response Body: %w", err))
					}
				}()

				if r.ResponseDebug {
					respDump, err := httputil.DumpResponse(resp, true)
					if err != nil {
						log.Fatal(err)
					}
					fmt.Printf("Requested url: %s\n", reqUrl)
					fmt.Printf("Response dump:\n%s\n", string(respDump))
					fmt.Println("TLS:")
					fmt.Printf("Version: %v\n", tlsVersionName(resp.TLS.Version))
					fmt.Printf("CipherSuite: %v\n", cipherSuiteName(resp.TLS.CipherSuite))

					for i, cert := range resp.TLS.PeerCertificates {
						fmt.Printf("Certificate %d:\n", i)
						printCertInfo(cert, 1)
					}

					// Optionally show verified chains
					// for i, chain := range resp.TLS.VerifiedChains {
					// 	fmt.Printf("Verified Chain %d:\n", i)
					// 	for j, cert := range chain {
					// 		fmt.Printf(" Cert %d:\n", j)
					// 		printCertInfo(cert, 2)
					// 	}
					// }
				}

				rd.Response = resp

				if rd.PrintResponseBody {
					rd.ImportResponseBody()
				}
				respDataList = append(respDataList, rd)
				respDataMap[rd.RequestName] = respDataList

				if cfg.Verbose {
					rd.PrintResponseData()
				}
			}
		}
	}

	return respDataMap, nil
}
