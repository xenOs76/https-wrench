package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"slices"
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

func buildHTTPClient(r RequestConfig, serverName string) (*http.Client, string, error) {

	var transportAddress string
	clientTimeout := httpClientTimeout

	if r.ClientTimeout > 0 {
		clientTimeout = r.ClientTimeout
	}

	if len(r.TransportOverrideUrl) > 0 {

		transport := &http.Transport{
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          transportMaxIdleConns,
			IdleConnTimeout:       transportIdleConnTimeout * time.Second,
			TLSHandshakeTimeout:   transportTLSHandshakeTimeout * time.Second,
			ResponseHeaderTimeout: transportResponseHeaderTimeout * time.Second,
			ExpectContinueTimeout: transportExpectContinueTimeout * time.Second,
			TLSClientConfig:       &tls.Config{ServerName: serverName},
		}

		overrideURL, err := url.Parse(r.TransportOverrideUrl)
		if err != nil {
			panic(err)
		}

		transportAddress = overrideURL.Host

		if match, _ := regexp.MatchString("\\:\\d+$", transportAddress); !match {
			transportAddress += ":443"
		}

		dialer := &net.Dialer{
			Timeout:   clientTimeout * time.Second,
			KeepAlive: httpClientKeepalive * time.Second,
		}

		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, transportAddress)
		}

		return &http.Client{
			Transport: transport,
			Timeout:   clientTimeout * time.Second,
		}, transportAddress, nil

	}

	return &http.Client{
		Timeout: clientTimeout * time.Second,
	}, transportAddress, nil
}

func handleRequests(cfg *Config) (map[string][]ResponseData, error) {

	respDataMap := make(map[string][]ResponseData)
	clientMethod := httpClientDefaultMethod

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

				req, err := http.NewRequest(clientMethod, reqUrl, requestBodyReader)
				if err != nil {
					return nil, fmt.Errorf("failed to create request: %w", err)
				}

				if len(r.UserAgent) > 0 {
					httpUserAgent = r.UserAgent
				}
				req.Header.Add("User-Agent", httpUserAgent)

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
