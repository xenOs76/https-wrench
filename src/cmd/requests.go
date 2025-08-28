/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/
package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
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

	"github.com/gookit/goutil/dump"
	"github.com/spf13/cobra"
)

var httpUserAgent string = "https-wrench-request"
var httpClientDefaultMethod = "GET"
var httpClientDefaultRequestBody []byte
var httpClientTimeout time.Duration = 30
var httpClientKeepalive time.Duration = 30

var transportMaxIdleConns int = 100
var transportIdleConnTimeout time.Duration = 30
var transportTLSHandshakeTimeout time.Duration = 30
var transportResponseHeaderTimeout time.Duration = 30
var transportExpectContinueTimeout time.Duration = 1

var requestsCmd = &cobra.Command{
	Use:   "requests",
	Short: "Make HTTPS requests",
	Long:  `Make HTTPS requests defined in YAML`,

	Run: func(cmd *cobra.Command, args []string) {
		cfg, err := LoadConfig()
		if err != nil {
			log.Fatal(err)
		}

		if cfg.Debug {
			dump.Print(cfg)
		}

		_, err = handleRequests(cfg)
		if err != nil {
			log.Fatal(err)
		}
	},
}

func init() {
	rootCmd.AddCommand(requestsCmd)

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// requestsCmd.PersistentFlags().String("foo", "", "A help for foo")
	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// requestsCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
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

func statusCodeParse(sc int) string {
	var status string
	statusString := strconv.Itoa(sc)

	switch {
	case sc >= 200 && sc < 300:
		status = styleStatus2xx.Render(statusString)
	case sc >= 300 && sc < 400:
		status = styleStatus3xx.Render(statusString)
	case sc >= 400 && sc < 500:
		status = styleStatus4xx.Render(statusString)
	case sc >= 500:
		status = styleStatus5xx.Render(statusString)
	default:
		status = styleStatus.Render(statusString)
	}

	return status
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
	clientTimeout := httpClientTimeout * time.Second

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

		if overrideURL.Scheme == "https" {
			transport.TLSClientConfig = &tls.Config{
				ServerName: serverName,
			}
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
