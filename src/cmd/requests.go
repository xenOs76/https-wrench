/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/
package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"time"

	"github.com/gookit/goutil/dump"
	"github.com/spf13/cobra"
)

var httpUserAgent string = "https-wrench-request"

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

		respDataMap := make(map[string][]ResponseData)

		for _, reqCfg := range cfg.Requests {

			respDataList, err := handleRequests(reqCfg)
			if err != nil {
				log.Fatal(err)
			}
			respDataMap[reqCfg.Name] = respDataList
		}

		if cfg.Verbose {
			for reqName, respDataList := range respDataMap {

				fmt.Print(lgSprintf(styleTitleKey, "Request:"))
				fmt.Println(lgSprintf(styleTitle, "%s", reqName))

				if respDataList[0].TransportAddress != "" {
					fmt.Print(lgSprintf(styleItemKey, "Via:"))
					fmt.Println(lgSprintf(styleVia, "https://%s ", respDataList[0].TransportAddress))
				}
				fmt.Println()

				for i := range respDataList {

					respData := respDataList[i]

					fmt.Println(lgSprintf(styleItemKey,
						"- Url: %s",
						styleUrl.Render(respData.Url)),
					)

					fmt.Print(lgSprintf(styleItemKeyP3, "StatusCode: "))

					if respData.Error != nil {
						fmt.Println(lgSprintf(styleStatusError, "000"))
						fmt.Println(lgSprintf(
							styleItemKeyP3,
							"Error: %s",
							styleError.Render(respData.Error.Error())),
						)
						fmt.Println()
						break
					}

					fmt.Println(lgSprintf(styleStatus, "%v", statusCodeParse(respData.Response.StatusCode)))

					if respData.PrintResponseHeaders {
						headersStr := parseResponseHeaders(respData.Response.Header, respData.ResponseHeadersFilter)

						fmt.Println(lgSprintf(styleItemKeyP3, "Headers: "))
						fmt.Println(
							lgSprintf(
								styleHeaders,
								"%s",
								headersStr,
							),
						)
					}

					if respData.PrintResponseBody {
						fmt.Println(lgSprintf(styleItemKeyP3, "Body:"))
						fmt.Println(respData.ResponseBody)
					}
					fmt.Println()
				}
			}
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

	if len(r.TransportOverrideUrl) > 0 {

		transport := &http.Transport{
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          100,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
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
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
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
			Timeout:   60 * time.Second,
		}, transportAddress, nil

	}

	return &http.Client{
		Timeout: 30 * time.Second,
	}, transportAddress, nil
}

func handleRequests(r RequestConfig) ([]ResponseData, error) {

	var respDataList []ResponseData

	for _, host := range r.Hosts {

		client, transportAddress, err := buildHTTPClient(r, host.Name)
		if err != nil {
			return nil, fmt.Errorf("failed to build HTTP client: %w", err)
		}

		urlList := getUrlsFromHost(host)

		for _, reqUrl := range urlList {

			req, err := http.NewRequest("GET", reqUrl, nil)
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
				PrintResponseBody:     r.PrintResponseBody,
				PrintResponseHeaders:  r.PrintResponseHeaders,
				ResponseHeadersFilter: r.ResponseHeadersFilter,
				TransportAddress:      transportAddress,
				Url:                   reqUrl,
			}

			resp, err := client.Do(req)
			if err != nil {
				rd.Error = err
				respDataList = append(respDataList, rd)
				break
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					fmt.Print(fmt.Errorf("unable to close response Body: %w", err))
				}
			}()

			rd.Response = resp

			if rd.PrintResponseBody {
				rd.ImportResponseBody()
			}
			respDataList = append(respDataList, rd)
		}
	}

	return respDataList, nil
}
