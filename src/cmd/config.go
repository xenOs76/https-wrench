package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"
)

type (
	Uri            string
	ResponseHeader string
)

type Host struct {
	Name    string `mapstructure:"name"`
	UriList []Uri  `mapstructure:"uriList"`
}

type RequestHeader struct {
	Key   string `mapstructure:"key"`
	Value string `mapstructure:"value"`
}

type RequestConfig struct {
	Name                      string          `mapstructure:"name"`
	ClientTimeout             time.Duration   `mapstructure:"clientTimeout"`
	UserAgent                 string          `mapstructure:"userAgent"`
	TransportOverrideUrl      string          `mapstructure:"transportOverrideUrl"`
	RequestDebug              bool            `mapstructure:"requestDebug"`
	RequestHeaders            []RequestHeader `mapstructure:"requestHeaders"`
	RequestMethod             string          `mapstructure:"requestMethod"`
	RequestBody               string          `mapstructure:"requestBody"`
	ResponseDebug             bool            `mapstructure:"responseDebug"`
	ResponseHeadersFilter     []string        `mapstructure:"responseHeadersFilter"`
	PrintResponseBody         bool            `mapstructure:"printResponseBody"`
	PrintResponseHeaders      bool            `mapstructure:"printResponseHeaders"`
	PrintResponseCertificates bool            `mapstructure:"printResponseCertificates"`
	Hosts                     []Host          `mapstructure:"hosts"`
}

type ResponseData struct {
	RequestName               string
	TransportAddress          string
	Url                       string
	PrintResponseBody         bool
	PrintResponseHeaders      bool
	PrintResponseCertificates bool
	ResponseHeadersFilter     []string
	ResponseBody              string
	Response                  *http.Response
	Error                     error
}

type Config struct {
	Debug    bool            `mapstructure:"debug"`
	Verbose  bool            `mapstructure:"verbose"`
	Requests []RequestConfig `mapstructure:"requests"`
}

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

func (rd *ResponseData) ImportResponseBody() {
	body, err := io.ReadAll(rd.Response.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return
	}

	if contentTypeHeaders, ok := rd.Response.Header["Content-Type"]; ok {
		jsonRegexp, _ := regexp.Compile("(?i)application/json")

		for i := range contentTypeHeaders {

			if matched := jsonRegexp.MatchString(contentTypeHeaders[i]); matched {

				var obj map[string]any
				err := json.Unmarshal([]byte(body), &obj)
				if err != nil {
					fmt.Println("Error unmarshalling Json response body:", err)
				}

				s := prettyPrintJson(obj, 0)
				rd.ResponseBody = s
				return
			}
		}
	}
	rd.ResponseBody = string(body)
}

func (rd ResponseData) PrintResponseData() {
	fmt.Println(lgSprintf(styleItemKey,
		"- Url: %s",
		styleUrl.Render(rd.Url)),
	)

	fmt.Print(lgSprintf(styleItemKeyP3, "StatusCode: "))

	if rd.Error != nil {
		fmt.Println(lgSprintf(styleStatusError, "000"))
		fmt.Println(lgSprintf(
			styleItemKeyP3,
			"Error: %s",
			styleError.Render(rd.Error.Error())),
		)
		fmt.Println()
	} else {
		fmt.Println(lgSprintf(styleStatus, "%v", statusCodeParse(rd.Response.StatusCode)))

		if rd.PrintResponseCertificates {
			RenderTlsData(rd.Response)
		}

		if rd.PrintResponseHeaders {
			headersStr := parseResponseHeaders(rd.Response.Header, rd.ResponseHeadersFilter)

			fmt.Println(lgSprintf(styleItemKeyP3, "Headers: "))
			fmt.Println(
				lgSprintf(
					styleHeaders,
					"%s",
					headersStr,
				),
			)
		}

		if rd.PrintResponseBody {
			fmt.Println(lgSprintf(styleItemKeyP3, "Body:"))
			fmt.Println(rd.ResponseBody)
		}
		fmt.Println()
	}
}

func RenderTlsData(r *http.Response) {

	tls := r.TLS

	fmt.Println(lgSprintf(styleItemKeyP3, "TLS:"))

	if tls == nil {
		fmt.Println(lgSprintf(styleCertKeyP4, "%s", styleError.Render("No TLS connection state available")))
		return
	}

	fmt.Println(lgSprintf(styleCertKeyP4, "Version: %s", styleCertValue.Render(tlsVersionName(tls.Version))))

	fmt.Println(lgSprintf(styleCertKeyP4, "CipherSuite: %v", styleCertValue.Render(cipherSuiteName(tls.CipherSuite))))

	for i, cert := range tls.PeerCertificates {

		fmt.Println(lgSprintf(styleCertKeyP4.Bold(true), "Certificate %v:", i))
		fmt.Println(lgSprintf(styleCertKeyP5, "Subject: %s", styleCertValue.Render(cert.Subject.String())))

		if len(cert.DNSNames) > 0 {
			dnsnames := "[ "
			for _, name := range cert.DNSNames {
				dnsnames += name + " "
			}
			dnsnames += "]"

			fmt.Println(lgSprintf(styleCertKeyP5, "DNS Names: %v", styleCertValue.Render(dnsnames)))
		}

		fmt.Println(lgSprintf(styleCertKeyP5, "Issuer: %s", styleCertValue.Render(cert.Issuer.String())))
		fmt.Println(lgSprintf(styleCertKeyP5, "Valid From: %s", styleCertValue.Render(cert.NotBefore.Format(time.RFC1123))))
		fmt.Println(lgSprintf(styleCertKeyP5, "Valid To: %s", styleCertValue.Render(cert.NotAfter.Format(time.RFC1123))))

	}

}
