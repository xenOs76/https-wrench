package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
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
	Name                  string          `mapstructure:"name"`
	UserAgent             string          `mapstructure:"userAgent"`
	PrintResponseBody     bool            `mapstructure:"printResponseBody"`
	PrintResponseHeaders  bool            `mapstructure:"printResponseHeaders"`
	TransportOverrideUrl  string          `mapstructure:"transportOverrideUrl"`
	RequestHeaders        []RequestHeader `mapstructure:"requestHeaders"`
	ResponseHeadersFilter []string        `mapstructure:"responseHeadersFilter"`
	Hosts                 []Host          `mapstructure:"hosts"`
}

type ResponseData struct {
	RequestName           string
	TransportAddress      string
	Url                   string
	PrintResponseBody     bool
	PrintResponseHeaders  bool
	ResponseHeadersFilter []string
	ResponseBody          string
	Response              *http.Response
	Error                 error
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
		log.Fatalf("Unable to parse Uri %s", u)
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
