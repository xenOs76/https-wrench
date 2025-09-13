package cmd

import (
	"encoding/json"
	"fmt"
	"github.com/charmbracelet/lipgloss"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

func lgSprintf(style lipgloss.Style, pattern string, a ...any) string {
	str := fmt.Sprintf(pattern, a...)
	out := style.Render(str)
	return out
}

func prettyPrintJson(v any, indent int) string {
	ind := strings.Repeat("  ", indent)
	switch val := v.(type) {
	case map[string]any:
		var b strings.Builder
		b.WriteString(styleBracket.Render("{") + "\n")
		for k, v2 := range val {
			b.WriteString(ind + "  ")
			b.WriteString(styleKey.Render(fmt.Sprintf(`"%s"`, k)))
			b.WriteString(styleBracket.Render(": ") + prettyPrintJson(v2, indent+1))
			b.WriteString("\n")
		}
		b.WriteString(ind + styleBracket.Render("}"))
		return b.String()

	case []any:
		var b strings.Builder
		b.WriteString(styleBracket.Render("[") + "\n")
		for _, item := range val {
			b.WriteString(ind + "  " + prettyPrintJson(item, indent+1) + "\n")
		}
		b.WriteString(ind + styleBracket.Render("]"))
		return b.String()

	case string:
		return styleString.Render(fmt.Sprintf(`"%s"`, val))
	case float64:
		return styleNumber.Render(fmt.Sprintf("%v", val))
	case bool:
		return styleBool.Render(fmt.Sprintf("%v", val))
	case nil:
		return styleNull.Render("null")
	default:
		return fmt.Sprintf("%v", val)
	}
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

func (rd *ResponseData) ImportResponseBody() {

	if len(rd.ResponseBody) > 0 {
		return
	}

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

		if rd.Request.PrintResponseCertificates {
			RenderTlsData(rd.Response)
		}

		if rd.Request.PrintResponseHeaders {
			headersStr := parseResponseHeaders(rd.Response.Header, rd.Request.ResponseHeadersFilter)

			fmt.Println(lgSprintf(styleItemKeyP3, "Headers: "))
			fmt.Println(
				lgSprintf(
					styleHeaders,
					"%s",
					headersStr,
				),
			)
		}

		if rd.Request.ResponseBodyMatchRegexp != "" {
			fmt.Print(lgSprintf(styleItemKeyP3, "BodyRegexpMatch: "))
			fmt.Println(rd.ResponseBodyRegexpMatched)
		}

		if rd.Request.PrintResponseBody {
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
