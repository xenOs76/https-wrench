package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
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

func boolStyle(b bool) string {

	if b {
		return lgSprintf(styleBoolTrue, "true")
	}
	return lgSprintf(styleBoolFalse, "false")
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
	sl := styleCertKeyP4.Render
	sv := styleCertValue.Render

	fmt.Println(lgSprintf(styleItemKeyP3, "TLS:"))

	if tls == nil {
		fmt.Println(lgSprintf(styleCertKeyP4, "%s", styleError.Render("No TLS connection state available")))
		return
	}

	t := table.New().Border(lipgloss.HiddenBorder())
	t.Row(sl("Version"), sv(tlsVersionName(tls.Version)))
	t.Row(sl("CipherSuite"), sv(cipherSuiteName(tls.CipherSuite)))
	fmt.Println(t.Render())
	t.ClearRows()

	CertsToTables(tls.PeerCertificates)

}

func CertsToTables(certs []*x509.Certificate) {

	sl := styleCertKeyP4.Render
	sv := styleCertValue.Render

	for i := range certs {

		header := lgSprintf(styleCertKeyP4.Bold(true), "Certificate %d", i)

		t := table.New().Border(lipgloss.HiddenBorder()).Headers(header)
		t.Row(sl("Subject"), sv(certs[i].Subject.String()))
		t.Row(sl("DNSNames"), sv("[ "+strings.Join(certs[i].DNSNames, ", ")+" ]"))
		t.Row(sl("Issuer"), sv(certs[i].Issuer.String()))
		t.Row(sl("NotBefore"), sv(certs[i].NotBefore.String()))
		t.Row(sl("NotAfter"), sv(certs[i].NotAfter.String()))
		t.Row(sl("IsCA"), sv(strconv.FormatBool(certs[i].IsCA)))
		t.Row(sl("PublicKeyAlgorithm"), sv(certs[i].PublicKeyAlgorithm.String()))
		t.Row(sl("SignatureAlgorithm"), sv(certs[i].SignatureAlgorithm.String()))
		t.Row(sl("SerialNumber"), sv(certs[i].SerialNumber.String()))
		fmt.Println(t.Render())
		t.ClearRows()
	}

}

func printKeyInfoStyle(privKey crypto.PrivateKey) {

	sl := styleCertKeyP4.Render
	sv := styleCertValue.Render

	t := table.New().Border(lipgloss.HiddenBorder())

	switch k := privKey.(type) {
	case *rsa.PrivateKey:

		t.Row(sl("Type"), sv("RSA"))
		size := fmt.Sprintf("%d bits", k.N.BitLen())
		t.Row(sl("Key Size"), sv(size))

	case *ecdsa.PrivateKey:

		t.Row(sl("Type"), sv("ECDSA"))
		curve := fmt.Sprintf("%s", k.Curve.Params().Name)
		t.Row(sl("Curve"), sv(curve))

	case ed25519.PrivateKey:
		t.Row(sl("Type"), sv("Ed25519"))
		size := fmt.Sprintf("%d bytes", len(k))
		t.Row(sl("Key Size"), sv(size))

	default:
		t.Row("Unknown key type")
	}

	fmt.Println(t.Render())
	t.ClearRows()
}
