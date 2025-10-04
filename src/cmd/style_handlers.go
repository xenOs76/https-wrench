package cmd

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/formatters"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/dustin/go-humanize"
)

func lgSprintf(style lipgloss.Style, pattern string, a ...any) string {
	str := fmt.Sprintf(pattern, a...)
	out := style.Render(str)
	return out
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

	htmlRegexp, _ := regexp.Compile("(?i)text/html")
	if matched := htmlRegexp.MatchString(contentType); matched {
		rd.ResponseBody = CodeSyntaxHighlight("html", string(body))
		return
	}

	jsonRegexp, _ := regexp.Compile("(?i)application/json")
	if matched := jsonRegexp.MatchString(contentType); matched {

		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, body, "", "  "); err != nil {
			prettyJSON.WriteString(string(body))
		}
		rd.ResponseBody = CodeSyntaxHighlight("json", prettyJSON.String())
		return
	}

	csvRegexp, _ := regexp.Compile("(?i)text/csv")
	if matched := csvRegexp.MatchString(contentType); matched {
		rd.ResponseBody = CodeSyntaxHighlight("csv", string(body))
		return
	}

	yamlRegexp, _ := regexp.Compile("(?i)(application|text)/(yaml|x-yaml)")
	if matched := yamlRegexp.MatchString(contentType); matched {
		rd.ResponseBody = CodeSyntaxHighlight("yaml", string(body))
		return
	}

	xmlRegexp, _ := regexp.Compile("(?i)(application|text)/xml")
	if matched := xmlRegexp.MatchString(contentType); matched {
		rd.ResponseBody = CodeSyntaxHighlight("xml", string(body))
		return
	}

	jsRegexp, _ := regexp.Compile("(?i)text/javascript")
	if matched := jsRegexp.MatchString(contentType); matched {
		rd.ResponseBody = CodeSyntaxHighlight("javascript", string(body))
		return
	}

	cssRegexp, _ := regexp.Compile("(?i)text/css")
	if matched := cssRegexp.MatchString(contentType); matched {
		rd.ResponseBody = CodeSyntaxHighlight("css", string(body))
		return
	}
	rd.ResponseBody = string(body)
}

func (rd ResponseData) PrintResponseData() {
	fmt.Println(lgSprintf(styleItemKey,
		"- Url: %s",
		styleURL.Render(rd.URL)),
	)

	fmt.Print(lgSprintf(styleItemKeyP3, "StatusCode: "))

	if rd.Error != nil {
		fmt.Println(lgSprintf(styleStatusError, "0"))
		fmt.Println(lgSprintf(
			styleItemKeyP3,
			"Error: %s",
			styleError.Render(rd.Error.Error())),
		)
		fmt.Println()
	} else {
		fmt.Println(lgSprintf(styleStatus, "%v", statusCodeParse(rd.Response.StatusCode)))

		if rd.Request.PrintResponseCertificates {
			RenderTLSData(rd.Response)
		}

		if rd.Request.PrintResponseHeaders {
			headersStr := parseResponseHeaders(rd.Response.Header, rd.Request.ResponseHeadersFilter)

			fmt.Println(lgSprintf(styleItemKeyP3, "Headers: "))
			fmt.Println(headersStr)
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

func RenderTLSData(r *http.Response) {
	tls := r.TLS
	sl := styleCertKeyP4.Render
	sv := styleCertValue.Render

	fmt.Println(lgSprintf(styleItemKeyP3, "TLS:"))

	if tls == nil {
		fmt.Println(lgSprintf(styleCertKeyP4, "%s", styleError.Render("No TLS connection state available")))
		return
	}

	t := table.New().Border(lgDefBorder)
	t.Row(sl("Version"), sv(tlsVersionName(tls.Version)))
	t.Row(sl("CipherSuite"), sv(cipherSuiteName(tls.CipherSuite)))
	fmt.Println(t.Render())
	t.ClearRows()

	CertsToTables(tls.PeerCertificates)
}

func CertsToTables(certs []*x509.Certificate) {
	sl := styleCertKeyP4.Render
	sv := styleCertValue.Render
	svn := styleCertValueNotice.Render

	for i := range certs {
		header := lgSprintf(styleCertKeyP4.Bold(true), "Certificate %d", i)
		cert := certs[i]

		subject := cert.Subject.String()
		dnsNames := "[" + strings.Join(cert.DNSNames, ", ") + "]"
		issuer := cert.Issuer.String()

		notBefore := cert.NotBefore
		notAfter := cert.NotAfter
		expiration := humanize.Time(notAfter)
		daysUntilExpiration := time.Until(notAfter).Hours() / 24

		expStyle := sv
		if (0 < daysUntilExpiration) && (daysUntilExpiration < certinfoCertExpWarnDays) {
			expStyle = styleWarn.Render
		}
		if daysUntilExpiration <= 0 {
			expStyle = styleCrit.Render
		}

		isCA := strconv.FormatBool(cert.IsCA)
		publicKeyAlgorithm := cert.PublicKeyAlgorithm.String()
		authorityKeyID := fmt.Sprintf("%x", cert.AuthorityKeyId)
		subjectKeyID := fmt.Sprintf("%x", cert.SubjectKeyId)
		signatureAlgorithm := cert.SignatureAlgorithm.String()
		fingerprintSha256 := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
		fingerprintSha1 := fmt.Sprintf("%x", sha1.Sum(cert.Raw))
		serialNumber := cert.SerialNumber.String()

		t := table.New().Border(lgDefBorder).Headers(header)
		t.Row(sl("Subject"), sv(subject))
		t.Row(sl("DNSNames"), sv(dnsNames))
		t.Row(sl("Issuer"), sv(issuer))
		t.Row(sl("NotBefore"), sv(notBefore.String()))
		t.Row(sl("NotAfter"), expStyle(notAfter.String()))
		t.Row(sl("Expiration"), expStyle(expiration))
		t.Row(sl("IsCA"), svn(isCA))
		t.Row(sl("AuthorityKeyId"), svn(authorityKeyID))
		t.Row(sl("SubjectKeyId"), svn(subjectKeyID))
		t.Row(sl("PublicKeyAlgorithm"), sv(publicKeyAlgorithm))
		t.Row(sl("SignatureAlgorithm"), sv(signatureAlgorithm))
		t.Row(sl("Fingerprint SHA-256"), sv(fingerprintSha256))
		t.Row(sl("Fingerprint SHA-1"), sv(fingerprintSha1))
		t.Row(sl("SerialNumber"), sv(serialNumber))
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
		curve := k.Curve.Params().Name
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

func CodeSyntaxHighlight(lang, code string) string {
	st := styles.Get(chromaDefStyle)
	if st == nil {
		st = styles.Fallback
	}

	fmttr := formatters.TTY16m
	if fmttr == nil {
		fmttr = formatters.Fallback
	}

	lexer := lexers.Get(lang)
	if lexer == nil {
		lexer = lexers.Analyse(code)
	}
	if lexer == nil {
		lexer = lexers.Fallback
	}
	lexer = chroma.Coalesce(lexer)

	iter, err := lexer.Tokenise(nil, code)
	if err != nil {
		return code
	}

	var buf bytes.Buffer
	if err := fmttr.Format(&buf, st, iter); err != nil {
		return code
	}
	out := buf.String()
	if !strings.HasSuffix(out, "\n") {
		out += "\n"
	}
	return out
}
