/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

package certinfo

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss/table"
	"github.com/dustin/go-humanize"
	"github.com/xenos76/https-wrench/internal/style"
)

func (c *CertinfoConfig) PrintData() {
	ks := style.ItemKey.PaddingBottom(0).PaddingTop(1).PaddingLeft(1)
	sl := style.CertKeyP4.Bold(true)
	sv := style.CertValue.Bold(false)

	fmt.Println()
	fmt.Println(style.LgSprintf(style.Cmd, "Certinfo"))
	fmt.Println()

	if c.PrivKey != nil {
		fmt.Println(style.LgSprintf(ks, "PrivateKey"))
		fmt.Println(style.LgSprintf(sl.PaddingTop(1), "PrivateKey file: %v", sv.Render(c.PrivKeyFilePath)))
		style.PrintKeyInfoStyle(c.PrivKey)
	}

	if len(c.CertsBundle) > 0 {
		fmt.Println(style.LgSprintf(ks, "Certificates"))

		fmt.Println(style.LgSprintf(sl.PaddingTop(1), "Certificates file: %v", sv.Render(c.CertsBundleFilePath)))

		if c.PrivKey != nil {
			certMatch, err := certMatchPrivateKey(c.CertsBundle[0], c.PrivKey)
			if err != nil {
				fmt.Print(err)
			}

			fmt.Println(style.LgSprintf(sl, "PrivateKey match: %v", style.BoolStyle(certMatch)))
		}

		CertsToTables(c.CertsBundle)
	}

	if len(c.TLSEndpointCerts) > 0 {
		endpoint := sv.Render(c.TLSEndpointHost + ":" + c.TLSEndpointPort)

		fmt.Println(style.LgSprintf(ks, "TLSEndpoint Certificates"))
		fmt.Println(style.LgSprintf(sl.PaddingTop(1), "Endpoint: %v", endpoint))

		if c.TLSServerName != "" {
			fmt.Println(style.LgSprintf(sl, "ServerName: %v", sv.Render(c.TLSServerName)))
		}

		if c.PrivKey != nil {
			tlsMatch, err := certMatchPrivateKey(c.TLSEndpointCerts[0], c.PrivKey)
			if err != nil {
				fmt.Print(err)
			}

			fmt.Println(style.LgSprintf(sl, "PrivateKey match: %v", style.BoolStyle(tlsMatch)))
		}

		CertsToTables(c.TLSEndpointCerts)
	}

	if len(c.CACertsFilePath) > 0 {
		fmt.Println(style.LgSprintf(ks, "CA Certificates"))
		fmt.Println(
			style.LgSprintf(
				sl.PaddingTop(1).PaddingBottom(1),
				"CA Certificates file: %v",
				sv.Render(c.CACertsFilePath),
			),
		)

		rootCerts, err := GetCertsFromBundle(c.CACertsFilePath)
		if err != nil {
			fmt.Printf("unable for read Root certificates from %s: %s", c.CACertsFilePath, err)

			return
		}

		CertsToTables(rootCerts)
	}
}

// TODO: return an error on fails
func (c *CertinfoConfig) GetRemoteCerts() {
	tlsConfig := &tls.Config{RootCAs: c.CACertsPool, InsecureSkipVerify: c.TLSInsecure}

	if c.TLSServerName != "" {
		tlsConfig.ServerName = c.TLSServerName
	}

	serverAddr := net.JoinHostPort(c.TLSEndpointHost, c.TLSEndpointPort)

	dialer := &net.Dialer{
		Timeout: TLSTimeout,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", serverAddr, tlsConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "TLS handshake failed: %v\n", err)

		return
	}
	defer conn.Close()

	cs := conn.ConnectionState()
	c.TLSEndpointCerts = cs.PeerCertificates

	opts := x509.VerifyOptions{
		DNSName:       c.TLSServerName,
		Roots:         c.CACertsPool,
		Intermediates: x509.NewCertPool(),
	}

	for _, ic := range cs.PeerCertificates[1:] {
		opts.Intermediates.AddCert(ic)
	}

	if _, err := c.TLSEndpointCerts[0].Verify(opts); err != nil {
		fmt.Println(err)
	} else {
		c.TLSEndpointCertsValid = true
	}
}

func CertsToTables(certs []*x509.Certificate) {
	sl := style.CertKeyP4.Render
	sv := style.CertValue.Render
	svn := style.CertValueNotice.Render

	for i := range certs {
		header := style.LgSprintf(style.CertKeyP4.Bold(true), "Certificate %d", i)
		cert := certs[i]

		subject := cert.Subject.String()
		dnsNames := "[" + strings.Join(cert.DNSNames, ", ") + "]"
		issuer := cert.Issuer.String()

		notBefore := cert.NotBefore
		notAfter := cert.NotAfter
		expiration := humanize.Time(notAfter)
		daysUntilExpiration := time.Until(notAfter).Hours() / 24

		expStyle := sv
		if (0 < daysUntilExpiration) && (daysUntilExpiration < CertExpWarnDays) {
			expStyle = style.Warn.Render
		}

		if daysUntilExpiration <= 0 {
			expStyle = style.Crit.Render
		}

		isCA := strconv.FormatBool(cert.IsCA)
		publicKeyAlgorithm := cert.PublicKeyAlgorithm.String()
		authorityKeyID := hex.EncodeToString(cert.AuthorityKeyId)
		subjectKeyID := hex.EncodeToString(cert.SubjectKeyId)
		signatureAlgorithm := cert.SignatureAlgorithm.String()
		fingerprintSha256 := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
		serialNumber := cert.SerialNumber.String()

		t := table.New().Border(style.LGDefBorder).Headers(header)
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
		t.Row(sl("SerialNumber"), sv(serialNumber))
		t.Row(sl("Fingerprint SHA-256"), sv(fingerprintSha256))
		fmt.Println(t.Render())
		t.ClearRows()
	}
}
