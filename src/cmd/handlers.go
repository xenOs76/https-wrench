package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"
)

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
