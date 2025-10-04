/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

package cmd

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	// "github.com/gookit/goutil/dump"
)

func (c *CertinfoConfig) PrintData() {
	ks := styleItemKey.PaddingBottom(0).PaddingTop(1).PaddingLeft(1)
	sl := styleCertKeyP4.Bold(true)
	sv := styleCertValue.Bold(false)

	fmt.Println()
	fmt.Println(lgSprintf(styleCmd, "Certinfo"))
	fmt.Println()

	if c.PrivKey != nil {
		fmt.Println(lgSprintf(ks, "PrivateKey"))
		fmt.Println(lgSprintf(sl.PaddingTop(1), "PrivateKey file: %v", sv.Render(keyFilePath)))
		printKeyInfoStyle(c.PrivKey)
	}

	if len(c.CertsBundle) > 0 {
		fmt.Println(lgSprintf(ks, "Certificates"))

		fmt.Println(lgSprintf(sl.PaddingTop(1), "Certificates file: %v", sv.Render(certBundlePath)))

		if c.PrivKey != nil {
			certMatch, err := certMatchPrivateKey(c.CertsBundle[0], c.PrivKey)
			if err != nil {
				fmt.Print(err)
			}
			fmt.Println(lgSprintf(sl, "PrivateKey match: %v", boolStyle(certMatch)))
		}

		CertsToTables(c.CertsBundle)
	}

	if len(c.TLSEndpointCerts) > 0 {
		endpoint := sv.Render(c.TLSEndpointHost + ":" + c.TLSEndpointPort)

		fmt.Println(lgSprintf(ks, "TLSEndpoint Certificates"))
		fmt.Println(lgSprintf(sl.PaddingTop(1), "Endpoint: %v", endpoint))

		if c.TLSServerName != "" {
			fmt.Println(lgSprintf(sl, "ServerName: %v", sv.Render(c.TLSServerName)))
		}

		if c.PrivKey != nil {
			tlsMatch, err := certMatchPrivateKey(c.TLSEndpointCerts[0], c.PrivKey)
			if err != nil {
				fmt.Print(err)
			}
			fmt.Println(lgSprintf(sl, "PrivateKey match: %v", boolStyle(tlsMatch)))
		}

		CertsToTables(c.TLSEndpointCerts)
	}

	if len(caBundlePath) > 0 {
		fmt.Println(lgSprintf(ks, "CA Certificates"))
		fmt.Println(lgSprintf(sl.PaddingTop(1).PaddingBottom(1), "CA Certificates file: %v", sv.Render(caBundlePath)))
		rootCerts, err := getCertsFromBundle(caBundlePath)
		if err != nil {
			fmt.Printf("unable for read Root certificates from %s: %s", caBundlePath, err)
			return
		}
		CertsToTables(rootCerts)
	}
}

func (c *CertinfoConfig) GetRemoteCerts() {
	tlsConfig := &tls.Config{RootCAs: c.CACerts, InsecureSkipVerify: c.TLSInsecure}

	if c.TLSServerName != "" {
		tlsConfig.ServerName = c.TLSServerName
	}

	serverAddr := net.JoinHostPort(c.TLSEndpointHost, c.TLSEndpointPort)

	dialer := &net.Dialer{
		Timeout: certinfoTLSTimeout,
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
		Roots:         c.CACerts,
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
