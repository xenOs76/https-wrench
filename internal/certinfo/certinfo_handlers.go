/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

package certinfo

import (
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/dustin/go-humanize"
	"github.com/xenos76/https-wrench/internal/style"
)

// defaultCurvePreferences lists Go 1.27 TLS hybrids plus classical fallbacks.
// Explicit CurvePreferences keeps PQ on when GODEBUG=tlsmlkem=0 / tlssecpmlkem=0.
var defaultCurvePreferences = []tls.CurveID{
	tls.X25519MLKEM768,
	tls.SecP256r1MLKEM768,
	tls.SecP384r1MLKEM1024,
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
}

// PrintData prints all collected certificate and key information (local files and remote endpoints)
// to the provided writer in a human-readable format.
//
//nolint:revive
func (c *Config) PrintData(ctx context.Context, w io.Writer) error {
	ks := style.ItemKey.PaddingBottom(0).PaddingTop(1).PaddingLeft(1)
	sl := style.CertKeyP4.Bold(true)
	sv := style.CertValue.Bold(false)

	fmt.Fprintln(w)
	fmt.Fprintln(w, style.LgSprintf(style.Cmd, "Certinfo"))
	fmt.Fprintln(w)

	c.printPrivateKey(w, ks, sl, sv)

	if err := c.printLocalCerts(w, ks, sl, sv); err != nil {
		return err
	}

	if err := c.printRemoteCerts(w, ks, sl, sv); err != nil {
		return err
	}

	if c.TLSInfoRequested {
		_ = c.ProbeTLSInfo(ctx)
		c.printTLSInfo(w, ks, sl, sv)
	}

	return c.printCACerts(w, ks, sl, sv)
}

// printPrivateKey prints the loaded private key information if available.
func (c *Config) printPrivateKey(w io.Writer, ks, sl, sv lipgloss.Style) {
	if c.PrivKey != nil {
		fmt.Fprintln(w, style.LgSprintf(ks, "PrivateKey"))
		fmt.Fprintln(w, style.LgSprintf(
			sl.PaddingTop(1),
			"PrivateKey file: %v",
			sv.Render(c.PrivKeyFilePath),
		))
		style.PrintKeyInfoStyle(w, c.PrivKey)
	}
}

// printLocalCerts prints the information for certificates loaded from a local bundle file.
func (c *Config) printLocalCerts(w io.Writer, ks, sl, sv lipgloss.Style) error {
	if len(c.CertsBundle) > 0 {
		fmt.Fprintln(w, style.LgSprintf(ks, "Certificates"))

		fmt.Fprintln(w, style.LgSprintf(
			sl.PaddingTop(1),
			"Certificate bundle file: %v",
			sv.Render(c.CertsBundleFilePath),
		))

		if c.PrivKey != nil {
			certMatch, err := certMatchPrivateKey(c.CertsBundle[0], c.PrivKey)
			if err != nil {
				return fmt.Errorf(
					"unable to check if private key matches local certificate: %w",
					err,
				)
			}

			fmt.Fprintln(w, style.LgSprintf(
				sl,
				"PrivateKey match: %v",
				style.BoolStyle(certMatch),
			))
		}

		CertsToTables(w, c.CertsBundle)
	}

	return nil
}

// printRemoteCerts prints the information for certificates retrieved from a remote TLS endpoint.
func (c *Config) printRemoteCerts(w io.Writer, ks, sl, sv lipgloss.Style) error {
	if len(c.TLSEndpointCerts) > 0 {
		endpoint := sv.Render(c.TLSEndpointHost + ":" + c.TLSEndpointPort)

		fmt.Fprintln(w, style.LgSprintf(ks, "TLSEndpoint Certificates"))
		fmt.Fprintln(w, style.LgSprintf(
			sl.PaddingTop(1),
			"Endpoint: %v",
			endpoint,
		))

		if c.TLSServerName != emptyString {
			fmt.Fprintln(w, style.LgSprintf(
				sl,
				"ServerName: %v",
				sv.Render(c.TLSServerName),
			))
		}

		if c.PrivKey != nil {
			tlsMatch, err := certMatchPrivateKey(c.TLSEndpointCerts[0], c.PrivKey)
			if err != nil {
				return fmt.Errorf(
					"unable to check if private key matches remote TLS Endpoint certificate: %w",
					err,
				)
			}

			fmt.Fprintln(w, style.LgSprintf(
				sl,
				"PrivateKey match: %v",
				style.BoolStyle(tlsMatch),
			))
		}

		CertsToTables(w, c.TLSEndpointCerts)
	}

	return nil
}

// printCACerts prints the information for CA certificates loaded from a file.
func (c *Config) printCACerts(w io.Writer, ks, sl, sv lipgloss.Style) error {
	if len(c.CACertsFilePath) > 0 {
		fmt.Fprintln(w, style.LgSprintf(ks, "CA Certificates"))
		fmt.Fprintln(
			w,
			style.LgSprintf(
				sl.PaddingTop(1).PaddingBottom(1),
				"CA Certificates file: %v",
				sv.Render(c.CACertsFilePath),
			),
		)

		rootCerts, err := GetCertsFromBundle(
			c.CACertsFilePath,
			inputReader,
		)
		if err != nil {
			return fmt.Errorf("unable to read Root certificates: %w", err)
		}

		CertsToTables(w, rootCerts)
	}

	return nil
}

// dialTLS connects to serverAddr and completes a TLS handshake using ctx for cancellation.
func dialTLS(ctx context.Context, serverAddr string, tlsConfig *tls.Config) (*tls.Conn, error) {
	dialer := &net.Dialer{Timeout: TLSTimeout}

	rawConn, err := dialer.DialContext(ctx, "tcp", serverAddr)
	if err != nil {
		return nil, err
	}

	conn := tls.Client(rawConn, tlsConfig)

	if err = conn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()

		return nil, err
	}

	return conn, nil
}

// GetRemoteCerts establishes a TLS connection to the configured endpoint and retrieves
// the peer certificate chain. It also performs certificate verification unless TLSInsecure is true.
func (c *Config) GetRemoteCerts(ctx context.Context) error {
	tlsConfig := &tls.Config{
		RootCAs:            c.CACertsPool,
		InsecureSkipVerify: c.TLSInsecure,
		CurvePreferences:   slices.Clone(defaultCurvePreferences),
	}

	verifyName := c.TLSServerName
	switch {
	case c.TLSServerName != emptyString:
		tlsConfig.ServerName = c.TLSServerName
	case c.TLSEndpointHost != emptyString:
		tlsConfig.ServerName = c.TLSEndpointHost
		verifyName = c.TLSEndpointHost
	default:
	}

	serverAddr := net.JoinHostPort(c.TLSEndpointHost, c.TLSEndpointPort)

	conn, err := dialTLS(ctx, serverAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS handshake failed: %w", err)
	}
	defer conn.Close()

	cs := conn.ConnectionState()
	c.TLSEndpointCerts = cs.PeerCertificates
	c.NegotiatedProtocol = tlsVersionToString(cs.Version)
	c.NegotiatedCipher = tls.CipherSuiteName(cs.CipherSuite)
	c.NegotiatedCurveID = cs.CurveID.String()

	// do not verify server certificates if TLSInsecure
	if c.TLSInsecure {
		return nil
	}

	opts := x509.VerifyOptions{
		DNSName:       verifyName,
		Roots:         c.CACertsPool,
		Intermediates: x509.NewCertPool(),
	}

	for _, ic := range cs.PeerCertificates[1:] {
		opts.Intermediates.AddCert(ic)
	}

	if _, err := c.TLSEndpointCerts[0].Verify(opts); err != nil {
		return fmt.Errorf("certificate verify: %w", err)
	}

	return nil
}

// CertsToTables formats and prints a list of x509 certificates as tables to the provided writer.
// An optional filter slice of maps can be provided to filter printed output by certificate index and field names.
//
//nolint:gocognit,funlen,gocyclo,wsl,revive,cyclop
func CertsToTables(w io.Writer, certs []*x509.Certificate, filter ...[]map[int][]string) {
	sl := style.CertKeyP4.Render
	sv := style.CertValue.Render
	svn := style.CertValueNotice.Render

	var f []map[int][]string
	if len(filter) > 0 {
		f = filter[0]
	}

	// If a filter is provided, map it for fast lookup by certificate index
	requestedCerts := make(map[int][]string)

	hasFilter := len(f) > 0
	if hasFilter {
		for _, m := range f {
			for k, fields := range m {
				requestedCerts[k] = fields
			}
		}
	}

	for i := range certs {
		var fields []string

		if hasFilter {
			var ok bool

			fields, ok = requestedCerts[i]
			if !ok {
				// Certificate index not in filter list, skip displaying it
				continue
			}
		}

		header := style.LgSprintf(
			style.CertKeyP4.Bold(true),
			"Certificate %d",
			i,
		)
		cert := certs[i]

		// Helper to check if a specific field is requested (case-insensitive)
		hasField := func(fieldName string) bool {
			if !hasFilter || len(fields) == 0 {
				return true // Print all fields if no filter is active or if field list is empty for this cert
			}

			for _, field := range fields {
				if strings.EqualFold(field, fieldName) {
					return true
				}
			}

			return false
		}

		t := table.New().Border(style.LGDefBorder).Headers(header)
		hasRows := false
		addRow := func(k, v string) {
			t.Row(k, v)

			hasRows = true
		}

		if hasField("Subject") {
			subject := cert.Subject.String()
			addRow(sl("Subject"), sv(subject))
		}

		if hasField("DNSNames") {
			dnsNames := strings.Join(cert.DNSNames, "\n")
			addRow(sl("DNSNames"), sv(dnsNames))
		}

		if hasField("IPAddresses") {
			var ipStrs []string

			for _, ip := range cert.IPAddresses {
				ipStrs = append(ipStrs, ip.String())
			}

			ips := strings.Join(ipStrs, "\n")
			addRow(sl("IPAddresses"), sv(ips))
		}

		if hasField("Issuer") {
			issuer := cert.Issuer.String()
			addRow(sl("Issuer"), sv(issuer))
		}

		if hasField("NotBefore") {
			notBefore := cert.NotBefore
			addRow(sl("NotBefore"), sv(notBefore.String()))
		}

		// Calculate expiration colors if needed
		var expStyle func(...string) string

		getExpStyle := func() func(...string) string {
			if expStyle != nil {
				return expStyle
			}

			daysUntilExpiration := time.Until(cert.NotAfter).Hours() / 24

			expStyle = sv
			if (0 < daysUntilExpiration) && (daysUntilExpiration < CertExpWarnDays) {
				expStyle = style.Warn.Render
			}

			if daysUntilExpiration <= 0 {
				expStyle = style.Crit.Render
			}

			return expStyle
		}

		if hasField("NotAfter") {
			notAfter := cert.NotAfter
			addRow(sl("NotAfter"), getExpStyle()(notAfter.String()))
		}

		if hasField("Expiration") {
			expiration := humanize.Time(cert.NotAfter)
			addRow(sl("Expiration"), getExpStyle()(expiration))
		}

		if hasField("IsCA") {
			isCA := strconv.FormatBool(cert.IsCA)
			addRow(sl("IsCA"), svn(isCA))
		}

		if hasField("AuthorityKeyId") {
			authorityKeyID := hex.EncodeToString(cert.AuthorityKeyId)
			addRow(sl("AuthorityKeyId"), svn(authorityKeyID))
		}

		if hasField("SubjectKeyId") {
			subjectKeyID := hex.EncodeToString(cert.SubjectKeyId)
			addRow(sl("SubjectKeyId"), svn(subjectKeyID))
		}

		if hasField("PublicKeyAlgorithm") {
			publicKeyAlgorithm := cert.PublicKeyAlgorithm.String()
			addRow(sl("PublicKeyAlgorithm"), sv(publicKeyAlgorithm))
		}

		if hasField("SignatureAlgorithm") {
			signatureAlgorithm := cert.SignatureAlgorithm.String()
			addRow(sl("SignatureAlgorithm"), sv(signatureAlgorithm))
		}

		if hasField("SerialNumber") {
			serialNumber := cert.SerialNumber.String()
			addRow(sl("SerialNumber"), sv(serialNumber))
		}

		if hasField("Fingerprint SHA-256") || hasField("Fingerprint") {
			fingerprintSha256 := fmt.Sprintf("%x", sha256.Sum256(cert.Raw))
			addRow(sl("Fingerprint SHA-256"), sv(fingerprintSha256))
		}

		if hasRows {
			fmt.Fprintln(w, t.Render())
		}

		t.ClearRows()
	}
}

// tlsVersionToString converts TLS version uint16 to standard string representation.
func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"

	case tls.VersionTLS11:
		return "TLS 1.1"

	case tls.VersionTLS12:
		return "TLS 1.2"

	case tls.VersionTLS13:
		return "TLS 1.3"

	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// probeProtocol tests whether the TLS endpoint supports a specific TLS protocol version.
func (c *Config) probeProtocol(ctx context.Context, version uint16) bool {
	tlsConfig := &tls.Config{
		MinVersion:         version,
		MaxVersion:         version,
		InsecureSkipVerify: true,
	}

	if c.TLSServerName != emptyString {
		tlsConfig.ServerName = c.TLSServerName
	} else if c.TLSEndpointHost != emptyString {
		tlsConfig.ServerName = c.TLSEndpointHost
	}

	serverAddr := net.JoinHostPort(c.TLSEndpointHost, c.TLSEndpointPort)

	conn, err := dialTLS(ctx, serverAddr, tlsConfig)
	if err == nil {
		_ = conn.Close()

		return true
	}

	return false
}

// probeCipher tests whether a specific TLS 1.0-1.2 cipher suite is supported.
func (c *Config) probeCipher(ctx context.Context, suite *tls.CipherSuite) (bool, string) {
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS10,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       []uint16{suite.ID},
		InsecureSkipVerify: true,
	}

	if c.TLSServerName != emptyString {
		tlsConfig.ServerName = c.TLSServerName
	} else if c.TLSEndpointHost != emptyString {
		tlsConfig.ServerName = c.TLSEndpointHost
	}

	serverAddr := net.JoinHostPort(c.TLSEndpointHost, c.TLSEndpointPort)

	conn, err := dialTLS(ctx, serverAddr, tlsConfig)
	if err == nil {
		state := conn.ConnectionState()

		_ = conn.Close()

		return true, tlsVersionToString(state.Version)
	}

	return false, ""
}

// ProbeTLSInfo concurrently scans the endpoint for supported TLS versions and cipher suites.
func (c *Config) ProbeTLSInfo(ctx context.Context) error {
	if c.TLSEndpoint == emptyString {
		return nil
	}

	c.ProbedProtocols = make(map[string]bool)

	// 1. Probe protocols
	versions := []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12, tls.VersionTLS13}

	for _, v := range versions {
		if err := ctx.Err(); err != nil {
			return err
		}

		supported := c.probeProtocol(ctx, v)

		c.ProbedProtocols[tlsVersionToString(v)] = supported
	}

	// 2. Probe ciphers concurrently
	suites := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)

	c.ProbedCiphers = c.probeCiphersConcurrently(ctx, suites)

	return nil
}

// probeCiphersConcurrently manages the worker pool to concurrently scan cipher suites.
//
//nolint:gocognit,revive,wsl
func (c *Config) probeCiphersConcurrently(ctx context.Context, suites []*tls.CipherSuite) []ProbedCipher {
	type job struct {
		suite *tls.CipherSuite
	}

	type result struct {
		probed ProbedCipher
	}

	numJobs := len(suites)
	jobs := make(chan job, numJobs)
	results := make(chan result, numJobs)

	// Start 10 concurrent workers
	numWorkers := 10
	if numWorkers > numJobs {
		numWorkers = numJobs
	}

	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for j := range jobs {
				if err := ctx.Err(); err != nil {
					return
				}

				suite := j.suite
				isTLS13 := false

				for _, v := range suite.SupportedVersions {
					if v == tls.VersionTLS13 {
						isTLS13 = true

						break
					}
				}

				var (
					supported bool
					protoName string
				)

				if isTLS13 {
					supported = c.ProbedProtocols["TLS 1.3"]
					protoName = "TLS 1.3"
				} else {
					ok, name := c.probeCipher(ctx, suite)

					supported = ok
					protoName = name
				}

				results <- result{
					probed: ProbedCipher{
						ID:        suite.ID,
						Name:      suite.Name,
						Protocol:  protoName,
						Insecure:  suite.Insecure,
						Supported: supported,
					},
				}
			}
		}()
	}

	// Queue up all jobs
	for _, s := range suites {
		jobs <- job{suite: s}
	}

	close(jobs)

	// Wait for workers to finish
	wg.Wait()

	close(results)

	// Collect results
	var list []ProbedCipher

	for r := range results {
		list = append(list, r.probed)
	}

	// Sort ciphers by Name for stable output
	slices.SortFunc(list, func(a, b ProbedCipher) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return list
}

// printTLSInfo formats and prints the scanned TLS info tables.
func (c *Config) printTLSInfo(w io.Writer, ks, _, _ lipgloss.Style) {
	if !c.TLSInfoRequested {
		return
	}

	// 1. Render Negotiated Connection details
	fmt.Fprintln(w, style.LgSprintf(ks, "Negotiated TLS Connection"))

	t1 := table.New().Border(style.LGDefBorder)
	t1.Row(style.CertKeyP4.Render("Protocol Version"), style.CertValue.Render(c.NegotiatedProtocol))
	t1.Row(style.CertKeyP4.Render("Cipher Suite"), style.CertValue.Render(c.NegotiatedCipher))
	t1.Row(style.CertKeyP4.Render("Key Exchange"), style.CertValue.Render(c.NegotiatedCurveID))
	fmt.Fprintln(w, t1.Render())

	// 2. Render Supported Protocol Versions Scan
	fmt.Fprintln(w, style.LgSprintf(ks, "Protocol Support Scan"))

	t2 := table.New().Border(style.LGDefBorder)
	protoOrder := []string{"TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"}

	for _, protoName := range protoOrder {
		supported := c.ProbedProtocols[protoName]
		statusStr, statusStyle := "No", style.BoolFalse.Render

		if supported {
			statusStr, statusStyle = "Yes", style.BoolTrue.Render
		}

		t2.Row(style.CertKeyP4.Render(protoName), statusStyle(statusStr))
	}

	fmt.Fprintln(w, t2.Render())

	// 3. Render Probed Cipher Suites
	fmt.Fprintln(w, style.LgSprintf(ks, "Cipher Suite Scan"))

	slRender := style.CertKeyP4.Bold(true).Render
	slNoPadRender := style.CertKeyP4.PaddingLeft(0).Bold(true).Render
	t3 := table.New().Border(style.LGDefBorder).Headers(
		slRender("Cipher Suite Name"),
		slNoPadRender("Protocol"),
		slNoPadRender("Status"),
		slNoPadRender("Security"),
	)

	var hasSupported bool

	for _, pc := range c.ProbedCiphers {
		if pc.Supported {
			hasSupported = true
			secStr, secStyle := "Secure", style.BoolTrue.Render

			if pc.Insecure {
				secStr, secStyle = "Insecure", style.Warn.Render
			}

			t3.Row(
				style.CertKeyP4.Render(pc.Name),
				style.CertValue.Render(pc.Protocol),
				style.BoolTrue.Render("Yes"),
				secStyle(secStr),
			)
		}
	}

	if !hasSupported {
		t3.Row(style.CertKeyP4.Render("No supported cipher suites found"), "", "", "")
	}

	fmt.Fprintln(w, t3.Render())
}
