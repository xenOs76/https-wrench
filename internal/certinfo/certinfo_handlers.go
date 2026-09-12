/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

package certinfo

import (
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"slices"
	"sync"

	"github.com/xenos76/https-wrench/internal/view"
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

// PrintData writes collected certificate and key information to w via the console view sink.
// Call ProbeTLSInfo before PrintData when TLSInfoRequested is set; PrintData does not probe
// or re-read certificate files.
func (c *Config) PrintData(_ context.Context, w io.Writer) error {
	return c.PrintDataWithOptions(w, view.Options{ForceColor: true})
}

// PrintDataWithOptions writes the certinfo report using the given view options.
func (c *Config) PrintDataWithOptions(w io.Writer, opts view.Options) error {
	result, err := c.BuildResult()
	if err != nil {
		return err
	}

	return view.Render(w, BuildDoc(result), opts)
}

// CertsToTables formats and prints certificates as tables (adapter over CertsDoc + view.Render).
func CertsToTables(w io.Writer, certs []*x509.Certificate, filter ...[]map[int][]string) {
	_ = view.Render(w, CertsDoc(certs, filter...), view.Options{ForceColor: true})
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
