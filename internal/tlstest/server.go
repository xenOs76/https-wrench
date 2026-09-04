package tlstest

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"time"

	"github.com/pires/go-proxyproto"
)

const proxyProtoReadHeaderTimeout = 10 * time.Second

// defaultCurvePreferences matches the Go 1.27 TLS hybrids plus classical fallbacks
// used by certinfo and requests production TLS configs.
var defaultCurvePreferences = []tls.CurveID{
	tls.X25519MLKEM768,
	tls.SecP256r1MLKEM768,
	tls.SecP384r1MLKEM1024,
	tls.X25519,
	tls.CurveP256,
	tls.CurveP384,
	tls.CurveP521,
}

// ServerConfig configures NewServer.
type ServerConfig struct {
	// ListenHost binds the listener to this host (ephemeral port). Empty uses httptest's default.
	ListenHost string
	// ProxyprotoEnabled wraps the listener with a PROXY protocol v2 reader.
	ProxyprotoEnabled bool
	// TLSCipherSuites, when non-empty, must be TLS 1.0–1.2 cipher suite IDs.
	// tls.Config.CipherSuites stays nil by default. Callers that pin suites
	// should also set TLSMaxVersion to tls.VersionTLS12.
	TLSCipherSuites []uint16
	// TLSCurvePreferences override the Go 1.27 hybrid defaults when non-empty.
	TLSCurvePreferences []tls.CurveID
	// TLSMaxVersion overrides TLS 1.3 when non-zero.
	TLSMaxVersion uint16
	// ServerCertFile is the PEM certificate path loaded for the TLS listener.
	ServerCertFile string
	// ServerKeyFile is the PEM private key path loaded for the TLS listener.
	ServerKeyFile string
}

// NewServer starts an httptest TLS server configured by cfg.
// CipherSuites stays nil by default (Go's TLS 1.3 AEADs plus default TLS 1.2
// suites). CurvePreferences default to the Go 1.27 PQ hybrids plus classical
// fallbacks, and MaxVersion to TLS 1.3. Non-empty cfg.TLSCipherSuites must be
// TLS 1.0–1.2 suite IDs; cfg.TLSCurvePreferences and a non-zero
// cfg.TLSMaxVersion override those defaults. Optional cfg.ListenHost and
// cfg.ProxyprotoEnabled replace the listener. The caller must Close the
// returned server.
func NewServer(cfg ServerConfig) (*httptest.Server, error) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "DemoHTTPSServer Handler - client output\n")
		fmt.Fprint(w, "Host requested: ", r.Host, "\n")

		fmt.Println("DemoHTTPSServer Handler - shell output")
	})

	ts := httptest.NewUnstartedServer(handler)
	ts.EnableHTTP2 = true

	if cfg.ListenHost != "" {
		ln, err := net.Listen("tcp", net.JoinHostPort(cfg.ListenHost, "0"))
		if err != nil {
			return nil, fmt.Errorf("error creating listener: %w", err)
		}

		_ = ts.Listener.Close()
		ts.Listener = ln
	}

	if cfg.ProxyprotoEnabled {
		ts.Listener = &proxyproto.Listener{
			Listener:          ts.Listener,
			ReadHeaderTimeout: proxyProtoReadHeaderTimeout,
		}
	}

	cert, err := tls.LoadX509KeyPair(cfg.ServerCertFile, cfg.ServerKeyFile)
	if err != nil {
		_ = ts.Listener.Close()
		return nil, err
	}

	var tlsCipherSuites []uint16

	if len(cfg.TLSCipherSuites) > 0 {
		if err := validateTLS12CipherSuites(cfg.TLSCipherSuites); err != nil {
			_ = ts.Listener.Close()
			return nil, err
		}

		tlsCipherSuites = cfg.TLSCipherSuites
	}

	tlsCurvePreferences := defaultCurvePreferences
	if len(cfg.TLSCurvePreferences) > 0 {
		tlsCurvePreferences = cfg.TLSCurvePreferences
	}

	tlsMaxVersion := uint16(tls.VersionTLS13)
	if cfg.TLSMaxVersion > 0 {
		tlsMaxVersion = cfg.TLSMaxVersion
	}

	ts.TLS = &tls.Config{
		Certificates:     []tls.Certificate{cert},
		CipherSuites:     tlsCipherSuites,
		CurvePreferences: tlsCurvePreferences,
		MaxVersion:       tlsMaxVersion,
	}

	ts.StartTLS()

	return ts, nil
}

func validateTLS12CipherSuites(ids []uint16) error {
	allowed := make(map[uint16]struct{})

	for _, suite := range slices.Concat(tls.CipherSuites(), tls.InsecureCipherSuites()) {
		for _, version := range suite.SupportedVersions {
			if version <= tls.VersionTLS12 {
				allowed[suite.ID] = struct{}{}
				break
			}
		}
	}

	for _, id := range ids {
		if _, ok := allowed[id]; !ok {
			return fmt.Errorf("cipher suite 0x%04x is not a TLS 1.0-1.2 suite", id)
		}
	}

	return nil
}
