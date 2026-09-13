/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

package certinfo

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
)

const (
	// ResultSchemaVersion is the JSON export schema version for certinfo results.
	ResultSchemaVersion = "1"
	resultCommand       = "certinfo"
)

// Result is the serializable certinfo report (source of truth for JSON and console Doc).
type Result struct {
	SchemaVersion string          `json:"schemaVersion"`
	Command       string          `json:"command"`
	PrivateKey    *PrivateKeyInfo `json:"privateKey,omitempty"`
	LocalCerts    *CertsSection   `json:"localCerts,omitempty"`
	RemoteCerts   *CertsSection   `json:"remoteCerts,omitempty"`
	CACerts       *CertsSection   `json:"caCerts,omitempty"`
	TLSInfo       *TLSInfoSection `json:"tlsInfo,omitempty"`
}

// PrivateKeyInfo holds plain private-key metadata for sinks.
type PrivateKeyInfo struct {
	FilePath   string            `json:"filePath"`
	Type       string            `json:"type"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// CertsSection groups certificates from one source.
type CertsSection struct {
	FilePath        string     `json:"filePath,omitempty"`
	Endpoint        string     `json:"endpoint,omitempty"`
	ServerName      string     `json:"serverName,omitempty"`
	PrivateKeyMatch *bool      `json:"privateKeyMatch,omitempty"`
	Certificates    []CertInfo `json:"certificates"`
}

// CertInfo is a plain certificate field set (no ANSI).
type CertInfo struct {
	Index              int      `json:"index"`
	Subject            string   `json:"subject,omitempty"`
	DNSNames           []string `json:"dnsNames,omitempty"`
	IPAddresses        []string `json:"ipAddresses,omitempty"`
	Issuer             string   `json:"issuer,omitempty"`
	NotBefore          string   `json:"notBefore,omitempty"`
	NotAfter           string   `json:"notAfter,omitempty"`
	Expiration         string   `json:"expiration,omitempty"`
	DaysUntilExpiry    float64  `json:"daysUntilExpiry"`
	IsCA               bool     `json:"isCA"` //nolint:tagliatelle // conventional CA acronym
	AuthorityKeyID     string   `json:"authorityKeyId,omitempty"`
	SubjectKeyID       string   `json:"subjectKeyId,omitempty"`
	PublicKeyAlgorithm string   `json:"publicKeyAlgorithm,omitempty"`
	SignatureAlgorithm string   `json:"signatureAlgorithm,omitempty"`
	SerialNumber       string   `json:"serialNumber,omitempty"`
	FingerprintSHA256  string   `json:"fingerprintSha256,omitempty"`
}

// TLSInfoSection holds negotiated and probed TLS details.
type TLSInfoSection struct {
	NegotiatedProtocol string          `json:"negotiatedProtocol,omitempty"`
	NegotiatedCipher   string          `json:"negotiatedCipher,omitempty"`
	NegotiatedCurveID  string          `json:"negotiatedCurveId,omitempty"`
	ProbedProtocols    map[string]bool `json:"probedProtocols,omitempty"`
	ProbedCiphers      []ProbedCipher  `json:"probedCiphers,omitempty"`
}

// BuildResult gathers a serializable report from Config. It does not probe TLS or read files.
func (c *Config) BuildResult() (*Result, error) {
	r := &Result{
		SchemaVersion: ResultSchemaVersion,
		Command:       resultCommand,
	}

	if c.PrivKey != nil {
		r.PrivateKey = privateKeyInfo(c.PrivKeyFilePath, c.PrivKey)
	}

	if len(c.CertsBundle) > 0 {
		sec, err := certsSectionFromBundle(c.CertsBundleFilePath, "", "", c.CertsBundle, c.PrivKey)
		if err != nil {
			return nil, fmt.Errorf(
				"unable to check if private key matches local certificate: %w",
				err,
			)
		}

		r.LocalCerts = sec
	}

	if len(c.TLSEndpointCerts) > 0 {
		endpoint := net.JoinHostPort(c.TLSEndpointHost, c.TLSEndpointPort)

		sec, err := certsSectionFromBundle("", endpoint, c.TLSServerName, c.TLSEndpointCerts, c.PrivKey)
		if err != nil {
			return nil, fmt.Errorf(
				"unable to check if private key matches remote TLS Endpoint certificate: %w",
				err,
			)
		}

		r.RemoteCerts = sec
	}

	if len(c.CACertsFilePath) > 0 {
		r.CACerts = &CertsSection{
			FilePath:     c.CACertsFilePath,
			Certificates: CertInfos(c.CACerts),
		}
	}

	if c.TLSInfoRequested {
		r.TLSInfo = &TLSInfoSection{
			NegotiatedProtocol: c.NegotiatedProtocol,
			NegotiatedCipher:   c.NegotiatedCipher,
			NegotiatedCurveID:  c.NegotiatedCurveID,
			ProbedProtocols:    c.ProbedProtocols,
			ProbedCiphers:      c.ProbedCiphers,
		}
	}

	return r, nil
}

// EncodeJSON writes the result as indented JSON with no ANSI.
func EncodeJSON(r *Result) ([]byte, error) {
	if r == nil {
		return nil, errors.New("certinfo: nil result")
	}

	return json.MarshalIndent(r, "", "  ")
}

func certsSectionFromBundle(
	filePath, endpoint, serverName string,
	certs []*x509.Certificate,
	privKey crypto.PrivateKey,
) (*CertsSection, error) {
	sec := &CertsSection{
		FilePath:     filePath,
		Endpoint:     endpoint,
		ServerName:   serverName,
		Certificates: CertInfos(certs),
	}

	if privKey != nil && len(certs) > 0 {
		match, err := certMatchPrivateKey(certs[0], privKey)
		if err != nil {
			return nil, err
		}

		sec.PrivateKeyMatch = &match
	}

	return sec, nil
}

// CertInfos converts a slice of x509.Certificate into serializable CertInfo structs.
func CertInfos(certs []*x509.Certificate) []CertInfo {
	out := make([]CertInfo, 0, len(certs))
	for i, cert := range certs {
		out = append(out, FromX509(i, cert))
	}

	return out
}

// FromX509 builds a plain CertInfo from an x509.Certificate.
func FromX509(index int, cert *x509.Certificate) CertInfo {
	if cert == nil {
		return CertInfo{Index: index}
	}

	ipStrs := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ipStrs = append(ipStrs, ip.String())
	}

	days := time.Until(cert.NotAfter).Hours() / 24

	return CertInfo{
		Index:              index,
		Subject:            cert.Subject.String(),
		DNSNames:           append([]string(nil), cert.DNSNames...),
		IPAddresses:        ipStrs,
		Issuer:             cert.Issuer.String(),
		NotBefore:          cert.NotBefore.String(),
		NotAfter:           cert.NotAfter.String(),
		Expiration:         humanize.Time(cert.NotAfter),
		DaysUntilExpiry:    days,
		IsCA:               cert.IsCA,
		AuthorityKeyID:     hex.EncodeToString(cert.AuthorityKeyId),
		SubjectKeyID:       hex.EncodeToString(cert.SubjectKeyId),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		SerialNumber:       cert.SerialNumber.String(),
		FingerprintSHA256:  fmt.Sprintf("%x", sha256.Sum256(cert.Raw)),
	}
}

func privateKeyInfo(path string, privKey crypto.PrivateKey) *PrivateKeyInfo {
	info := &PrivateKeyInfo{
		FilePath:   path,
		Attributes: map[string]string{},
	}

	switch k := privKey.(type) {
	case *rsa.PrivateKey:
		info.Type = "RSA"
		info.Attributes["Key Size"] = fmt.Sprintf("%d bits", k.N.BitLen())
	case *ecdsa.PrivateKey:
		info.Type = "ECDSA"
		info.Attributes["Curve"] = k.Curve.Params().Name
	case ed25519.PrivateKey:
		info.Type = "ED25519"
		info.Attributes["Key Size"] = fmt.Sprintf("%d bytes", len(k))
	case *mldsa.PrivateKey:
		info.Type = "ML-DSA"
		info.Attributes["Parameters"] = k.PublicKey().Parameters().String()
	default:
		info.Type = fmt.Sprintf("Unknown (%T)", k)
	}

	return info
}

// expiryTone maps days-until-expiry to a view tone name used by BuildDoc.
func expiryTone(days float64) string {
	if days <= 0 {
		return "crit"
	}

	if days < float64(CertExpWarnDays) {
		return "warn"
	}

	return "default"
}

func formatBool(b bool) string {
	return strconv.FormatBool(b)
}

func joinLines(vals []string) string {
	return strings.Join(vals, "\n")
}
