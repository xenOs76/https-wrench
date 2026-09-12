/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

package certinfo

import (
	"crypto/x509"
	"fmt"
	"strconv"
	"strings"

	"github.com/xenos76/https-wrench/internal/view"
)

// BuildDoc builds a console view document from a Result.
func BuildDoc(r *Result) view.Doc {
	nodes := []view.Node{
		view.Blank{},
		view.Banner{Text: "Certinfo"},
		view.Blank{},
	}

	if r == nil {
		return view.Doc{Nodes: nodes}
	}

	if r.PrivateKey != nil {
		nodes = append(nodes, privateKeySection(r.PrivateKey))
	}

	if r.LocalCerts != nil {
		nodes = append(nodes, certsSectionDoc(
			"Certificates",
			"Certificate bundle file",
			r.LocalCerts.FilePath,
			"",
			r.LocalCerts,
		)...)
	}

	if r.RemoteCerts != nil {
		nodes = append(nodes, certsSectionDoc(
			"TLSEndpoint Certificates",
			"Endpoint",
			r.RemoteCerts.Endpoint,
			r.RemoteCerts.ServerName,
			r.RemoteCerts,
		)...)
	}

	if r.TLSInfo != nil {
		nodes = append(nodes, tlsInfoNodes(r.TLSInfo)...)
	}

	if r.CACerts != nil {
		kids := []view.Node{
			view.KV{Key: "CA Certificates file", Value: r.CACerts.FilePath, Tone: view.ToneValue},
		}
		kids = append(kids, certInfoTables(r.CACerts.Certificates)...)
		nodes = append(nodes, view.Section{Title: "CA Certificates", Level: 1, Kids: kids})
	}

	return view.Doc{Nodes: nodes}
}

func privateKeySection(pk *PrivateKeyInfo) view.Node {
	kids := []view.Node{
		view.KV{Key: "PrivateKey file", Value: pk.FilePath, Tone: view.ToneValue},
	}

	rows := [][]view.Cell{
		{
			{Text: "Type", Tone: view.ToneKey},
			{Text: pk.Type, Tone: view.ToneValue},
		},
	}
	for _, key := range attrOrder(pk.Attributes) {
		rows = append(rows, []view.Cell{
			{Text: key, Tone: view.ToneKey},
			{Text: pk.Attributes[key], Tone: view.ToneValue},
		})
	}

	kids = append(kids, view.Table{Rows: rows})

	return view.Section{Title: "PrivateKey", Level: 1, Kids: kids}
}

func attrOrder(attrs map[string]string) []string {
	prefer := []string{"Key Size", "Curve", "Parameters"}

	var out []string

	seen := map[string]bool{}

	for _, k := range prefer {
		if _, ok := attrs[k]; ok {
			out = append(out, k)
			seen[k] = true
		}
	}

	for k := range attrs {
		if !seen[k] {
			out = append(out, k)
		}
	}

	return out
}

func certsSectionDoc(
	title, primaryKey, primaryVal, serverName string,
	sec *CertsSection,
) []view.Node {
	kids := []view.Node{
		view.KV{Key: primaryKey, Value: primaryVal, Tone: view.ToneValue},
	}

	if serverName != emptyString {
		kids = append(kids, view.KV{Key: "ServerName", Value: serverName, Tone: view.ToneValue})
	}

	if sec.PrivateKeyMatch != nil {
		tone := view.ToneBoolFalse
		if *sec.PrivateKeyMatch {
			tone = view.ToneBoolTrue
		}

		kids = append(kids, view.KV{
			Key:   "PrivateKey match",
			Value: formatBool(*sec.PrivateKeyMatch),
			Tone:  tone,
		})
	}

	kids = append(kids, certInfoTables(sec.Certificates)...)

	return []view.Node{view.Section{Title: title, Level: 1, Kids: kids}}
}

func certInfoTables(certs []CertInfo) []view.Node {
	nodes := make([]view.Node, 0, len(certs))
	for _, c := range certs {
		nodes = append(nodes, certInfoTable(c, nil))
	}

	return nodes
}

type certFieldSpec struct {
	names []string
	key   string
	value func(CertInfo) string
	tone  func(CertInfo) view.Tone
}

func valueTone(CertInfo) view.Tone { return view.ToneValue }

func noticeTone(CertInfo) view.Tone { return view.ToneNotice }

func expTone(c CertInfo) view.Tone {
	switch expiryTone(c.DaysUntilExpiry) {
	case "warn":
		return view.ToneWarn
	case "crit":
		return view.ToneCrit
	default:
		return view.ToneValue
	}
}

//nolint:gochecknoglobals // data-driven cert field list keeps certInfoTable small
var certFields = []certFieldSpec{
	{
		names: []string{"Subject"},
		key:   "Subject",
		value: func(c CertInfo) string { return c.Subject },
		tone:  valueTone,
	},
	{
		names: []string{"DNSNames"},
		key:   "DNSNames",
		value: func(c CertInfo) string { return joinLines(c.DNSNames) },
		tone:  valueTone,
	},
	{
		names: []string{"IPAddresses"},
		key:   "IPAddresses",
		value: func(c CertInfo) string { return joinLines(c.IPAddresses) },
		tone:  valueTone,
	},
	{
		names: []string{"Issuer"},
		key:   "Issuer",
		value: func(c CertInfo) string { return c.Issuer },
		tone:  valueTone,
	},
	{
		names: []string{"NotBefore"},
		key:   "NotBefore",
		value: func(c CertInfo) string { return c.NotBefore },
		tone:  valueTone,
	},
	{
		names: []string{"NotAfter"},
		key:   "NotAfter",
		value: func(c CertInfo) string { return c.NotAfter },
		tone:  expTone,
	},
	{
		names: []string{"Expiration"},
		key:   "Expiration",
		value: func(c CertInfo) string { return c.Expiration },
		tone:  expTone,
	},
	{
		names: []string{"IsCA"},
		key:   "IsCA",
		value: func(c CertInfo) string { return strconv.FormatBool(c.IsCA) },
		tone:  noticeTone,
	},
	{
		names: []string{"AuthorityKeyId"},
		key:   "AuthorityKeyId",
		value: func(c CertInfo) string { return c.AuthorityKeyID },
		tone:  noticeTone,
	},
	{
		names: []string{"SubjectKeyId"},
		key:   "SubjectKeyId",
		value: func(c CertInfo) string { return c.SubjectKeyID },
		tone:  noticeTone,
	},
	{
		names: []string{"PublicKeyAlgorithm"},
		key:   "PublicKeyAlgorithm",
		value: func(c CertInfo) string { return c.PublicKeyAlgorithm },
		tone:  valueTone,
	},
	{
		names: []string{"SignatureAlgorithm"},
		key:   "SignatureAlgorithm",
		value: func(c CertInfo) string { return c.SignatureAlgorithm },
		tone:  valueTone,
	},
	{
		names: []string{"SerialNumber"},
		key:   "SerialNumber",
		value: func(c CertInfo) string { return c.SerialNumber },
		tone:  valueTone,
	},
	{
		names: []string{"Fingerprint SHA-256", "Fingerprint"},
		key:   "Fingerprint SHA-256",
		value: func(c CertInfo) string { return c.FingerprintSHA256 },
		tone:  valueTone,
	},
}

func certInfoTable(c CertInfo, fields []string) view.Node {
	header := fmt.Sprintf("Certificate %d", c.Index)
	rows := make([][]view.Cell, 0, 14)

	for _, spec := range certFields {
		if !fieldRequested(fields, spec.names...) {
			continue
		}

		rows = append(rows, []view.Cell{
			{Text: spec.key, Tone: view.ToneKey},
			{Text: spec.value(c), Tone: spec.tone(c)},
		})
	}

	return view.Table{Headers: []string{header}, Rows: rows}
}

func fieldRequested(fields []string, names ...string) bool {
	if len(fields) == 0 {
		return true
	}

	for _, want := range names {
		for _, f := range fields {
			if strings.EqualFold(f, want) {
				return true
			}
		}
	}

	return false
}

// CertsDoc builds certificate table nodes from x509 certificates with optional field filters.
func CertsDoc(certs []*x509.Certificate, filter ...[]map[int][]string) view.Doc {
	var f []map[int][]string
	if len(filter) > 0 {
		f = filter[0]
	}

	requested := make(map[int][]string)
	hasFilter := len(f) > 0

	if hasFilter {
		for _, m := range f {
			for k, fields := range m {
				requested[k] = fields
			}
		}
	}

	nodes := make([]view.Node, 0, len(certs))
	for i, cert := range certs {
		var fields []string

		if hasFilter {
			var ok bool

			fields, ok = requested[i]
			if !ok {
				continue
			}
		}

		info := certInfoFromX509(i, cert)
		nodes = append(nodes, certInfoTable(info, fields))
	}

	return view.Doc{Nodes: nodes}
}

func tlsInfoNodes(info *TLSInfoSection) []view.Node {
	return []view.Node{
		negotiatedTLSSection(info),
		protocolSupportSection(info),
		cipherSuiteSection(info),
	}
}

func negotiatedTLSSection(info *TLSInfoSection) view.Node {
	return view.Section{
		Title: "Negotiated TLS Connection",
		Level: 1,
		Kids: []view.Node{
			view.Table{Rows: [][]view.Cell{
				kvRow("Protocol Version", info.NegotiatedProtocol),
				kvRow("Cipher Suite", info.NegotiatedCipher),
				kvRow("Key Exchange", info.NegotiatedCurveID),
			}},
		},
	}
}

func kvRow(key, val string) []view.Cell {
	return []view.Cell{
		{Text: key, Tone: view.ToneKey},
		{Text: val, Tone: view.ToneValue},
	}
}

func protocolSupportSection(info *TLSInfoSection) view.Node {
	protoRows := make([][]view.Cell, 0, 4)

	for _, protoName := range []string{"TLS 1.3", "TLS 1.2", "TLS 1.1", "TLS 1.0"} {
		supported := info.ProbedProtocols[protoName]
		statusStr, tone := "No", view.ToneBoolFalse

		if supported {
			statusStr, tone = "Yes", view.ToneBoolTrue
		}

		protoRows = append(protoRows, []view.Cell{
			{Text: protoName, Tone: view.ToneKey},
			{Text: statusStr, Tone: tone},
		})
	}

	return view.Section{
		Title: "Protocol Support Scan",
		Level: 1,
		Kids:  []view.Node{view.Table{Rows: protoRows}},
	}
}

func cipherSuiteSection(info *TLSInfoSection) view.Node {
	cipherRows := make([][]view.Cell, 0)

	for _, pc := range info.ProbedCiphers {
		if !pc.Supported {
			continue
		}

		secStr, secTone := "Secure", view.ToneBoolTrue
		if pc.Insecure {
			secStr, secTone = "Insecure", view.ToneWarn
		}

		cipherRows = append(cipherRows, []view.Cell{
			{Text: pc.Name, Tone: view.ToneKey},
			{Text: pc.Protocol, Tone: view.ToneValue},
			{Text: "Yes", Tone: view.ToneBoolTrue},
			{Text: secStr, Tone: secTone},
		})
	}

	if len(cipherRows) == 0 {
		cipherRows = append(cipherRows, []view.Cell{
			{Text: "No supported cipher suites found", Tone: view.ToneKey},
			{Text: "", Tone: view.ToneValue},
			{Text: "", Tone: view.ToneValue},
			{Text: "", Tone: view.ToneValue},
		})
	}

	return view.Section{
		Title: "Cipher Suite Scan",
		Level: 1,
		Kids: []view.Node{
			view.Table{
				Headers: []string{"Cipher Suite Name", "Protocol", "Status", "Security"},
				Rows:    cipherRows,
			},
		},
	}
}
