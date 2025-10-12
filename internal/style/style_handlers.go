package style

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"strconv"
	"strings"

	"github.com/alecthomas/chroma/v2"
	"github.com/alecthomas/chroma/v2/formatters"
	"github.com/alecthomas/chroma/v2/lexers"
	"github.com/alecthomas/chroma/v2/styles"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

func LgSprintf(style lipgloss.Style, pattern string, a ...any) string {
	str := fmt.Sprintf(pattern, a...)
	out := style.Render(str)

	return out
}

func StatusCodeParse(sc int) string {
	var status string

	statusString := strconv.Itoa(sc)

	switch {
	case sc >= 200 && sc < 300:
		status = Status2xx.Render(statusString)
	case sc >= 300 && sc < 400:
		status = Status3xx.Render(statusString)
	case sc >= 400 && sc < 500:
		status = Status4xx.Render(statusString)
	case sc >= 500:
		status = Status5xx.Render(statusString)
	default:
		status = Status.Render(statusString)
	}

	return status
}

func BoolStyle(b bool) string {
	if b {
		return LgSprintf(BoolTrue, "true")
	}

	return LgSprintf(BoolFalse, "false")
}

func PrintKeyInfoStyle(privKey crypto.PrivateKey) {
	sl := CertKeyP4.Render
	sv := CertValue.Render
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
