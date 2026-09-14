/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

package view

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/xenos76/https-wrench/internal/style"
	"golang.org/x/term"
)

// Options controls how a Doc is painted.
type Options struct {
	// Plain disables ANSI/lipgloss styling.
	Plain bool
	// ForceColor forces styled output even when stdout is not a TTY.
	ForceColor bool
}

// Render writes doc to w using theme tokens from internal/style.
func Render(w io.Writer, doc Doc, opts Options) error {
	styled := !opts.Plain
	if styled && !opts.ForceColor && !isTerminal(w) {
		styled = false
	}

	r := renderer{w: w, styled: styled}
	for _, n := range doc.Nodes {
		if err := r.renderNode(n); err != nil {
			return err
		}
	}

	return nil
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}

	return term.IsTerminal(int(f.Fd()))
}

type renderer struct {
	w      io.Writer
	styled bool
}

func (r renderer) renderNode(n Node) error {
	switch v := n.(type) {
	case Banner:
		return r.renderBanner(v)
	case Blank:
		_, err := fmt.Fprintln(r.w)
		return err
	case Section:
		return r.renderSection(v)
	case KV:
		return r.renderKV(v, 4)
	case Table:
		return r.renderTable(v)
	case Code:
		if r.styled && v.Lang != "" {
			out := style.CodeSyntaxHighlight(v.Lang, v.Body)
			if !strings.HasSuffix(out, "\n") {
				out += "\n"
			}

			_, err := fmt.Fprint(r.w, out)

			return err
		}

		_, err := fmt.Fprintln(r.w, v.Body)

		return err
	default:
		return fmt.Errorf("view: unsupported node %T", n)
	}
}

func (r renderer) renderBanner(b Banner) error {
	if r.styled {
		_, err := fmt.Fprintln(r.w, style.LgSprintf(style.Cmd, "%s", b.Text))
		return err
	}

	_, err := fmt.Fprintln(r.w, b.Text)

	return err
}

func (r renderer) renderSection(s Section) error {
	pad := sectionPad(s.Level)

	if r.styled {
		st := style.ItemKey.PaddingBottom(0).PaddingTop(1).PaddingLeft(pad)
		if _, err := fmt.Fprintln(r.w, style.LgSprintf(st, "%s", s.Title)); err != nil {
			return err
		}
	} else {
		indent := strings.Repeat(" ", pad)
		if _, err := fmt.Fprintln(r.w, indent+s.Title); err != nil {
			return err
		}
	}

	for _, kid := range s.Kids {
		switch k := kid.(type) {
		case KV:
			if err := r.renderKV(k, pad+3); err != nil {
				return err
			}
		default:
			if err := r.renderNode(kid); err != nil {
				return err
			}
		}
	}

	return nil
}

func sectionPad(level int) int {
	switch {
	case level <= 1:
		return 1
	case level == 2:
		return 3
	default:
		return 4
	}
}

func (r renderer) renderKV(kv KV, leftPad int) error {
	if r.styled {
		keyStyle := style.CertKeyP4.Bold(true).PaddingLeft(leftPad)
		line := keyStyle.Render(kv.Key+": ") + r.paint(kv.Value, effectiveValueTone(kv.Tone))
		_, err := fmt.Fprintln(r.w, line)

		return err
	}

	indent := strings.Repeat(" ", leftPad)
	_, err := fmt.Fprintf(r.w, "%s%s: %s\n", indent, kv.Key, kv.Value)

	return err
}

func effectiveValueTone(t Tone) Tone {
	if t == ToneDefault {
		return ToneValue
	}

	return t
}

func (r renderer) renderTable(t Table) error {
	if r.styled {
		return r.renderTableStyled(t)
	}

	return r.renderTablePlain(t)
}

func (r renderer) renderTableStyled(t Table) error {
	lt := table.New().Border(style.LGDefBorder)

	if len(t.Headers) > 0 {
		headers := make([]string, len(t.Headers))
		for i, h := range t.Headers {
			if i == 0 {
				headers[i] = style.CertKeyP4.Bold(true).Render(h)
			} else {
				headers[i] = style.CertKeyP4.Bold(true).PaddingLeft(0).Render(h)
			}
		}

		lt = lt.Headers(headers...)
	}

	for _, row := range t.Rows {
		cells := make([]string, len(row))
		for i, c := range row {
			tone := c.Tone
			if tone == ToneDefault && i == 0 {
				tone = ToneKey
			} else if tone == ToneDefault {
				tone = ToneValue
			}

			cells[i] = r.paint(c.Text, tone)
		}

		lt = lt.Row(cells...)
	}

	_, err := fmt.Fprintln(r.w, lt.Render())

	return err
}

func (r renderer) renderTablePlain(t Table) error {
	if len(t.Headers) > 0 {
		if _, err := fmt.Fprintln(r.w, strings.Join(t.Headers, "\t")); err != nil {
			return err
		}
	}

	for _, row := range t.Rows {
		parts := make([]string, len(row))
		for i, c := range row {
			parts[i] = c.Text
		}

		if _, err := fmt.Fprintln(r.w, strings.Join(parts, "\t")); err != nil {
			return err
		}
	}

	return nil
}

func (r renderer) paint(text string, tone Tone) string {
	if !r.styled {
		return text
	}

	return toneStyle(tone).Render(text)
}

func toneStyle(tone Tone) lipgloss.Style {
	if st, ok := statusToneStyle(tone); ok {
		return st
	}

	switch tone {
	case ToneWarn:
		return style.Warn
	case ToneCrit:
		return style.Crit
	case ToneBoolTrue:
		return style.BoolTrue
	case ToneBoolFalse:
		return style.BoolFalse
	case ToneNotice:
		return style.CertValueNotice
	case ToneURL:
		return style.URL
	case ToneCmd:
		return style.Cmd
	case ToneSection:
		return style.ItemKey
	case ToneKey:
		return style.CertKeyP4
	case ToneHeader:
		return style.CertKeyP4.Bold(true)
	default:
		return style.CertValue
	}
}

func statusToneStyle(tone Tone) (lipgloss.Style, bool) {
	switch tone {
	case ToneStatus2xx:
		return style.Status2xx, true
	case ToneStatus3xx:
		return style.Status3xx, true
	case ToneStatus4xx:
		return style.Status4xx, true
	case ToneStatus5xx:
		return style.Status5xx, true
	default:
		return lipgloss.Style{}, false
	}
}
