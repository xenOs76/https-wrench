package cmd

import (
	"fmt"
	catppuccin "github.com/catppuccin/go"
	"github.com/charmbracelet/lipgloss"
	"strings"
)

var (
	flavour = catppuccin.Frappe

	styleTitleKey = lipgloss.NewStyle().
			Foreground(lipgloss.Color(flavour.Blue().Hex)).Bold(true)

	styleTitle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(flavour.Lavender().Hex)).Bold(true).
			PaddingLeft(1)

	styleItemKey = lipgloss.NewStyle().
			Foreground(lipgloss.Color(flavour.Blue().Hex)).
			PaddingLeft(1)

	styleItemKeyP3 = lipgloss.NewStyle().
			Foreground(lipgloss.Color(flavour.Blue().Hex)).
			PaddingLeft(3)

	styleVia = lipgloss.NewStyle().
			Foreground(lipgloss.Color(flavour.Mauve().Hex)).Italic(true).
			PaddingLeft(1)

	styleUrl = lipgloss.NewStyle().
			Foreground(lipgloss.Color(flavour.Flamingo().Hex)).Bold(true)

	styleStatus = lipgloss.NewStyle().
			Foreground(lipgloss.Color(flavour.Sapphire().Hex))

	styleStatus2xx = lipgloss.NewStyle().
			Foreground(lipgloss.Color(flavour.Green().Hex))

	styleStatus3xx = lipgloss.NewStyle().
			Foreground(lipgloss.Color(flavour.Mauve().Hex))

	styleStatus4xx = lipgloss.NewStyle().
			Foreground(lipgloss.Color(flavour.Yellow().Hex))

	styleStatus5xx = lipgloss.NewStyle().
			Foreground(lipgloss.Color(flavour.Red().Hex))

	styleStatusError = lipgloss.NewStyle().
				Foreground(lipgloss.Color(flavour.Red().Hex))

	styleError = lipgloss.NewStyle().
			Foreground(lipgloss.Color(flavour.Pink().Hex)).Italic(true)

	styleHeaders = lipgloss.NewStyle().Italic(true).PaddingLeft(4).
			Foreground(lipgloss.Color(flavour.Teal().Hex))

	// styleBody = lipgloss.NewStyle().PaddingLeft(4)

	styleKey     = lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true)
	styleString  = lipgloss.NewStyle().Foreground(lipgloss.Color("39"))
	styleNumber  = lipgloss.NewStyle().Foreground(lipgloss.Color("208"))
	styleBool    = lipgloss.NewStyle().Foreground(lipgloss.Color("170"))
	styleNull    = lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Italic(true)
	styleBracket = lipgloss.NewStyle().Foreground(lipgloss.Color("245"))
)

func lgSprintf(style lipgloss.Style, pattern string, a ...any) string {
	str := fmt.Sprintf(pattern, a...)
	out := style.Render(str)
	return out
}

func prettyPrintJson(v any, indent int) string {
	ind := strings.Repeat("  ", indent)
	switch val := v.(type) {
	case map[string]any:
		var b strings.Builder
		b.WriteString(styleBracket.Render("{") + "\n")
		for k, v2 := range val {
			b.WriteString(ind + "  ")
			b.WriteString(styleKey.Render(fmt.Sprintf(`"%s"`, k)))
			b.WriteString(styleBracket.Render(": ") + prettyPrintJson(v2, indent+1))
			b.WriteString("\n")
		}
		b.WriteString(ind + styleBracket.Render("}"))
		return b.String()

	case []any:
		var b strings.Builder
		b.WriteString(styleBracket.Render("[") + "\n")
		for _, item := range val {
			b.WriteString(ind + "  " + prettyPrintJson(item, indent+1) + "\n")
		}
		b.WriteString(ind + styleBracket.Render("]"))
		return b.String()

	case string:
		return styleString.Render(fmt.Sprintf(`"%s"`, val))
	case float64:
		return styleNumber.Render(fmt.Sprintf("%v", val))
	case bool:
		return styleBool.Render(fmt.Sprintf("%v", val))
	case nil:
		return styleNull.Render("null")
	default:
		return fmt.Sprintf("%v", val)
	}
}
