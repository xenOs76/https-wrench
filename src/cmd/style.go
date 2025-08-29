package cmd

import (
	catppuccin "github.com/catppuccin/go"
	"github.com/charmbracelet/lipgloss"
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
			PaddingLeft(1).Bold(true)

	styleItemKeyP3 = lipgloss.NewStyle().
			Foreground(lipgloss.Color(flavour.Blue().Hex)).
			PaddingLeft(3).Bold(true)

	styleCertKeyP4 = lipgloss.NewStyle().
			Foreground(lipgloss.Color(flavour.Lavender().Hex)).
			PaddingLeft(4)

	styleCertKeyP5 = lipgloss.NewStyle().
			Foreground(lipgloss.Color(flavour.Lavender().Hex)).
			PaddingLeft(5)

	styleCertValue = lipgloss.NewStyle().
			Foreground(lipgloss.Color(flavour.Peach().Hex))

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
