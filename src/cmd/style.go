package cmd

import (
	catppuccin "github.com/catppuccin/go"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

var (
	glamourDefStyle = "tokyo-night"
	chromaDefStyle  = "dracula"

	// lgDefBorder = lipgloss.NormalBorder()
	lgDefBorder = lipgloss.HiddenBorder()
	lgTable     = table.New().Border(lgDefBorder)

	flavour = catppuccin.Frappe

	catBase     = lipgloss.Color(flavour.Base().Hex)
	catBlue     = lipgloss.Color(flavour.Blue().Hex)
	catLavander = lipgloss.Color(flavour.Lavender().Hex)
	catPeach    = lipgloss.Color(flavour.Peach().Hex)
	catMauve    = lipgloss.Color(flavour.Mauve().Hex)
	catFlamingo = lipgloss.Color(flavour.Flamingo().Hex)
	catSapphire = lipgloss.Color(flavour.Sapphire().Hex)
	catGreen    = lipgloss.Color(flavour.Green().Hex)
	catYellow   = lipgloss.Color(flavour.Yellow().Hex)
	catRed      = lipgloss.Color(flavour.Red().Hex)
	catPink     = lipgloss.Color(flavour.Pink().Hex)
	catTeal     = lipgloss.Color(flavour.Teal().Hex)
	lgRed       = lipgloss.Color("#FF0000")

	styleCmd = lipgloss.NewStyle().Foreground(catBase).Background(catBlue).Bold(true).PaddingLeft(1).PaddingRight(1)

	styleTitleKey = lipgloss.NewStyle().
			Foreground(lipgloss.Color(catBlue)).Bold(true)

	styleTitle = lipgloss.NewStyle().
			Foreground(lipgloss.Color(catLavander)).Bold(true).
			PaddingLeft(1)

	styleItemKey = lipgloss.NewStyle().
			Foreground(lipgloss.Color(catBlue)).
			PaddingLeft(1).Bold(true)

	styleItemKeyP3 = lipgloss.NewStyle().
			Foreground(lipgloss.Color(catBlue)).
			PaddingLeft(3).Bold(true)

	styleHeadKeyP3 = lipgloss.NewStyle().
			Foreground(lipgloss.Color(catFlamingo)).
			PaddingLeft(3)

	styleHeadValue = lipgloss.NewStyle().
			Foreground(lipgloss.Color(catSapphire))

	styleCertKeyP3 = lipgloss.NewStyle().
			Foreground(lipgloss.Color(catLavander)).
			PaddingLeft(3)

	styleCertKeyP4 = lipgloss.NewStyle().
			Foreground(lipgloss.Color(catLavander)).
			PaddingLeft(4)

	styleCertKeyP5 = lipgloss.NewStyle().
			Foreground(lipgloss.Color(catLavander)).
			PaddingLeft(5)

	styleCertValue = lipgloss.NewStyle().
			Foreground(lipgloss.Color(catPeach))

	styleVia = lipgloss.NewStyle().
			Foreground(lipgloss.Color(catMauve)).Italic(true).
			PaddingLeft(1)

	styleUrl = lipgloss.NewStyle().
			Foreground(lipgloss.Color(catFlamingo)).Bold(true)

	styleStatus = lipgloss.NewStyle().
			Foreground(lipgloss.Color(catSapphire))

	styleStatus2xx = lipgloss.NewStyle().
			Foreground(lipgloss.Color(catGreen))

	styleStatus3xx = lipgloss.NewStyle().
			Foreground(lipgloss.Color(catMauve))

	styleStatus4xx = lipgloss.NewStyle().
			Foreground(lipgloss.Color(catYellow))

	styleStatus5xx = lipgloss.NewStyle().
			Foreground(lipgloss.Color(catRed))

	styleStatusError = lipgloss.NewStyle().
				Foreground(lipgloss.Color(catRed))

	styleError = lipgloss.NewStyle().
			Foreground(lipgloss.Color(catPink)).Italic(true)

	styleHeaders = lipgloss.NewStyle().Italic(true).PaddingLeft(4).
			Foreground(lipgloss.Color(catTeal))

	styleBoolTrue  = lipgloss.NewStyle().Foreground(catTeal)
	styleBoolFalse = lipgloss.NewStyle().Foreground(catYellow)
	styleWarn      = lipgloss.NewStyle().Foreground(catYellow)
	styleCrit      = lipgloss.NewStyle().Foreground(lgRed)
)
