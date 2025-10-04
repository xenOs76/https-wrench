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

	styleCmd = lipgloss.NewStyle().Foreground(catBase).Background(catBlue).
			Bold(true).PaddingLeft(1).PaddingRight(1)

	styleTitleKey = lipgloss.NewStyle().
			Foreground(catBlue).Bold(true)

	styleTitle = lipgloss.NewStyle().
			Foreground(catLavander).Bold(true).
			PaddingLeft(1)

	styleItemKey = lipgloss.NewStyle().
			Foreground(catBlue).
			PaddingLeft(1).Bold(true)

	styleItemKeyP3 = lipgloss.NewStyle().
			Foreground(catBlue).
			PaddingLeft(3).Bold(true)

	styleHeadKeyP3 = lipgloss.NewStyle().
			Foreground(catFlamingo).
			PaddingLeft(3)

	styleHeadValue = lipgloss.NewStyle().
			Foreground(catSapphire)

	styleCertKeyP3 = lipgloss.NewStyle().
			Foreground(catLavander).
			PaddingLeft(3)

	styleCertKeyP4 = lipgloss.NewStyle().
			Foreground(catLavander).
			PaddingLeft(4)

	styleCertKeyP5 = lipgloss.NewStyle().
			Foreground(catLavander).
			PaddingLeft(5)

	styleCertValue = lipgloss.NewStyle().
			Foreground(catPeach)

	styleCertValueNotice = lipgloss.NewStyle().
				Foreground(catMauve)

	styleVia = lipgloss.NewStyle().
			Foreground(catMauve).Italic(true).
			PaddingLeft(1)

	styleURL = lipgloss.NewStyle().
			Foreground(catFlamingo).Bold(true)

	styleStatus = lipgloss.NewStyle().
			Foreground(catSapphire)

	styleStatus2xx = lipgloss.NewStyle().
			Foreground(catGreen)

	styleStatus3xx = lipgloss.NewStyle().
			Foreground(catMauve)

	styleStatus4xx = lipgloss.NewStyle().
			Foreground(catYellow)

	styleStatus5xx = lipgloss.NewStyle().
			Foreground(catRed)

	styleStatusError = lipgloss.NewStyle().
				Foreground(catRed)

	styleError = lipgloss.NewStyle().
			Foreground(catPink).Italic(true)

	styleHeaders = lipgloss.NewStyle().Italic(true).PaddingLeft(4).
			Foreground(catTeal)

	styleBoolTrue  = lipgloss.NewStyle().Foreground(catTeal)
	styleBoolFalse = lipgloss.NewStyle().Foreground(catYellow)
	styleWarn      = lipgloss.NewStyle().Foreground(catYellow)
	styleCrit      = lipgloss.NewStyle().Foreground(lgRed)
)
