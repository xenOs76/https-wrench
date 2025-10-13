package style

import (
	catppuccin "github.com/catppuccin/go"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

var (
	glamourDefStyle = "tokyo-night"
	chromaDefStyle  = "dracula"

	LGDefBorder = lipgloss.HiddenBorder()
	LGTable     = table.New().Border(LGDefBorder)

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

	Cmd = lipgloss.NewStyle().Foreground(catBase).Background(catBlue).
		Bold(true).PaddingLeft(1).PaddingRight(1)

	TitleKey = lipgloss.NewStyle().
			Foreground(catBlue).Bold(true)

	Title = lipgloss.NewStyle().
		Foreground(catLavander).Bold(true).
		PaddingLeft(1)

	ItemKey = lipgloss.NewStyle().
		Foreground(catBlue).
		PaddingLeft(1).Bold(true)

	ItemKeyP3 = lipgloss.NewStyle().
			Foreground(catBlue).
			PaddingLeft(3).Bold(true)

	HeadKeyP3 = lipgloss.NewStyle().
			Foreground(catFlamingo).
			PaddingLeft(3)

	HeadValue = lipgloss.NewStyle().
			Foreground(catSapphire)

	CertKeyP3 = lipgloss.NewStyle().
			Foreground(catLavander).
			PaddingLeft(3)

	CertKeyP4 = lipgloss.NewStyle().
			Foreground(catLavander).
			PaddingLeft(4)

	CertKeyP5 = lipgloss.NewStyle().
			Foreground(catLavander).
			PaddingLeft(5)

	CertValue = lipgloss.NewStyle().
			Foreground(catPeach)

	CertValueNotice = lipgloss.NewStyle().
			Foreground(catMauve)

	Via = lipgloss.NewStyle().
		Foreground(catMauve).Italic(true).
		PaddingLeft(1)

	URL = lipgloss.NewStyle().
		Foreground(catFlamingo).Bold(true)

	Status = lipgloss.NewStyle().
		Foreground(catSapphire)

	Status2xx = lipgloss.NewStyle().
			Foreground(catGreen)

	Status3xx = lipgloss.NewStyle().
			Foreground(catMauve)

	Status4xx = lipgloss.NewStyle().
			Foreground(catYellow)

	Status5xx = lipgloss.NewStyle().
			Foreground(catRed)

	StatusError = lipgloss.NewStyle().
			Foreground(catRed)

	Error = lipgloss.NewStyle().
		Foreground(catPink).Italic(true)

	Headers = lipgloss.NewStyle().Italic(true).PaddingLeft(4).
		Foreground(catTeal)

	BoolTrue  = lipgloss.NewStyle().Foreground(catTeal)
	BoolFalse = lipgloss.NewStyle().Foreground(catYellow)
	Warn      = lipgloss.NewStyle().Foreground(catYellow)
	Crit      = lipgloss.NewStyle().Foreground(lgRed)
)
