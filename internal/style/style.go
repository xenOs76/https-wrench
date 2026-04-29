package style

import (
	catppuccin "github.com/catppuccin/go"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

var (
	glamourDefStyle = "tokyo-night"
	chromaDefStyle  = "catppuccin-frappe"

	// LGDefBorder is the default hidden border for lipgloss tables.
	LGDefBorder = lipgloss.HiddenBorder()
	// LGTable is a pre-configured lipgloss table with a hidden border.
	LGTable = table.New().Border(LGDefBorder)

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

	// Cmd is the style for command/section headers.
	Cmd = lipgloss.NewStyle().Foreground(catBase).Background(catBlue).
		Bold(true).PaddingLeft(1).PaddingRight(1)

	// TitleKey is the style for main titles' keys.
	TitleKey = lipgloss.NewStyle().
			Foreground(catBlue).Bold(true)

	// Title is the style for main titles' values.
	Title = lipgloss.NewStyle().
		Foreground(catLavander).Bold(true).
		PaddingLeft(1)

	// Title2 is an alternative style for titles with a background color.
	Title2 = lipgloss.NewStyle().
		Foreground(catBase).Background(catPeach).Bold(true).
		PaddingLeft(1).PaddingRight(1)

	// ItemKey is the style for item keys with minimal padding.
	ItemKey = lipgloss.NewStyle().
		Foreground(catBlue).
		PaddingLeft(1).Bold(true)

	// ItemKeyP3 is the style for item keys with more left padding.
	ItemKeyP3 = lipgloss.NewStyle().
			Foreground(catBlue).
			PaddingLeft(3).Bold(true)

	// HeadKeyP3 is the style for header keys in tables with padding.
	HeadKeyP3 = lipgloss.NewStyle().
			Foreground(catFlamingo).
			PaddingLeft(3)

	// HeadValue is the style for header values in tables.
	HeadValue = lipgloss.NewStyle().
			Foreground(catSapphire)

	// CertKeyP3 is the style for certificate keys with padding.
	CertKeyP3 = lipgloss.NewStyle().
			Foreground(catLavander).
			PaddingLeft(3)

	// CertKeyP4 is the style for certificate keys with more padding.
	CertKeyP4 = lipgloss.NewStyle().
			Foreground(catLavander).
			PaddingLeft(4)

	// CertKeyP5 is the style for certificate keys with maximum padding.
	CertKeyP5 = lipgloss.NewStyle().
			Foreground(catLavander).
			PaddingLeft(5)

	// CertValue is the style for certificate values.
	CertValue = lipgloss.NewStyle().
			Foreground(catPeach)

	// CertValueNotice is the style for highlighted certificate values (e.g. CA status).
	CertValueNotice = lipgloss.NewStyle().
			Foreground(catMauve)

	// Via is the style for "via" transport information.
	Via = lipgloss.NewStyle().
		Foreground(catMauve).Italic(true).
		PaddingLeft(1)

	// URL is the style for URLs.
	URL = lipgloss.NewStyle().
		Foreground(catFlamingo).Bold(true)

	// Status is the default style for HTTP status codes.
	Status = lipgloss.NewStyle().
		Foreground(catSapphire)

	// Status2xx is the style for 2xx HTTP status codes.
	Status2xx = lipgloss.NewStyle().
			Foreground(catGreen)

	// Status3xx is the style for 3xx HTTP status codes.
	Status3xx = lipgloss.NewStyle().
			Foreground(catMauve)

	// Status4xx is the style for 4xx HTTP status codes.
	Status4xx = lipgloss.NewStyle().
			Foreground(catYellow)

	// Status5xx is the style for 5xx HTTP status codes.
	Status5xx = lipgloss.NewStyle().
			Foreground(catRed)

	// StatusError is the style for error status codes (e.g. 0).
	StatusError = lipgloss.NewStyle().
			Foreground(catRed)

	// Error is the style for error messages.
	Error = lipgloss.NewStyle().
		Foreground(catPink).Italic(true)

	// Headers is the style for response headers.
	Headers = lipgloss.NewStyle().Italic(true).PaddingLeft(4).
		Foreground(catTeal)

	// BoolTrue is the style for boolean true values.
	BoolTrue = lipgloss.NewStyle().Foreground(catTeal)
	// BoolFalse is the style for boolean false values.
	BoolFalse = lipgloss.NewStyle().Foreground(catYellow)
	// Warn is the style for warning messages or near-expiration dates.
	Warn = lipgloss.NewStyle().Foreground(catYellow)
	// Crit is the style for critical errors or expired certificates.
	Crit = lipgloss.NewStyle().Foreground(lgRed)
)
