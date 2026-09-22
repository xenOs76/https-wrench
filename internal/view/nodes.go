/*
Copyright © 2025 Zeno Belli xeno@os76.xyz
*/

package view

// Cell is one table cell.
type Cell struct {
	Text string
	Tone Tone
}

// Table is a lipgloss table (or plain aligned rows).
type Table struct {
	Headers []string
	Rows    [][]Cell
}

// viewNode marks Table as a renderable document node.
func (Table) viewNode() {}

// Code is a fenced code body; highlight only in a TTY renderer (future).
type Code struct {
	Lang, Body string
}

// viewNode marks Code as a renderable document node.
func (Code) viewNode() {}

// Banner is a single prominent command/title line.
type Banner struct {
	Text string
}

// viewNode marks Banner as a renderable document node.
func (Banner) viewNode() {}

// Blank is a blank line.
type Blank struct{}

// viewNode marks Blank as a renderable document node.
func (Blank) viewNode() {}
