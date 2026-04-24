package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"charm.land/bubbles/v2/filepicker"
	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#7C3AED"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6B7280"))

	errStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#EF4444"))

	successStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#10B981"))

	warnStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F59E0B"))

	boldStyle = lipgloss.NewStyle().Bold(true)

	selectedStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#7C3AED"))

	leafStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#10B981"))

	interStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#3B82F6"))

	rootCertStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#F59E0B"))

	// Panel chrome
	panelStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#374151")).
			Padding(0, 1)

	panelTitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("#E5E7EB"))

	// Option selector
	optionLabelActive = lipgloss.NewStyle().
				Bold(true).
				Foreground(lipgloss.Color("#7C3AED"))

	optionHintActive = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#A78BFA"))

	optionLabelIdle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#6B7280"))

	optionHintIdle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#4B5563"))
)

type clearErrMsg struct{}
type appErrMsg struct{ err error }
type parsedMsg struct {
	certs  []CertNode
	sorted []CertNode
}
type writtenMsg struct{ outputPath string }

func clearErrAfter(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(_ time.Time) tea.Msg { return clearErrMsg{} })
}

type appState int

const (
	statePicking appState = iota
	stateAnalysis
	stateDone
)

type model struct {
	state        appState
	fp           filepicker.Model
	help         help.Model
	width        int
	height       int
	selectedFile string
	original     []CertNode
	sorted       []CertNode
	cursor       int
	outputPath   string
	err          error
	quitting     bool
}

func newModel() model {
	fp := filepicker.New()
	fp.AllowedTypes = []string{".pem", ".cer", ".crt", ".cert", ".p7b"}
	fp.ShowPermissions = false
	fp.AutoHeight = false
	fp.CurrentDirectory, _ = os.Getwd()
	return model{fp: fp, help: help.New()}
}

func (m model) Init() tea.Cmd { return m.fp.Init() }

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.help.SetWidth(msg.Width)
		const reservedLines = 8
		m.fp.SetHeight(max(4, msg.Height-reservedLines))
		var cmd tea.Cmd
		m.fp, cmd = m.fp.Update(msg)
		return m, cmd

	case clearErrMsg:
		m.err = nil
		return m, nil

	case appErrMsg:
		m.err = msg.err
		return m, clearErrAfter(4 * time.Second)

	case parsedMsg:
		m.original = msg.certs
		m.sorted = msg.sorted
		m.state = stateAnalysis
		return m, nil

	case writtenMsg:
		m.outputPath = msg.outputPath
		m.state = stateDone
		return m, nil
	}

	switch m.state {
	case statePicking:
		return m.updatePicking(msg)
	case stateAnalysis:
		return m.updateAnalysis(msg)
	case stateDone:
		return m.updateDone(msg)
	}
	return m, nil
}

func (m model) updatePicking(msg tea.Msg) (tea.Model, tea.Cmd) {
	if kp, ok := msg.(tea.KeyPressMsg); ok {
		switch {
		case key.Matches(kp, pickingKeys.Quit):
			m.quitting = true
			return m, tea.Quit
		case key.Matches(kp, pickingKeys.Help):
			m.help.ShowAll = !m.help.ShowAll
			return m, nil
		}
		switch kp.String() {
		case "w":
			msg = tea.KeyPressMsg{Code: tea.KeyUp}
		case "s":
			msg = tea.KeyPressMsg{Code: tea.KeyDown}
		case "a":
			msg = tea.KeyPressMsg{Code: tea.KeyLeft}
		case "d":
			msg = tea.KeyPressMsg{Code: tea.KeyRight}
		}
	}

	var cmd tea.Cmd
	m.fp, cmd = m.fp.Update(msg)

	if didSelect, path := m.fp.DidSelectFile(msg); didSelect {
		m.selectedFile = path
		return m, tea.Batch(cmd, parseFileCmd(path))
	}
	if didSelect, path := m.fp.DidSelectDisabledFile(msg); didSelect {
		m.err = fmt.Errorf("%s is not a recognized certificate type (.pem .cer .crt .cert .p7b)", filepath.Base(path))
		return m, tea.Batch(cmd, clearErrAfter(3*time.Second))
	}
	return m, cmd
}

func (m model) updateAnalysis(msg tea.Msg) (tea.Model, tea.Cmd) {
	kp, ok := msg.(tea.KeyPressMsg)
	if !ok {
		return m, nil
	}
	switch {
	case key.Matches(kp, analysisKeys.Quit):
		m.quitting = true
		return m, tea.Quit
	case key.Matches(kp, analysisKeys.Back):
		m.state = statePicking
		m.err = nil
		return m, m.fp.Init()
	case key.Matches(kp, analysisKeys.Up):
		if m.cursor > 0 {
			m.cursor--
		}
	case key.Matches(kp, analysisKeys.Down):
		if m.cursor < 1 {
			m.cursor++
		}
	case key.Matches(kp, analysisKeys.Help):
		m.help.ShowAll = !m.help.ShowAll
	case key.Matches(kp, analysisKeys.Confirm):
		out := buildOutputPath(m.selectedFile)
		return m, writeChainCmd(m.sorted, m.cursor == 1, out)
	}
	return m, nil
}

func (m model) updateDone(msg tea.Msg) (tea.Model, tea.Cmd) {
	if kp, ok := msg.(tea.KeyPressMsg); ok {
		if key.Matches(kp, doneKeys.Quit) {
			m.quitting = true
			return m, tea.Quit
		}
	}
	return m, nil
}

func parseFileCmd(path string) tea.Cmd {
	return func() tea.Msg {
		certs, err := ParseCertsFromFile(path)
		if err != nil {
			return appErrMsg{fmt.Errorf("not a valid certificate file: %w", err)}
		}
		sorted, err := SortChain(certs)
		if err != nil {
			return appErrMsg{fmt.Errorf("chain error: %w", err)}
		}
		return parsedMsg{certs: certs, sorted: sorted}
	}
}

func writeChainCmd(sorted []CertNode, rootFirst bool, path string) tea.Cmd {
	return func() tea.Msg {
		if err := WriteChain(path, sorted, rootFirst); err != nil {
			return appErrMsg{fmt.Errorf("failed to write output: %w", err)}
		}
		return writtenMsg{outputPath: path}
	}
}

func (m model) View() tea.View {
	if m.quitting {
		return tea.NewView("")
	}
	var content string
	switch m.state {
	case statePicking:
		content = m.viewPicking()
	case stateAnalysis:
		content = m.viewAnalysis()
	case stateDone:
		content = m.viewDone()
	}
	v := tea.NewView(content)
	v.AltScreen = true
	return v
}

func (m model) viewPicking() string {
	var b strings.Builder
	b.WriteString("\n  " + titleStyle.Render("🔐 CertFixer") + "\n")
	b.WriteString("  " + dimStyle.Render("Select a certificate file to analyze and reorder") + "\n\n")
	if m.err != nil {
		b.WriteString("  " + errStyle.Render("✗  "+m.err.Error()) + "\n\n")
	} else {
		b.WriteString("  " + dimStyle.Render("Showing: .pem  .cer  .crt  .cert  .p7b") + "\n\n")
	}
	b.WriteString(lipgloss.NewStyle().MarginLeft(2).Render(m.help.View(pickingKeys)) + "\n\n")
	b.WriteString(m.fp.View())
	return b.String()
}

// viewAnalysis renders the chain comparison and output-order selector.
//
// Layout rules (driven by m.width):
//   - Panels are placed side-by-side when the terminal is ≥ 90 columns wide,
//     stacked otherwise.
//   - All indentation is managed by lipgloss; no raw space strings are used for
//     alignment.
func (m model) viewAnalysis() string {
	const (
		outerMargin = 2  // left indent for the whole view
		panelGap    = 3  // columns between side-by-side panels
		minPanelW   = 40 // minimum outer width per panel before stacking
	)

	pad := strings.Repeat(" ", outerMargin)

	// Usable width inside the outer margin (right edge is the terminal boundary).
	innerW := m.width - outerMargin*2
	if innerW < minPanelW {
		innerW = minPanelW
	}

	var b strings.Builder

	b.WriteString("\n")
	b.WriteString(pad + titleStyle.Render("🔐 CertFixer") + "\n")
	b.WriteString(pad + dimStyle.Render("file: "+filepath.Base(m.selectedFile)) + "\n\n")

	warnBadge := ""
	if !IsChainComplete(m.sorted) {
		warnBadge = "  " + warnStyle.Render("⚠ incomplete")
	}

	rootFirst := m.cursor == 1
	fixedCerts := m.sorted
	if rootFirst {
		fixedCerts = reverseCerts(m.sorted)
	}

	sideBySide := innerW >= minPanelW*2+panelGap
	var chainBlock string
	if sideBySide {
		panelW := (innerW - panelGap) / 2
		left := certPanel("Current Order", "", m.original, false, false, panelW)
		right := certPanel("Fixed Order", warnBadge, fixedCerts, true, rootFirst, panelW)
		chainBlock = lipgloss.JoinHorizontal(lipgloss.Top,
			left,
			strings.Repeat(" ", panelGap),
			right,
		)
	} else {
		top := certPanel("Current Order", "", m.original, false, false, innerW)
		bot := certPanel("Fixed Order", warnBadge, fixedCerts, true, rootFirst, innerW)
		chainBlock = lipgloss.JoinVertical(lipgloss.Left, top, bot)
	}

	// Indent each line of the rendered block by outerMargin.
	for _, line := range strings.Split(chainBlock, "\n") {
		b.WriteString(pad + line + "\n")
	}
	b.WriteString("\n")
	b.WriteString(pad + boldStyle.Render("Output Order") + "\n\n")

	type option struct{ label, hint string }
	opts := []option{
		{"Leaf → Root", "Node.js · Nginx · Apache"},
		{"Root → Leaf", "Java · legacy servers"},
	}

	for i, opt := range opts {
		var row string
		if m.cursor == i {
			cursor := selectedStyle.Render("❯")
			label := optionLabelActive.Render(opt.label)
			hint := optionHintActive.Render("  " + opt.hint)
			row = cursor + "  " + label + hint
		} else {
			label := optionLabelIdle.Render(opt.label)
			hint := optionHintIdle.Render("  " + opt.hint)
			row = "   " + label + hint
		}
		b.WriteString(pad + "  " + row + "\n")
	}

	b.WriteString("\n" + lipgloss.NewStyle().MarginLeft(outerMargin).Render(m.help.View(analysisKeys)))
	return b.String()
}

// certPanel builds a single rounded-border panel for a certificate chain.
//
// outerWidth is the desired total width including borders and padding.
// The panel title and an optional styled badge (e.g. a warning) are rendered
// on the same line, followed by a thin divider, then the chain rows.
func certPanel(title, badge string, certs []CertNode, annotate, rootFirst bool, outerWidth int) string {
	const (
		borderCols  = 2 // 1 left + 1 right border character
		paddingCols = 2 // Padding(0,1) → 1 left + 1 right
	)
	contentW := outerWidth - borderCols - paddingCols
	if contentW < 10 {
		contentW = 10
	}

	// Title row: left-aligned title, badge appended (already styled by caller).
	titleRow := panelTitleStyle.Render(title) + badge
	divider := dimStyle.Render(strings.Repeat("─", contentW-4))

	// Chain lines without any outer indentation.
	chainLines := strings.Join(renderChainLines(certs, annotate, rootFirst), "\n")

	inner := titleRow + "\n" + divider + "\n" + chainLines

	return panelStyle.Width(contentW).Render(inner)
}

// renderChainLines returns the chain as a slice of display lines with no outer
// indentation. Callers that need indentation (e.g. the legacy viewPicking path)
// can prepend their own prefix.
//
// If annotate is true, semantic role labels ([leaf] / [intermediate] / [root])
// are shown; otherwise numeric positions ([1], [2] …).
//
// Column alignment is ANSI-escape-aware: lipgloss.Width is used for padding so
// styled labels never cause visible misalignment.
func renderChainLines(certs []CertNode, annotate, rootFirst bool) []string {
	type certRow struct {
		roleText     string // unstyled, for width measurement
		roleRendered string // ANSI-styled
		cn           string
	}
	type arrowRow struct{ issuerCN string }
	type row interface{}

	var rows []row
	for i, c := range certs {
		cn := CommonName(c.Subject)
		var roleText, roleRendered string
		if annotate {
			last := len(certs) - 1
			isLeaf := (!rootFirst && i == 0) || (rootFirst && i == last)
			isRoot := (!rootFirst && i == last && c.IsRoot) || (rootFirst && i == 0 && c.IsRoot)
			isMissingRoot := (!rootFirst && i == last && !c.IsRoot) || (rootFirst && i == 0 && !c.IsRoot)
			switch {
			case isLeaf:
				roleText = "[leaf]"
				roleRendered = leafStyle.Render(roleText)
			case isRoot:
				roleText = "[root]"
				roleRendered = rootCertStyle.Render(roleText)
			case isMissingRoot:
				roleText = "[?incomplete]"
				roleRendered = warnStyle.Render(roleText)
			default:
				roleText = "[intermediate]"
				roleRendered = interStyle.Render(roleText)
			}
		} else {
			roleText = fmt.Sprintf("[%d]", i+1)
			roleRendered = dimStyle.Render(roleText)
		}
		rows = append(rows, certRow{roleText: roleText, roleRendered: roleRendered, cn: cn})
		if i < len(certs)-1 {
			rows = append(rows, arrowRow{issuerCN: CommonName(c.Issuer)})
		}
	}

	// Find the widest plain role label to drive column alignment.
	maxRole := 0
	for _, r := range rows {
		if cr, ok := r.(certRow); ok && len(cr.roleText) > maxRole {
			maxRole = len(cr.roleText)
		}
	}

	var lines []string
	for _, r := range rows {
		switch v := r.(type) {
		case certRow:
			paddedRole := lipgloss.NewStyle().Width(maxRole).Render(v.roleRendered)
			lines = append(lines, paddedRole+"  "+v.cn)
		case arrowRow:
			indent := lipgloss.NewStyle().Width(maxRole + 2).Render("")
			lines = append(lines, indent+dimStyle.Render("↓ issuer: "+v.issuerCN))
		}
	}
	return lines
}

// reverseCerts returns a new slice with the elements in reverse order.
func reverseCerts(in []CertNode) []CertNode {
	out := make([]CertNode, len(in))
	for i, c := range in {
		out[len(in)-1-i] = c
	}
	return out
}

// renderChain is the original indented form, kept for compatibility with any
// callers outside viewAnalysis.
func renderChain(certs []CertNode, annotate bool) string {
	var b strings.Builder
	for _, line := range renderChainLines(certs, annotate, false) {
		b.WriteString("  " + line + "\n")
	}
	return b.String()
}

func (m model) viewDone() string {
	var b strings.Builder
	b.WriteString("\n  " + titleStyle.Render("🔐 CertFixer") + "\n\n")
	b.WriteString("  " + successStyle.Render("✓  Chain fixed successfully!") + "\n\n")
	b.WriteString("  Output:  " + m.outputPath + "\n")
	order := "leaf → root"
	if m.cursor == 1 {
		order = "root → leaf"
	}
	b.WriteString("  Order:   " + order + "\n")
	b.WriteString("  Certs:   " + fmt.Sprintf("%d", len(m.sorted)) + "\n")
	if !IsChainComplete(m.sorted) {
		b.WriteString("\n  " + warnStyle.Render("⚠  Note: chain may be incomplete — issuer not found for root cert") + "\n")
	}
	b.WriteString("\n" + lipgloss.NewStyle().MarginLeft(2).Render(m.help.View(doneKeys)))
	return b.String()
}

func buildOutputPath(input string) string {
	ext := filepath.Ext(input)
	base := strings.TrimSuffix(input, ext)
	return base + "_fixed" + ext
}

func main() {
	p := tea.NewProgram(newModel())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
