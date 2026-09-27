package ui

import (
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"deadeye/internal/terminal"
)

func (m *Model) termStart() {
	if m.term != nil {
		return
	}
	cols := m.width - 4
	if cols < 20 {
		cols = 20
	}
	rows := m.bodyHeight - 2
	if rows < 4 {
		rows = 4
	}
	t, err := terminal.New(terminal.ShellArgs(), cols, rows)
	if err != nil {
		m.termErr = "could not start the shell: " + err.Error()
		return
	}
	m.term = t
	m.termErr = ""
}

func (m *Model) termStop() {
	if m.term != nil {
		m.term.Close()
		m.term = nil
	}
}

func (m *Model) renderTerm(h int) string {
	inner := m.width - 4
	if inner < 20 {
		inner = 20
	}
	m.termStart()

	var b strings.Builder
	b.WriteString(clipPad(headerStyle.Render("TERMINAL")+dimStyle.Render("  ·  bash shell · Esc / Ctrl+Q to detach"), inner))
	b.WriteString("\n")
	b.WriteString(clipPad(dimStyle.Render(" a real shell: commands run right here"), inner))
	b.WriteString("\n")

	if m.termErr != "" {
		b.WriteString(badStyle.Render(clipPad(" "+m.termErr, inner)))
		b.WriteString("\n")
	} else if m.term != nil {
		lines := m.term.Lines()

		bodyH := h - 2
		if len(lines) > bodyH {
			lines = lines[len(lines)-bodyH:]
		}
		for _, ln := range lines {
			b.WriteString(clipPad(ln, inner))
			b.WriteString("\n")
		}
	}
	return padToHeight(b.String(), h, m.width)
}

func (m *Model) handleTermKey(msg tea.KeyMsg) (tea.Cmd, bool) {
	m.termStart()
	if m.term == nil {
		return nil, true
	}

	if msg.Type == tea.KeyEsc || msg.String() == "ctrl+q" {
		m.setPane(paneProcesses)
		return nil, true
	}

	if msg.String() == "tab" {
		m.switchPane(+1)
		return nil, true
	}
	if msg.String() == "shift+tab" {
		m.switchPane(-1)
		return nil, true
	}

	if data := keyMsgToBytes(msg); len(data) > 0 {
		if err := m.term.Write(data); err != nil {
			m.setStatus("shell exited: "+err.Error(), true, 5*time.Second)
		}
	}
	return nil, true
}

func keyMsgToBytes(msg tea.KeyMsg) []byte {
	if msg.Type == tea.KeyRunes {
		return []byte(string(msg.Runes))
	}
	switch msg.Type {
	case tea.KeyEnter:
		return []byte("\r")
	case tea.KeyBackspace:
		return []byte("\x7f")
	case tea.KeyTab:
		return []byte("\t")
	case tea.KeySpace:
		return []byte(" ")
	case tea.KeyUp:
		return []byte("\x1b[A")
	case tea.KeyDown:
		return []byte("\x1b[B")
	case tea.KeyRight:
		return []byte("\x1b[C")
	case tea.KeyLeft:
		return []byte("\x1b[D")
	case tea.KeyHome:
		return []byte("\x1b[H")
	case tea.KeyEnd:
		return []byte("\x1b[F")
	case tea.KeyDelete:
		return []byte("\x1b[3~")
	case tea.KeyPgUp:
		return []byte("\x1b[5~")
	case tea.KeyPgDown:
		return []byte("\x1b[6~")
	case tea.KeyCtrlA:
		return []byte("\x01")
	case tea.KeyCtrlB:
		return []byte("\x02")
	case tea.KeyCtrlC:
		return []byte("\x03")
	case tea.KeyCtrlD:
		return []byte("\x04")
	case tea.KeyCtrlE:
		return []byte("\x05")
	case tea.KeyCtrlK:
		return []byte("\x0b")
	case tea.KeyCtrlL:
		return []byte("\x0c")
	case tea.KeyCtrlU:
		return []byte("\x15")
	case tea.KeyCtrlW:
		return []byte("\x17")
	}
	return nil
}

func (m *Model) termRead() tea.Cmd {
	if m.term == nil {
		return nil
	}
	return func() tea.Msg {
		buf := make([]byte, 4096)
		_, err := m.term.Read(buf)
		if err != nil {
			return termClosedMsg{err: err}
		}
		return termOutputMsg{}
	}
}

type termOutputMsg struct{}

type termClosedMsg struct{ err error }

type termResizeMsg struct{}

func (m *Model) termResize() {
	if m.term != nil {
		cols := m.width - 4
		if cols < 20 {
			cols = 20
		}
		rows := m.bodyHeight - 2
		if rows < 4 {
			rows = 4
		}
		m.term.Resize(cols, rows)
	}
}
