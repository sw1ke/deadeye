package ui

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"deadeye/internal/launch"
	"deadeye/internal/servers"
)

func (m *Model) srvInit() {
	if m.srvLoaded {
		return
	}
	m.srvLoaded = true
	m.srvList = servers.Load()
	if m.srvTunnels == nil {
		m.srvTunnels = map[string]*servers.Tunnel{}
	}
}

func (m *Model) srvRefresh() {
	m.srvList = servers.Load()
	m.srvLoaded = true
}

// srvStep — which input is currently going on when adding a server:
// 1 user@host, 2 password, 3 panel port.
func (m *Model) srvStepTitle() string {
	switch m.srvStep {
	case 2:
		return "SSH password (not shown):"
	case 3:
		return "Marzban panel port (Enter — 8000):"
	default:
		return "server: user@host"
	}
}

func (m *Model) renderServers(h int) string {
	inner := m.width - 4
	if inner < 24 {
		inner = 24
	}
	m.srvInit()

	var b strings.Builder
	b.WriteString(clipPad(headerStyle.Render("SERVERS")+dimStyle.Render("  ·  Enter — SSH + open the panel · a — add · c — close the tunnel · d — delete"), inner))
	b.WriteString("\n")

	if len(m.srvList) == 0 {
		b.WriteString(dimStyle.Render(clipTo(" List is empty. Press a: server, SSH password, panel port — the program will then bring up the tunnel and open Marzban by itself.", inner)))
		b.WriteString("\n")
	} else {
		bodyH := h - 2
		if m.srvScroll > len(m.srvList)-bodyH {
			m.srvScroll = len(m.srvList) - bodyH
		}
		if m.srvScroll < 0 {
			m.srvScroll = 0
		}
		end := m.srvScroll + bodyH
		if end > len(m.srvList) {
			end = len(m.srvList)
		}
		for i := m.srvScroll; i < end; i++ {
			s := m.srvList[i]
			state := dimStyle.Render("· no tunnel")
			if t, ok := m.srvTunnels[s.Name]; ok && t != nil {
				state = okStyle.Render("· tunnel: " + t.PanelURL())
			}
			out := clipPad(fmt.Sprintf(" ▶ %s   %s@%s:%d   %s",
				s.Name, s.User, s.Host, s.PanelPort, state), inner)
			if i == m.srvCursor {
				out = selectedStyle.Render(out)
			}
			b.WriteString(out)
			b.WriteString("\n")
		}
	}

	if m.srvInput {
		b.WriteString(accStyle.Render(clipTo(" "+m.srvStepTitle(), inner)))
		b.WriteString("\n")
		shown := m.srvInputB
		if m.srvStep == 2 {
			shown = strings.Repeat("•", len([]rune(m.srvInputB)))
		}
		b.WriteString(selectedStyle.Render(clipTo(" "+shown+"▏", inner)))
		b.WriteString("\n")
		b.WriteString(dimStyle.Render(clipTo(" Enter — next · Esc — cancel", inner)))
		b.WriteString("\n")
	} else if m.srvMsg != "" {
		b.WriteString(dimStyle.Render(clipTo(" "+m.srvMsg, inner)))
		b.WriteString("\n")
	}
	return padToHeight(b.String(), h, m.width)
}

func (m *Model) handleSrvKey(msg tea.KeyMsg) (tea.Cmd, bool) {
	m.srvInit()
	if m.srvInput {
		switch msg.String() {
		case "esc", "ctrl+c":
			m.srvInput = false
			m.srvInputB = ""
			m.srvStep = 0
			return nil, true
		case "enter":
			switch m.srvStep {
			case 1:
				user, host := servers.SplitUserHost(strings.TrimSpace(m.srvInputB))
				if host == "" {
					m.setStatus("an address like user@host is required", true, 4*time.Second)
					return nil, true
				}
				m.srvDraft = servers.Server{Name: host, User: user, Host: host}
				m.srvStep = 2
				m.srvInputB = ""
				return nil, true
			case 2:
				m.srvDraft.Password = m.srvInputB
				m.srvStep = 3
				m.srvInputB = ""
				return nil, true
			default:
				port := 8000
				if v, err := strconv.Atoi(strings.TrimSpace(m.srvInputB)); err == nil && v > 0 && v < 65536 {
					port = v
				}
				m.srvDraft.PanelPort = port
				m.srvList = append(m.srvList, m.srvDraft)
				if err := servers.Save(m.srvList); err != nil {
					m.setStatus("not saved: "+err.Error(), true, 5*time.Second)
				} else {
					m.srvCursor = len(m.srvList) - 1
					m.srvMsg = "added: " + m.srvDraft.Name + " (" + m.srvDraft.User + "@" + m.srvDraft.Host + ")"
				}
				m.srvInput = false
				m.srvInputB = ""
				m.srvStep = 0
				return nil, true
			}
		case "backspace":
			if r := []rune(m.srvInputB); len(r) > 0 {
				m.srvInputB = string(r[:len(r)-1])
			}
			return nil, true
		case "ctrl+u":
			m.srvInputB = ""
			return nil, true
		}
		if msg.Type == tea.KeyRunes {
			m.srvInputB += string(msg.Runes)
			return nil, true
		}
		return nil, true
	}

	switch msg.String() {
	case "up", "k":
		m.srvMove(-1)
		return nil, true
	case "down", "j":
		m.srvMove(1)
		return nil, true
	case "home", "g":
		m.srvCursor, m.srvScroll = 0, 0
		return nil, true
	case "end", "G":
		m.srvCursor = len(m.srvList) - 1
		if m.srvCursor < 0 {
			m.srvCursor = 0
		}
		return nil, true
	case "enter":
		if m.srvCursor < 0 || m.srvCursor >= len(m.srvList) {
			return nil, true
		}
		return m.srvOpen(m.srvList[m.srvCursor]), true
	case "c":
		if m.srvCursor < 0 || m.srvCursor >= len(m.srvList) {
			return nil, true
		}
		name := m.srvList[m.srvCursor].Name
		if t, ok := m.srvTunnels[name]; ok && t != nil {
			t.Close()
			delete(m.srvTunnels, name)
			m.srvMsg = "tunnel closed: " + name
		} else {
			m.srvMsg = "no tunnel: " + name
		}
		return nil, true
	case "a":
		m.srvInput = true
		m.srvInputB = ""
		m.srvStep = 1
		return nil, true
	case "d":
		if m.srvCursor < 0 || m.srvCursor >= len(m.srvList) {
			return nil, true
		}
		removed := m.srvList[m.srvCursor]
		if t, ok := m.srvTunnels[removed.Name]; ok && t != nil {
			t.Close()
			delete(m.srvTunnels, removed.Name)
		}
		m.srvList = append(m.srvList[:m.srvCursor], m.srvList[m.srvCursor+1:]...)
		if err := servers.Save(m.srvList); err != nil {
			m.setStatus("not saved: "+err.Error(), true, 5*time.Second)
			return nil, true
		}
		if m.srvCursor >= len(m.srvList) {
			m.srvCursor = len(m.srvList) - 1
		}
		m.srvMsg = "deleted: " + removed.Name
		return nil, true
	case "r":
		m.srvRefresh()
		m.srvMsg = fmt.Sprintf("servers: %d", len(m.srvList))
		return nil, true
	}
	return nil, false
}

// srvOpen brings up an SSH tunnel in the background and opens the panel in
// the browser.
func (m *Model) srvOpen(s servers.Server) tea.Cmd {
	m.srvBusy = true
	m.srvMsg = "connecting over SSH to " + s.User + "@" + s.Host + "…"
	return func() tea.Msg {
		t, err := servers.OpenTunnel(s, 12*time.Second)
		return srvTunnelMsg{name: s.Name, t: t, err: err}
	}
}

type srvTunnelMsg struct {
	name string
	t    *servers.Tunnel
	err  error
}

func (m *Model) srvTunnelOpened(msg srvTunnelMsg) tea.Cmd {
	m.srvBusy = false
	if msg.err != nil {
		m.srvMsg = "SSH failed: " + msg.err.Error()
		m.setStatus("the connection failed: "+msg.err.Error(), true, 8*time.Second)
		return nil
	}
	m.srvTunnels[msg.name] = msg.t
	url := msg.t.PanelURL()
	m.srvMsg = "panel: " + url + "  (c — close the tunnel)"
	m.setStatus("Marzban opened: "+url, false, 6*time.Second)
	if err := launch.Launch("xdg-open " + url); err != nil {
		m.setStatus("the browser did not open: "+err.Error(), true, 6*time.Second)
	}
	return nil
}

func (m *Model) srvCloseAll() {
	for _, t := range m.srvTunnels {
		if t != nil {
			t.Close()
		}
	}
	m.srvTunnels = map[string]*servers.Tunnel{}
}

func (m *Model) srvMove(delta int) {
	if len(m.srvList) == 0 {
		return
	}
	m.srvCursor += delta
	if m.srvCursor < 0 {
		m.srvCursor = 0
	}
	if m.srvCursor >= len(m.srvList) {
		m.srvCursor = len(m.srvList) - 1
	}
	if m.srvCursor < m.srvScroll {
		m.srvScroll = m.srvCursor
	}
}
