package ui

import (
	"strconv"

	"github.com/charmbracelet/lipgloss"
)

type pane int

const (
	paneProcesses pane = iota
	paneHung
	paneGraphs
	paneAI
	paneGroups
	paneSecurity
	paneSystem
	paneTerminal
	paneLog
	paneLaunch
	paneServers
	paneLast
)

func (p pane) digit() string {
	if p == paneLaunch {
		return "0"
	}
	if p == paneServers {
		return "Ins"
	}
	if p < 0 || p >= paneLast {
		return ""
	}
	return strconv.Itoa(int(p) + 1)
}

func (p pane) title() string {
	switch p {
	case paneProcesses:
		return "PROCESSES"
	case paneHung:
		return "STUCK AND BLOCKED"
	case paneGraphs:
		return "LOAD AND TRENDS"
	case paneAI:
		return "AI"
	case paneGroups:
		return "PROCESS GROUPS"
	case paneSecurity:
		return "SECURITY"
	case paneSystem:
		return "SYSTEM"
	case paneTerminal:
		return "TERMINAL"
	case paneLog:
		return "LOG"
	case paneLaunch:
		return "LAUNCH AND STARTUP"
	case paneServers:
		return "SERVERS"
	}
	return "?"
}

func (p pane) short() string {
	switch p {
	case paneProcesses:
		return "Processes"
	case paneHung:
		return "Stuck"
	case paneGraphs:
		return "Load"
	case paneAI:
		return "AI"
	case paneGroups:
		return "Groups"
	case paneSecurity:
		return "Security"
	case paneSystem:
		return "System"
	case paneTerminal:
		return "Terminal"
	case paneLog:
		return "Log"
	case paneLaunch:
		return "Launch"
	case paneServers:
		return "Servers"
	}
	return "?"
}

func (p pane) hint() string {
	switch p {
	case paneProcesses:
		return "process tree, Enter — branch"
	case paneHung:
		return "what is stuck, why, and what to do about it"
	case paneGraphs:
		return "CPU, memory graphs and trends of the selected process"
	case paneAI:
		return "local model explains the selected process"
	case paneGroups:
		return "process categories: terminate the whole group"
	case paneSecurity:
		return "what looks suspicious: processes, autostart, network"
	case paneSystem:
		return "services, network, power, users"
	case paneTerminal:
		return "root shell right inside the app"
	case paneLog:
		return "all actions and events with timestamps"
	case paneLaunch:
		return "launch a program or manage Hyprland autostart"
	case paneServers:
		return "servers: open the Marzban panel of the selected one"
	}
	return ""
}

func openTabs() []pane {
	return []pane{paneProcesses, paneHung, paneGraphs, paneAI, paneGroups,
		paneSecurity, paneSystem, paneTerminal, paneLog, paneLaunch, paneServers}
}

func (m *Model) switchPane(delta int) {
	tabs := openTabs()
	if len(tabs) == 0 {
		return
	}
	for i, p := range tabs {
		if p != m.pane {
			continue
		}
		m.setPane(tabs[(i+delta+len(tabs))%len(tabs)])
		return
	}
	m.setPane(tabs[0])
}

func (m *Model) setPane(p pane) {
	if p == m.pane {
		return
	}
	m.pane = p
	if p == paneTerminal {
		m.termStart()
	}
	m.clampScroll()
}

func paneByDigit(r string) (pane, bool) {
	for _, p := range openTabs() {
		if p.digit() == r {
			return p, true
		}
	}
	return paneProcesses, false
}

func (m *Model) renderTabBar() string {
	tabs := openTabs()
	parts := make([]string, 0, len(tabs)+1)
	for _, p := range tabs {
		label := " " + p.digit() + " " + p.short() + " "
		if p == m.pane {
			parts = append(parts, tabActiveStyle.Render(label))
		} else {
			parts = append(parts, tabIdleStyle.Render(label))
		}
	}
	bar := lipgloss.JoinHorizontal(lipgloss.Bottom, parts...)
	if h := m.pane.hint(); h != "" {
		with := lipgloss.JoinHorizontal(lipgloss.Bottom, bar, dimStyle.Render("   "+h))
		if lipgloss.Width(with) <= m.width {
			bar = with
		}
	}
	return clipPad(bar, m.width)
}
