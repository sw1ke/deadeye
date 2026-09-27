package ui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"deadeye/internal/launch"
)

func (m *Model) launchAppsList() []launch.App {
	if m.launchAppsLoaded == nil {
		m.launchAppsLoaded = launch.InstalledApps()
	}
	return m.launchAppsLoaded
}

func (m *Model) launchInit() {
	if m.launchFiles == nil {
		m.launchFiles = launch.DefaultFiles()
		m.launchItems = launch.ReadEntries(m.launchFiles...)
	}
	m.launchAppsList()
}

func (m *Model) launchRefresh() {
	m.launchItems = launch.ReadEntries(m.launchFiles...)
}

type launchRow struct {
	app   *launch.App
	entry *launch.Entry
}

func (m *Model) launchRows() []launchRow {
	apps := m.launchAppsList()
	rows := make([]launchRow, 0, len(apps)+len(m.launchItems)+2)
	filter := strings.ToLower(strings.TrimSpace(m.launchFilter))
	for i := range apps {
		if filter != "" && !strings.Contains(strings.ToLower(apps[i].Name), filter) {
			continue
		}
		rows = append(rows, launchRow{app: &apps[i]})
	}
	for i := range m.launchItems {
		rows = append(rows, launchRow{entry: &m.launchItems[i]})
	}
	return rows
}

func (m *Model) renderLaunch(h int) string {
	inner := m.width - 4
	if inner < 24 {
		inner = 24
	}
	m.launchInit()

	var b strings.Builder
	b.WriteString(clipPad(headerStyle.Render("LAUNCH AND STARTUP")+dimStyle.Render("  ·  Enter — launch/toggle · a — add · r — refresh"), inner))
	b.WriteString("\n")

	rows := m.launchRows()
	appsN := len(m.launchAppsList())

	type row struct {
		text   string
		idx    int
		isItem bool
	}
	var lines []row
	appTitle := " INSTALLED APPS (Enter — launch, a — add to autostart, / — search)"
	if m.launchFilter != "" {
		appTitle += "  ·  filter: " + m.launchFilter
	}
	lines = append(lines, row{text: dimStyle.Render(appTitle)})
	for i := 0; i < appsN; i++ {
		lines = append(lines, row{text: "  ▶ " + rows[i].app.Name, idx: i, isItem: true})
	}
	lines = append(lines, row{text: dimStyle.Render(" STARTUP (Enter — on/off)")})
	for i := appsN; i < len(rows); i++ {
		e := rows[i].entry
		mark := okStyle.Render("✓")
		if !e.Enabled {
			mark = dimStyle.Render("✗")
		}
		file := e.File
		if idx := strings.LastIndex(file, "/"); idx >= 0 {
			file = file[idx+1:]
		}
		lines = append(lines, row{
			text:   " " + mark + " " + e.Command + dimStyle.Render("   ["+file+":"+fmt.Sprint(e.Line)+"]"),
			idx:    i,
			isItem: true,
		})
	}
	if len(m.launchItems) == 0 {
		lines = append(lines, row{text: dimStyle.Render("  no autostart files found: ~/.config/hypr/custom/execs.lua and ~/.config/hypr/hyprland.conf")})
	}

	bodyH := h - 1
	if m.launchScroll > len(lines)-bodyH {
		m.launchScroll = len(lines) - bodyH
	}
	if m.launchScroll < 0 {
		m.launchScroll = 0
	}
	end := m.launchScroll + bodyH
	if end > len(lines) {
		end = len(lines)
	}
	itemPos := 0
	for i := m.launchScroll; i < end; i++ {
		out := clipPad(lines[i].text, inner)
		if lines[i].isItem {
			if itemPos == m.launchCursor {
				out = selectedStyle.Render(out)
			}
			itemPos++
		}
		b.WriteString(out)
		b.WriteString("\n")
	}

	if m.launchInput {
		b.WriteString(accStyle.Render(clipTo(" autostart command:", inner)))
		b.WriteString("\n")
		b.WriteString(selectedStyle.Render(clipTo(" "+m.launchInputB+"▏", inner)))
		b.WriteString("\n")
		b.WriteString(dimStyle.Render(clipTo(" Enter — add to execs.lua · Esc — cancel", inner)))
		b.WriteString("\n")
	} else if m.launchMsg != "" {
		b.WriteString(dimStyle.Render(clipTo(" "+m.launchMsg, inner)))
		b.WriteString("\n")
	}
	return padToHeight(b.String(), h, m.width)
}

func (m *Model) handleLaunchKey(msg tea.KeyMsg) (tea.Cmd, bool) {
	m.launchInit()

	if m.launchFiltering {
		switch msg.String() {
		case "esc", "ctrl+c", "enter":
			m.launchFiltering = false
			m.launchCursor = 0
			return nil, true
		case "backspace":
			if r := []rune(m.launchFilter); len(r) > 0 {
				m.launchFilter = string(r[:len(r)-1])
			}
			return nil, true
		case "ctrl+u":
			m.launchFilter = ""
			return nil, true
		}
		if msg.Type == tea.KeyRunes {
			m.launchFilter += string(msg.Runes)
			return nil, true
		}
		return nil, true
	}
	if m.launchInput {
		switch msg.String() {
		case "esc", "ctrl+c":
			m.launchInput = false
			m.launchInputB = ""
			return nil, true
		case "enter":
			cmd := strings.TrimSpace(m.launchInputB)
			m.launchInput = false
			m.launchInputB = ""
			if cmd == "" {
				m.setStatus("empty command — cancelled", true, 3*time.Second)
				return nil, true
			}
			files := launch.DefaultFiles()
			if len(files) == 0 {
				m.setStatus("no autostart file (execs.lua or hyprland.conf)", true, 5*time.Second)
				return nil, true
			}
			if err := launch.Add(files[0], cmd); err != nil {
				m.setStatus("not added: "+err.Error(), true, 6*time.Second)
				return nil, true
			}
			m.launchRefresh()
			m.setStatus("added to autostart: "+cmd, false, 4*time.Second)
			return nil, true
		case "backspace":
			if r := []rune(m.launchInputB); len(r) > 0 {
				m.launchInputB = string(r[:len(r)-1])
			}
			return nil, true
		case "ctrl+u":
			m.launchInputB = ""
			return nil, true
		}
		if msg.Type == tea.KeyRunes {
			m.launchInputB += string(msg.Runes)
			return nil, true
		}
		return nil, true
	}

	switch msg.String() {
	case "up", "k":
		m.launchMove(-1)
		return nil, true
	case "down", "j":
		m.launchMove(1)
		return nil, true
	case "pgup", "ctrl+u":
		m.launchMove(-6)
		return nil, true
	case "pgdown", "ctrl+d":
		m.launchMove(6)
		return nil, true
	case "home", "g":
		m.launchCursor, m.launchScroll = 0, 0
		return nil, true
	case "end", "G":
		m.launchCursor = len(m.launchRows()) - 1
		if m.launchCursor < 0 {
			m.launchCursor = 0
		}

		m.launchScroll = len(m.launchRows()) + 100
		return nil, true
	case "enter", " ":
		rows := m.launchRows()
		if m.launchCursor < 0 || m.launchCursor >= len(rows) {
			return nil, true
		}
		r := rows[m.launchCursor]
		if r.app != nil {
			if err := launch.Launch(r.app.Exec); err != nil {
				m.setStatus("did not launch: "+err.Error(), true, 5*time.Second)
			} else {
				m.setStatus("launched: "+r.app.Name, false, 4*time.Second)
				m.launchMsg = "launched just now: " + r.app.Name + " (" + r.app.Exec + ")"
			}
			return nil, true
		}
		if r.entry != nil {
			if err := launch.Toggle(r.entry.File, r.entry.Line); err != nil {
				m.setStatus("not changed: "+err.Error(), true, 6*time.Second)
				return nil, true
			}
			m.launchRefresh()
			state := "enabled"
			if r.entry.Enabled {
				state = "disabled"
			}
			m.setStatus(state+": "+r.entry.Command, false, 4*time.Second)
			return nil, true
		}
	case "/", ".":
		m.launchFiltering = true
		m.launchFilter = ""
		return nil, true
	case "a":
		rows := m.launchRows()
		if m.launchCursor < 0 || m.launchCursor >= len(rows) {
			return nil, true
		}
		r := rows[m.launchCursor]
		if r.app == nil {
			m.setStatus("select an app above: a adds it to autostart", true, 5*time.Second)
			return nil, true
		}
		files := launch.DefaultFiles()
		if len(files) == 0 {
			m.setStatus("no autostart file (execs.lua or hyprland.conf)", true, 5*time.Second)
			return nil, true
		}
		if err := launch.Add(files[0], r.app.Exec); err != nil {
			m.setStatus("not added: "+err.Error(), true, 6*time.Second)
			return nil, true
		}
		m.launchRefresh()
		m.setStatus("added to autostart: "+r.app.Name, false, 4*time.Second)
		m.launchMsg = "startup: added " + r.app.Name + " (" + r.app.Exec + ")"
		return nil, true
	case "i":

		m.launchInput = true
		m.launchInputB = ""
		return nil, true
	case "r":
		m.launchRefresh()
		m.launchMsg = fmt.Sprintf("read %d autostart entries (%d files)",
			len(m.launchItems), len(m.launchFiles))
		return nil, true
	}
	return nil, false
}

func (m *Model) launchMove(delta int) {
	n := len(m.launchRows())
	if n == 0 {
		return
	}
	m.launchCursor += delta
	if m.launchCursor < 0 {
		m.launchCursor = 0
	}
	if m.launchCursor >= n {
		m.launchCursor = n - 1
	}
	if m.launchCursor < m.launchScroll {
		m.launchScroll = m.launchCursor
	}
}
