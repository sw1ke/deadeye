package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"deadeye/internal/actions"
	"deadeye/internal/groups"
	"deadeye/internal/human"
	"deadeye/internal/proc"
)

type groupLine struct {
	group    groups.Group
	member   groups.Member
	isMember bool
}

type groupKill struct {
	kind    groups.Kind
	title   string
	danger  string
	targets []groups.Member
	skipped int
	procs   int

	yes     bool
	running bool
	done    int
	failed  int
	stage   string
	started time.Time
}

type groupKillMsg struct {
	kind   groups.Kind
	title  string
	done   int
	failed int
	procs  int
	errs   []string
}

type groupReniceMsg struct {
	title string
	delta int
	done  int
	fail  int
	last  string
}

func (m *Model) refreshGroups() {
	if m.groupCache == nil {
		m.groupCache = make(map[string]groups.Kind, 64)
	}
	if m.groupOpen == nil {
		m.groupOpen = make(map[groups.Kind]bool)
	}
	list := make([]proc.Snapshot, 0, len(m.procs))
	for _, s := range m.procs {
		list = append(list, s)
	}

	prot := groups.NewProtectionFor(m.selfPID(), list)
	m.groupList = groups.ClassifyCached(m.groupCache, list, prot)

	shown := make([]groups.Group, 0, len(m.groupList))
	for _, g := range m.groupList {
		shown = append(shown, g)
	}
	m.groupShown = shown
	m.rebuildGroupLines()
	if m.groupCursor >= len(m.groupLines) {
		m.groupCursor = len(m.groupLines) - 1
	}
	if m.groupCursor < 0 {
		m.groupCursor = 0
	}
}

func (m *Model) selfPID() int { return m.ownPID }

func (m *Model) rebuildGroupLines() {
	lines := make([]groupLine, 0, len(m.groupShown)+16)
	for _, g := range m.groupShown {
		lines = append(lines, groupLine{group: g})
		if !m.groupOpen[g.Kind] || g.Empty {
			continue
		}
		for _, mem := range g.Members {
			lines = append(lines, groupLine{group: g, member: mem, isMember: true})
		}
	}
	m.groupLines = lines
}

func (m *Model) selectedLine() (groupLine, bool) {
	if m.groupCursor < 0 || m.groupCursor >= len(m.groupLines) {
		return groupLine{}, false
	}
	return m.groupLines[m.groupCursor], true
}

func (m *Model) selectedGroup() (groups.Group, bool) {
	l, ok := m.selectedLine()
	if !ok {
		return groups.Group{}, false
	}
	return l.group, true
}

func (m *Model) groupRows() int {
	n := m.bodyHeight - 6
	if n < 1 {
		n = 1
	}
	return n
}

func (m *Model) moveGroupCursor(delta int) {
	m.groupCursor += delta
	if m.groupCursor < 0 {
		m.groupCursor = 0
	}
	if len(m.groupLines) > 0 && m.groupCursor >= len(m.groupLines) {
		m.groupCursor = len(m.groupLines) - 1
	}
	m.clampGroupScroll()
}

func (m *Model) clampGroupScroll() {
	rows := m.groupRows()
	if m.groupCursor < m.groupScroll {
		m.groupScroll = m.groupCursor
	}
	if m.groupCursor >= m.groupScroll+rows {
		m.groupScroll = m.groupCursor - rows + 1
	}
	if m.groupScroll < 0 {
		m.groupScroll = 0
	}
}

func (m *Model) toggleGroup() {
	l, ok := m.selectedLine()
	if !ok || l.isMember {
		if ok && l.isMember {
			m.setStatus("this is a process inside a group: Enter expands the members on the group header", false, 4*time.Second)
		}
		return
	}
	if l.group.Empty {
		m.setStatus("in group "+l.group.Title+"» has no processes right now", false, 3*time.Second)
		return
	}
	m.groupOpen[l.group.Kind] = !m.groupOpen[l.group.Kind]
	m.rebuildGroupLines()
	m.clampGroupScroll()
}

func (m *Model) renderGroups(h int) string {
	inner := m.width - 4
	if inner < 30 {
		inner = 30
	}

	const numW = 6 + 1 + 11 + 1 + 7 + 2

	actW := 30
	if inner < 100 {
		actW = 24
	}
	nameW := inner - numW - actW
	if nameW < 14 {
		nameW = 14
		actW = inner - numW - nameW
		if actW < 8 {
			actW = 8
		}
	}

	head := fmt.Sprintf(" %-*s %6s %11s %7s  %-*s",
		nameW, "GROUP", "PROC.", "MEMORY", "CPU%", actW, "WHAT YOU CAN DO")
	lines := []string{colHeadStyle.Render(clipPad(head, inner))}

	rows := h - 6
	if rows < 1 {
		rows = 1
	}
	if m.groupScroll >= len(m.groupLines) {
		m.groupScroll = 0
	}
	end := m.groupScroll + rows
	if end > len(m.groupLines) {
		end = len(m.groupLines)
	}

	for i := m.groupScroll; i < end; i++ {
		l := m.groupLines[i]
		var text string
		if l.isMember {
			text = m.formatMemberLine(l, inner, nameW, actW)
		} else {
			text = m.formatGroupLine(l.group, inner, nameW, actW)
		}
		if i == m.groupCursor {
			text = selectedStyle.Render(clipPad(text, inner))
		} else if !l.isMember && i%2 == 1 {
			text = groupShadeStyle.Render(clipPad(text, inner))
		}
		lines = append(lines, clipPad(text, inner))
	}
	for len(lines) < rows+1 {
		lines = append(lines, "")
	}

	bottom := m.groupBottomLine(inner)
	lines = append(lines, clipPad(bottom, inner))

	title := "PROCESS GROUPS  ·  Enter — members, F9 — kill group, x — renice"
	return panelBoxH(clipPad(headerStyle.Render(title), inner), strings.Join(lines, "\n"), m.width, h)
}

func (m *Model) formatGroupLine(g groups.Group, inner, nameW, actW int) string {
	chev := "  "
	switch {
	case g.Blocked:
		chev = "⛔"
	case g.Empty:
		chev = "· "
	case m.groupOpen[g.Kind]:
		chev = "▾ "
	default:
		chev = "▸ "
	}
	name := chev + " " + g.Title
	if g.Empty {
		name += " — no processes"
	} else if g.ProtectedCount > 0 && g.Killable > 0 {
		name += fmt.Sprintf(" (%d protected)", g.ProtectedCount)
	}

	actText := ""
	switch {
	case g.Empty:
		actText = "—"
	case g.Blocked:
		actText = "protected"
	case g.Killable == 0:
		actText = "all protected"
	default:
		actText = fmt.Sprintf("kill %s",
			human.Pluralf(g.Killable, "process", "processes", "processes"))
		if kp := g.KillProcs(); kp > g.Killable {
			actText = fmt.Sprintf("kill %d (%d with children)", g.Killable, kp)
		}
	}
	action := dimStyle.Render(clip(actText, actW))
	if !g.Empty && !g.Blocked && g.Killable > 0 {
		action = okStyle.Render(clip(actText, actW))
	}

	mem := human.FromKiB(float64(g.RSSKiB))
	cpu := human.Percent(g.CPUPercent)
	st := textStyle
	if g.Empty {
		st = dimStyle
	}
	return clipPad(st.Render(fmt.Sprintf("%-*s %6d %11s %7s  ", nameW, clip(name, nameW),
		g.Procs, mem, cpu))+action, inner)
}

func (m *Model) formatMemberLine(l groupLine, inner, nameW, actW int) string {
	mem := l.member

	pidW := 7
	userW := 9
	mnW := nameW - pidW - userW - 2
	if mnW < 8 {
		mnW = 8
	}
	tail := ""
	switch {
	case mem.Protected:
		tail = warnStyle.Render(clip("⛔ "+mem.Why, actW+18))
	case mem.Descendants > 0:
		tail = dimStyle.Render(clip(fmt.Sprintf("+%s",
			human.Pluralf(mem.Descendants, "descendant", "descendants", "descendants")), actW))
	}
	head := fmt.Sprintf("   %6d  %-*s %-*s %11s  ", mem.PID, mnW, clip(mem.Name, mnW),
		userW, clip(mem.User, userW), human.FromKiB(float64(mem.RSSKiB)))
	st := rowStyle
	if mem.Protected {
		st = rowDimStyle
	}
	return clipPad(st.Render(head)+tail, inner)
}

func (m *Model) groupBottomLine(inner int) string {
	total := 0
	killable := 0
	protected := 0
	for _, g := range m.groupShown {
		total += g.Procs
		killable += g.Killable
		protected += g.ProtectedCount
	}
	s := fmt.Sprintf("%s total in %d groups · %d killable · %d protected",
		human.Pluralf(total, "process", "processes", "processes"),
		len(m.groupShown), killable, protected)
	if g, ok := m.selectedGroup(); ok && !g.Empty {
		s += " · " + truncateWords(g.Purpose, 60)
	}
	return dimStyle.Render(clipPad(s, inner))
}

func (m *Model) openGroupKill() tea.Cmd {
	g, ok := m.selectedGroup()
	if !ok {
		m.setStatus("no group selected", true, 3*time.Second)
		return nil
	}
	if g.Empty {
		m.setStatus("in group "+g.Title+"» has no processes right now", false, 3*time.Second)
		return nil
	}
	if g.Blocked {
		m.setStatus("the group «"+g.Title+"» cannot be killed in one action: "+g.Danger, true, 8*time.Second)
		m.journal.Warnf("groups", 0, g.Title,
			"refused: the group is protected from a group kill (%s)", g.Danger)
		return nil
	}
	targets := g.Targets()
	if len(targets) == 0 {
		m.setStatus("in group "+g.Title+"» all processes are protected", true, 5*time.Second)
		return nil
	}

	procs := g.KillProcs()
	m.groupKill = &groupKill{
		kind:    g.Kind,
		title:   g.Title,
		danger:  g.Danger,
		targets: targets,
		skipped: g.ProtectedCount,
		procs:   procs,
		yes:     false,
	}
	return nil
}

func (m *Model) renderGroupKill(h int) string {
	g := m.groupKill
	inner := m.width - 8
	if inner < 30 {
		inner = 30
	}
	st := dialogStyle
	if g.running {
		st = boxActiveStyle
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s\n\n", badStyle.Render("KILL THE GROUP «"+strings.ToUpper(g.title)+"»?"))
	fmt.Fprintf(&b, "%s\n", dimStyle.Render("Will die: "+
		human.Pluralf(len(g.targets), "process", "processes", "processes")+
		fmt.Sprintf(" (%d with children), SIGTERM → wait → SIGKILL.", g.procs)))
	if g.skipped > 0 {
		fmt.Fprintf(&b, "%s\n", warnStyle.Render(fmt.Sprintf(
			"Skipped protected: %d — they will keep running.", g.skipped)))
	}
	if g.danger != "" {
		fmt.Fprintf(&b, "%s\n", warnStyle.Render("Consequences: "+g.danger))
	}
	b.WriteString("\n")

	listRows := h - 12
	if listRows < 3 {
		listRows = 3
	}
	shown := g.targets
	if len(shown) > listRows {
		shown = shown[:listRows]
	}
	for _, t := range shown {
		desc := ""
		if t.Descendants > 0 {
			desc = fmt.Sprintf(" +%d", t.Descendants)
		}
		fmt.Fprintf(&b, "  %6d  %-*s %-8s %9s%s\n", t.PID,
			maxInt(inner-40, 12), clip(t.Name, maxInt(inner-40, 12)),
			clip(t.User, 8), human.FromKiB(float64(t.RSSKiB)), desc)
	}
	if len(g.targets) > len(shown) {
		fmt.Fprintf(&b, "  %s\n", dimStyle.Render(fmt.Sprintf("…and %s more",
			human.Pluralf(len(g.targets)-len(shown), "process", "processes", "processes"))))
	}
	b.WriteString("\n")

	if g.running {
		fmt.Fprintf(&b, "%s\n", accStyle.Render(" killing: "+g.stage))
		fmt.Fprintf(&b, "%s\n", dimStyle.Render(fmt.Sprintf(
			" done %d, %d errors · the window will close by itself", g.done, g.failed)))
	} else {
		yes, no := "  kill the group  ", "  cancel (n)  "
		if g.yes {
			yes = selectedStyle.Render(yes)
		} else {
			no = selectedStyle.Render(no)
		}
		fmt.Fprintf(&b, "%s%s\n", yes, no)
		fmt.Fprintf(&b, "%s\n", dimStyle.Render(
			" ←/→ or Tab — choose, y — kill, n/Esc — cancel"))
	}

	body := clipPadWidth(b.String(), inner)
	lines := strings.Split(body, "\n")
	maxLines := h - 4
	if maxLines < 3 {
		maxLines = 3
	}
	if len(lines) > maxLines {
		lines = lines[:maxLines]
	}
	return st.Width(inner).Render(strings.Join(lines, "\n"))
}

func (m *Model) handleGroupKillKey(msg tea.Msg) (tea.Model, tea.Cmd) {
	g := m.groupKill
	if msg, ok := msg.(tea.KeyMsg); ok {
		if g.running {

			switch msg.String() {
			case "q", "ctrl+c":
				m.quitting = true
				return m, tea.Quit
			}
			return m, nil
		}
		switch msg.String() {
		case "left", "h", "tab", "shift+tab":
			g.yes = !g.yes
			return m, nil
		case "right", "l":
			g.yes = !g.yes
			return m, nil
		case "y", "Y", "enter":
			if !g.yes && msg.String() == "enter" {
				g.yes = true
				return m, nil
			}
			return m, m.confirmGroupKill()
		case "n", "N", "esc":
			m.groupKill = nil
			m.setStatus("group kill cancelled", false, 4*time.Second)
			m.journal.Actionf("groups", 0, g.title, "group kill cancelled in the confirmation dialog")
			return m, nil
		}
		return m, nil
	}
	return m, nil
}

func (m *Model) handleGroupsKey(msg tea.Msg) (tea.Cmd, bool) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return nil, false
	}
	rows := m.groupRows()
	switch key.String() {
	case "enter", " ", "space":
		m.toggleGroup()
		return nil, true
	case "f9", "y", "Y":
		return m.openGroupKill(), true
	case "x":
		return m.groupReniceCmd(m.act.ReniceStep()), true
	case "X":
		return m.groupReniceCmd(-m.act.ReniceStep()), true
	case "g":
		m.groupCursor = 0
		m.clampGroupScroll()
		return nil, true
	case "G":
		m.groupCursor = len(m.groupLines) - 1
		m.clampGroupScroll()
		return nil, true
	case "pgup", "ctrl+u":
		m.moveGroupCursor(-rows)
		return nil, true
	case "pgdown", "ctrl+d":
		m.moveGroupCursor(rows)
		return nil, true
	case "home":
		m.groupCursor = 0
		m.clampGroupScroll()
		return nil, true
	case "end":
		m.groupCursor = len(m.groupLines) - 1
		m.clampGroupScroll()
		return nil, true
	}
	return nil, false
}

func clipPadWidth(s string, width int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = clipPad(l, width)
	}
	return strings.Join(lines, "\n")
}

func (m *Model) confirmGroupKill() tea.Cmd {
	g := m.groupKill
	if g == nil || g.running {
		return nil
	}
	g.running = true
	g.started = time.Now()
	g.stage = "SIGTERM"

	targets := make([]groups.Member, len(g.targets))
	copy(targets, g.targets)
	title, kind := g.title, g.kind
	act := m.act
	p := m.program

	m.journal.Actionf("groups", 0, title,
		"group kill: %d targets (%d processes with children), skipped protected %d",
		len(targets), g.procs, g.skipped)

	return func() tea.Msg {
		res := groupKillMsg{kind: kind, title: title}
		for i, t := range targets {
			if p != nil {
				p.Send(groupStageMsg(fmt.Sprintf("%d/%d %s (PID %d)",
					i+1, len(targets), t.Name, t.PID)))
			}
			opts := act.DefaultKillOptions()
			opts.Scope = actions.ScopeTree
			opts.ExpectStart = t.StartTime
			rep, err := act.SmartKill(context.Background(), t.PID, opts, nil)
			if err != nil {
				res.failed++
				if len(res.errs) < 5 {
					res.errs = append(res.errs, fmt.Sprintf("PID %d %s: %v", t.PID, t.Name, err))
				}
				continue
			}
			res.done++
			res.procs += rep.Targets
		}
		return res
	}
}

type groupStageMsg string

func (m *Model) groupReniceCmd(delta int) tea.Cmd {
	g, ok := m.selectedGroup()
	if !ok || g.Empty {
		m.setStatus("no group selected", true, 3*time.Second)
		return nil
	}
	if g.Blocked {
		m.setStatus("a system group's priority cannot be changed in one action", true, 5*time.Second)
		return nil
	}
	targets := g.Targets()
	if len(targets) == 0 {
		m.setStatus("the group has no processes whose priority can be changed", true, 4*time.Second)
		return nil
	}
	title := g.Title
	act := m.act
	m.journal.Actionf("groups", 0, title, "group renice %+d for %d processes",
		delta, len(targets))
	return func() tea.Msg {
		res := groupReniceMsg{title: title, delta: delta}
		for _, t := range targets {
			_, _, err := act.ReniceChecked(t.PID, delta, t.StartTime)
			if err != nil {
				res.fail++
				res.last = err.Error()
				continue
			}
			res.done++
		}
		return res
	}
}
