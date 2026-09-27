package ui

import (
	"fmt"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"deadeye/internal/human"
	"deadeye/internal/hung"
	"deadeye/internal/proc"
)

func (m *Model) refreshHung() {
	if m.hungTracker == nil {

		m.hungTracker = hung.NewTracker(m.cfg.HungRules())
	}
	m.hungItems = m.hungTracker.Update(m.procs, m.anoms, time.Now())
	m.hungFixCursor()
}

func (m *Model) hungFixCursor() {
	if len(m.hungItems) == 0 {
		m.hungCursor, m.hungScroll, m.hungSelectedPID = 0, 0, 0
		return
	}

	if m.hungSelectedPID > 0 {
		for i, it := range m.hungItems {
			if it.PID == m.hungSelectedPID {
				m.hungCursor = i
				m.hungScrollTo()
				return
			}
		}
	}
	if m.hungCursor >= len(m.hungItems) {
		m.hungCursor = len(m.hungItems) - 1
	}
	if m.hungCursor < 0 {
		m.hungCursor = 0
	}
	if it, ok := m.hungSelected(); ok {
		m.hungSelectedPID = it.PID
	}
	m.hungScrollTo()
}

func (m *Model) hungSelected() (hung.Item, bool) {
	if m.hungCursor < 0 || m.hungCursor >= len(m.hungItems) {
		return hung.Item{}, false
	}
	return m.hungItems[m.hungCursor], true
}

func (m *Model) hungMove(delta int) {
	if len(m.hungItems) == 0 {
		return
	}
	m.hungCursor += delta
	if m.hungCursor < 0 {
		m.hungCursor = 0
	}
	if m.hungCursor >= len(m.hungItems) {
		m.hungCursor = len(m.hungItems) - 1
	}
	if it, ok := m.hungSelected(); ok {
		m.hungSelectedPID = it.PID
		m.hungScrollTo()
	}
}

func (m *Model) hungScrollTo() {
	vis := m.hungVisible()
	if vis <= 0 {
		return
	}
	if m.hungCursor < m.hungScroll {
		m.hungScroll = m.hungCursor
	}
	if m.hungCursor >= m.hungScroll+vis {
		m.hungScroll = m.hungCursor - vis + 1
	}
	if m.hungScroll < 0 {
		m.hungScroll = 0
	}
}

func (m *Model) hungVisible() int {
	v := m.bodyHeight - 2 - 8
	if v < 1 {
		v = 1
	}
	return v
}

func (m *Model) renderHung(h int) string {
	inner := m.width - 4
	if inner < 24 {
		inner = 24
	}
	var b strings.Builder

	titleLine := headerStyle.Render(m.pane.title()) +
		dimStyle.Render("  ·  "+hung.Summarize(m.hungItems))
	b.WriteString(clipPad(titleLine, inner))
	b.WriteString("\n")

	if len(m.hungItems) == 0 {
		r := m.hungRules()
		for _, ln := range []string{
			"No stuck processes. This tab watches four states:",
			"",
			fmt.Sprintf("  D — waiting for I/O over %d s;", r.IOBlockSec),
			"  R — burning CPU without I/O (already confirmed by the anomaly detector);",
			fmt.Sprintf("  Z — zombie over %d s;", r.ZombieSec),
			fmt.Sprintf("  T — stopped by a signal over %d s.", r.StoppedSec),
			"",
			"The first snapshot after startup finds nothing: a state's duration",
			"cannot be measured until the process has been seen at least twice.",
			"",
			"Kernel threads ([kworker], [migration]) do not show up here: sleeping",
			"in the kernel is normal work for them, not a hang.",
		} {
			b.WriteString(dimStyle.Render(clipTo(" "+ln, inner)))
			b.WriteString("\n")
		}
		return padToHeight(b.String(), h, m.width)
	}

	w := hungWidthsFor(inner)
	b.WriteString(headerStyle.Render(hungHeader(w, inner)))
	b.WriteString("\n")

	vis := m.hungVisible()
	if m.hungScroll > len(m.hungItems)-vis {
		m.hungScroll = len(m.hungItems) - vis
	}
	if m.hungScroll < 0 {
		m.hungScroll = 0
	}
	end := m.hungScroll + vis
	if end > len(m.hungItems) {
		end = len(m.hungItems)
	}

	rowsOut := make([]string, 0, vis+1)
	for i := m.hungScroll; i < end; i++ {
		it := m.hungItems[i]
		line := clipTo(hungRow(it, w), inner)
		if i == m.hungCursor {
			rowsOut = append(rowsOut, selectedStyle.Render(line))
		} else {
			rowsOut = append(rowsOut, verdictStyle(it).Render(line))
		}
	}
	if len(m.hungItems) > end {
		rowsOut = append(rowsOut, dimStyle.Render(
			clipTo(fmt.Sprintf(" … %d more", len(m.hungItems)-end), inner)))
	}
	for _, r := range rowsOut {
		b.WriteString(clipPad(r, inner))
		b.WriteString("\n")
	}

	b.WriteString("\n")
	if it, ok := m.hungSelected(); ok {
		// Whatever is left after the list goes to the detail block; the
		// evidence lines are trimmed so nothing gets cut mid-line.
		budget := h - 3 - len(rowsOut)
		b.WriteString(m.renderHungDetail(it, inner, budget))
	}
	return padToHeight(b.String(), h, m.width)
}

func hungHeader(w hungWidths, inner int) string {
	parts := make([]string, 0, 7)
	add := func(width int, v string, right bool) {
		if width <= 0 {
			return
		}
		v = human.TruncateMiddle(v, width)
		if right {
			parts = append(parts, fmt.Sprintf("%*s", width, v))
			return
		}
		parts = append(parts, fmt.Sprintf("%-*s", width, v))
	}
	add(w.pid, "PID", false)
	add(w.state, "ST", false)
	add(w.since, "HOW LONG", true)
	add(w.cpu, "CPU", true)
	add(w.rss, "MEMORY", true)
	parts = addEnd(w.verdict, "VERDICT", parts)
	add(w.name, "PROCESS", false)
	return clipTo(" "+strings.Join(parts, " "), inner)
}

func addEnd(width int, v string, parts []string) []string {
	if width <= 0 {
		return parts
	}
	return append(parts, fmt.Sprintf("%-*s", width, human.Truncate(v, width)))
}

type hungWidths struct {
	pid, state, since, cpu, rss, verdict, name int
}

func hungWidthsFor(inner int) hungWidths {
	w := hungWidths{pid: 7, state: 3, since: 9, cpu: 6, rss: 9, verdict: 22, name: 20}
	switch {
	case inner >= 112:
	case inner >= 96:
		w.verdict = 16
	case inner >= 84:
		w.rss, w.verdict = 0, 16
	case inner >= 72:
		w.rss, w.verdict, w.since = 0, 12, 8
	case inner >= 56:
		w.rss, w.verdict, w.since, w.cpu = 0, 0, 8, 0
	default:
		w.pid, w.state, w.since, w.cpu, w.rss, w.verdict = 5, 0, 0, 0, 0, 0
	}
	shown := 1
	for _, c := range []int{w.state, w.since, w.cpu, w.rss, w.verdict} {
		if c > 0 {
			shown++
		}
	}

	w.name = inner - (w.pid + w.state + w.since + w.cpu + w.rss + w.verdict + shown + 2)
	if w.name < 8 {
		w.name = 8
	}
	return w
}

func hungRow(it hung.Item, w hungWidths) string {
	parts := make([]string, 0, 7)
	add := func(width int, v string, right bool) {
		if width <= 0 {
			return
		}
		v = human.TruncateMiddle(v, width)
		if right {
			parts = append(parts, fmt.Sprintf("%*s", width, v))
			return
		}
		parts = append(parts, fmt.Sprintf("%-*s", width, v))
	}
	add(w.pid, fmt.Sprint(it.PID), false)
	add(w.state, it.State, false)
	add(w.since, human.Duration(it.Since), true)
	add(w.cpu, fmt.Sprintf("%.0f%%", it.CPU), true)
	add(w.rss, human.Bytes(float64(it.RSSKiB)*1024), true)
	parts = addEnd(w.verdict, string(it.Verdict), parts)
	add(w.name, it.Title(), false)
	return " " + strings.Join(parts, " ")
}

func clipTo(s string, width int) string {
	if width <= 0 {
		return ""
	}
	return human.TruncateMiddle(s, width)
}

func verdictStyle(it hung.Item) lipgloss.Style {
	switch it.Verdict {
	case hung.VerdictCPUBurn:
		return rowBadStyle
	case hung.VerdictIOBlock, hung.VerdictZombie, hung.VerdictRealtime:
		return rowWarnStyle
	}
	return rowStyle
}

// renderHungDetail builds the block under the list. The budget is the number
// of lines available; title, action and the key hints always fit, the
// evidence lines are trimmed from the end when the terminal is short.
func (m *Model) renderHungDetail(it hung.Item, inner, budget int) string {
	if budget < 3 {
		budget = 3
	}
	fixed := 2 // title + key hints
	if it.Action != "" {
		fixed += 2 // blank line + action
	}
	if it.Protected {
		fixed++ // the red "protected" line
	}
	maxEv := budget - fixed
	if maxEv < 0 {
		maxEv = 0
	}
	ev := append([]string(nil), it.Evidence...)
	if it.Wchan != "" {
		ev = append(ev, "waiting in kernel: "+it.Wchan)
	}
	if it.Threads > 1 {
		ev = append(ev, fmt.Sprintf("threads: %d", it.Threads))
	}
	if len(ev) > maxEv {
		ev = ev[:maxEv]
	}

	var b strings.Builder
	title := fmt.Sprintf("PID %d · %s · %s", it.PID, it.Title(), it.Verdict)
	b.WriteString(titleStyle.Render(clipTo(title, inner)))
	b.WriteString("\n")

	for _, e := range ev {
		b.WriteString(dimStyle.Render(clipTo(" • "+e, inner)))
		b.WriteString("\n")
	}
	if it.Protected {
		b.WriteString(rowBadStyle.Render(clipTo(" • protected: "+it.Why, inner)))
		b.WriteString("\n")
	}
	if it.Action != "" {
		b.WriteString("\n")
		b.WriteString(accStyle.Render(clipTo(" → "+it.Action, inner)))
		b.WriteString("\n")
	}
	b.WriteString(dimStyle.Render(clipTo(
		" Enter — show in Processes · a — ask AI · c — SIGCONT · F9 — kill",
		inner)))
	b.WriteString("\n")
	return b.String()
}

func (m *Model) hungRules() hung.Rules {
	if m.hungTracker == nil {
		return m.cfg.HungRules()
	}
	return m.hungTracker.Rules()
}

func (m *Model) handleHungKey(msg tea.KeyMsg) (tea.Cmd, bool) {
	switch msg.String() {
	case "up", "k":
		m.hungMove(-1)
		return nil, true
	case "down", "j":
		m.hungMove(1)
		return nil, true
	case "pgup":
		m.hungMove(-m.hungVisible())
		return nil, true
	case "pgdown":
		m.hungMove(m.hungVisible())
		return nil, true
	case "g", "home":
		m.hungMove(-len(m.hungItems) - 1)
		return nil, true
	case "G", "end":
		m.hungMove(len(m.hungItems) + 1)
		return nil, true
	case "enter":
		return m.hungJump(), true
	case "c":
		return m.hungCont(), true
	case "a":
		if it, ok := m.hungSelected(); ok {
			return m.aiExplain(it.PID), true
		}
		m.setStatus("no process selected", true, 4*time.Second)
		return nil, true
	case "r":
		m.refreshHung()
		m.setStatus("recomputed: "+hung.Summarize(m.hungItems), false, 4*time.Second)
		return nil, true
	}
	return nil, false
}

func (m *Model) hungJump() tea.Cmd {
	it, ok := m.hungSelected()
	if !ok {
		m.setStatus("no process selected", true, 4*time.Second)
		return nil
	}
	m.setPane(paneProcesses)
	if !m.selectPID(it.PID) {

		anc := m.ancestorPIDs(it.PID)
		if len(anc) > 0 {
			for _, p := range anc {
				m.expanded[p] = true
			}
			m.recompute()
		}
		if !m.selectPID(it.PID) {
			m.setStatus(fmt.Sprintf("PID %d is gone from the list", it.PID), true, 5*time.Second)
			return nil
		}
	}
	m.setStatus(fmt.Sprintf("PID %d · %s · %s", it.PID, it.Title(), it.Verdict), false, 6*time.Second)
	return nil
}

func (m *Model) ancestorPIDs(pid int) []int {
	byPID := make(map[int]int, len(m.procs))
	for _, s := range m.procs {
		byPID[s.PID] = s.PPID
	}
	out := make([]int, 0, 4)
	seen := map[int]bool{pid: true}
	cur := pid
	for i := 0; i < 32; i++ {
		pp, ok := byPID[cur]
		if !ok || pp == 0 || seen[pp] {
			break
		}
		seen[pp] = true
		out = append(out, pp)
		cur = pp
	}
	return out
}

func (m *Model) hungCont() tea.Cmd {
	it, ok := m.hungSelected()
	if !ok {
		m.setStatus("no process selected", true, 4*time.Second)
		return nil
	}
	if it.State != proc.StateStopped && it.State != proc.StateTraced {
		m.setStatus(fmt.Sprintf(
			"PID %d is in state %s: SIGCONT not needed, the process is not stopped",
			it.PID, it.State), true, 6*time.Second)
		return nil
	}
	if it.PID == 1 {
		m.setStatus("PID 1 is protected: init cannot be touched from the TUI", true, 6*time.Second)
		return nil
	}
	pid, name := it.PID, it.Title()
	return func() tea.Msg {
		err := m.act.SendSignal(pid, syscall.SIGCONT, "resume a stopped process")
		return contMsg{pid: pid, name: name, err: err}
	}
}
