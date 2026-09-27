package ui

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"

	"deadeye/internal/actions"
	"deadeye/internal/anomaly"
	"deadeye/internal/human"
	"deadeye/internal/proc"
)

func (m *Model) View() string {
	if m.fatalErr != nil && len(m.procs) == 0 {
		return badStyle.Render("Deadeye: metrics collector is broken: " + m.fatalErr.Error())
	}
	if !m.ready {
		return dimStyle.Render("Deadeye: terminal too small (need at least 60×12) or size not received yet…")
	}

	header := m.renderHeader()
	tabbar := m.renderTabBar()
	summary := m.renderSummary()
	footer := m.renderFooter()

	chrome := lipgloss.Height(header) + lipgloss.Height(tabbar) +
		lipgloss.Height(summary) + lipgloss.Height(footer)
	body := m.height - chrome
	if body < 5 {
		body = 5
	}
	m.bodyHeight = body

	m.tableTop = lipgloss.Height(header) + lipgloss.Height(tabbar) + lipgloss.Height(summary) + 3

	var main string
	switch {
	case m.groupKill != nil:
		main = m.renderGroupKill(body)
	case m.confirm != nil:
		main = m.renderConfirm(body)
	case m.showHelp:
		main = m.renderHelp(body)
	case m.pane == paneProcesses:
		main = m.renderTable(body)
	case m.pane == paneHung:
		main = m.renderHung(body)
	case m.pane == paneSecurity:
		main = m.renderSec(body)
	case m.pane == paneSystem:
		main = m.renderSys(body)
	case m.pane == paneTerminal:
		main = m.renderTerm(body)
	case m.pane == paneLaunch:
		main = m.renderLaunch(body)
	case m.pane == paneServers:
		main = m.renderServers(body)
	case m.pane == paneGroups:
		main = m.renderGroups(body)
	case m.pane == paneAI:
		main = m.renderAI(body)
	case m.pane == paneLog:
		main = m.renderLog(body)
	default:
		main = m.renderGraphs(body)
	}

	// No pane may render more lines than its body: cut the excess, otherwise
	// the footer and the last rows would spill past the terminal height.
	main = padToHeight(main, body, m.width)

	view := lipgloss.JoinVertical(lipgloss.Left, header, tabbar, summary, main, footer)
	view = lipgloss.NewStyle().MaxHeight(m.height).MaxWidth(m.width).Render(view)
	return padToHeight(view, m.height, m.width)
}

// nyanFrames is the tiny nyancat: ears, face (blinks) and legs (running).
// Every row is exactly 8 columns wide so the sprite stays steady.
var nyanFrames = [4][3]string{
	{` /\_/\  `, `( 0.0 ) `, `  > v < `},
	{` /\_/\  `, `( 0.0 ) `, `  >v<   `},
	{` /\_/\  `, `( -.- ) `, `  > v < `},
	{` /\_/\  `, `( 0.0 ) `, `  > v<  `},
}

var nyanRainbow = []string{"196", "208", "226", "46", "27", "129"}

// nyanTrail renders the scrolling rainbow behind the cat.
func nyanTrail(frame int) string {
	var b strings.Builder
	for i := range nyanRainbow {
		c := nyanRainbow[(i+frame)%len(nyanRainbow)]
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color(c)).Render("▀"))
	}
	return b.String()
}

func (m *Model) renderHeader() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "localhost"
	}
	title := " Deadeye v" + m.version

	info := fmt.Sprintf("  %s · up %s · snaps %d · every %s · CLK_TCK %d · UID %d",
		host, human.Duration(m.sys.Uptime), m.mon.Samples(),
		m.mon.Options().Interval, proc.ClkTck(), m.ownUID)
	if err := m.mon.LastError(); err != nil {
		info += "  ⚠ " + clip(err.Error(), 40)
	}

	left := titleStyle.Render(title)
	right := dimStyle.Render(info)

	const catW = 14 // sprite (8) + rainbow trail (6)
	if m.width >= 88 && m.height >= 16 {
		f := m.nyanFrame % len(nyanFrames)
		cat := nyanFrames[f]
		catX := (m.width - catW) / 2
		if catX >= lipgloss.Width(left)+1 && catX+catW+8 <= m.width {
			row0 := left + strings.Repeat(" ", catX-lipgloss.Width(left)) +
				catStyle.Render(cat[0]) + strings.Repeat(" ", m.width-catX-8)
			row1 := strings.Repeat(" ", catX) +
				catStyle.Render(cat[1]) + nyanTrail(f) +
				strings.Repeat(" ", m.width-catX-catW)
			infoW := m.width - catX - catW - 1
			row2 := strings.Repeat(" ", catX) + catStyle.Render(cat[2]) + " " +
				clipPad(right, infoW)
			return row0 + "\n" + row1 + "\n" + row2
		}
	}

	return clipPad(lipgloss.JoinHorizontal(lipgloss.Top, left, right), m.width)
}

func (m *Model) renderSummary() string {
	sys := m.sys
	sep := dimStyle.Render("  │  ")

	barW := 16
	if m.width < 110 {
		barW = 10
	}
	if m.width < 84 {
		barW = 6
	}

	cpuPct := sys.CPUPercent
	memPct := sys.MemPercent()
	swapPct := sys.SwapPercent()

	cpuPart := keyValue("CPU", human.Percent(cpuPct), cpuColor(cpuPct)) +
		" " + bar(cpuPct/100, barW, cpuColor(cpuPct))

	memPart := keyValue("MEM", human.FromKiB(float64(sys.MemUsedKiB()))+"/"+human.FromKiB(float64(sys.MemTotalKiB)),
		memColor(memPct)) + " " + bar(memPct/100, barW, memColor(memPct)) +
		dimStyle.Render(" "+human.Percent(memPct))

	freeCol := lipgloss.TerminalColor(cOK)
	if sys.MemAvailableKiB < 512*1024 {
		freeCol = cWarn
	}
	freePart := keyValue("FREE", human.FromKiB(float64(sys.MemAvailableKiB)), freeCol)

	swapCol := lipgloss.TerminalColor(cDim)
	if swapPct > 0 {
		swapCol = memColor(swapPct)
	}
	swapPart := keyValue("SWAP", human.FromKiB(float64(sys.SwapUsedKiB())), swapCol)

	loadCol := lipgloss.TerminalColor(cOK)
	switch {
	case sys.LoadPerCore() > 1.5:
		loadCol = cBad
	case sys.LoadPerCore() > 0.8:
		loadCol = cWarn
	}
	loadPart := keyValue("LOAD", fmt.Sprintf("%.2f %.2f %.2f", sys.Load1, sys.Load5, sys.Load15), loadCol)

	states := make(map[string]int, 8)
	for _, s := range m.procs {
		states[s.State]++
	}
	procPart := keyValue("PROCESSES", human.Count(len(m.procs)), cText) +
		dimStyle.Render(fmt.Sprintf(" (R %d · D %d · S %d · Z %d · in D-state I/O %d)",
			states[proc.StateRunning], states[proc.StateDiskSleep],
			states[proc.StateSleeping], states[proc.StateZombie], sys.ProcsBlocked))

	anomText := "none"
	anomCol := lipgloss.TerminalColor(cOK)
	if len(m.anoms) > 0 {
		byKind := make(map[anomaly.Kind]int, 5)
		maxSev := 0.0
		for _, a := range m.anoms {
			byKind[a.Kind]++
			if a.Severity > maxSev {
				maxSev = a.Severity
			}
		}
		parts := make([]string, 0, len(byKind))
		for _, k := range anomaly.AllKinds() {
			if n := byKind[k]; n > 0 {
				parts = append(parts, fmt.Sprintf("%s %d", k.Title(), n))
			}
		}
		anomText = strings.Join(parts, ", ")
		anomCol = severityColor(maxSev)
	}
	anomPart := keyValue("ANOMALIES", strconv.Itoa(len(m.anoms)), anomCol) + dimStyle.Render("  "+anomText)

	inner := m.width - 4
	if inner < 20 {
		inner = 20
	}

	line1 := fitLine([]string{cpuPart, memPart, freePart, swapPart, loadPart}, sep, inner)

	parts2 := []string{procPart, anomPart}
	if len(sys.PerCore) > 0 && len(sys.PerCore) <= 64 {
		var b strings.Builder
		b.WriteString(dimStyle.Render("CORES "))
		for _, p := range sys.PerCore {
			b.WriteString(lipgloss.NewStyle().Foreground(cpuColor(p)).Render(coreBar(p)))
		}
		parts2 = append(parts2, b.String())
	}
	line2 := fitLine(parts2, sep, inner)

	return boxStyle.Width(inner + 2).Render(padLines(line1+"\n"+line2, inner))
}

func fitLine(parts []string, sep string, width int) string {
	if len(parts) == 0 {
		return ""
	}
	sepW := lipgloss.Width(sep)
	for len(parts) > 1 {
		total := sepW * (len(parts) - 1)
		for _, p := range parts {
			total += lipgloss.Width(p)
		}
		if total <= width {
			break
		}
		parts = parts[:len(parts)-1]
	}
	out := strings.Join(parts, sep)
	if lipgloss.Width(out) > width {
		out = clipPad(out, width)
	}
	return out
}

var coreGlyphs = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

func coreBar(pct float64) string {
	idx := int(pct / 100 * float64(len(coreGlyphs)-1))
	if idx < 0 {
		idx = 0
	}
	if idx >= len(coreGlyphs) {
		idx = len(coreGlyphs) - 1
	}
	return string(coreGlyphs[idx])
}

type colSpec struct {
	title    string
	width    int
	right    bool
	optional bool
	key      sortKey
	value    func(proc.Snapshot, *Model) string

	rowValue func(row, *Model) string

	fitPrefix bool
}

func (m *Model) buildColumns(avail int) []colSpec {
	nameW := 22
	if m.showCmdline {
		nameW = 44
	}
	if nameW > avail/2 {
		nameW = maxInt(avail/2, 8)
	}

	cols := []colSpec{
		{title: "PID", width: 7, right: true, key: sortPID,
			value: func(s proc.Snapshot, _ *Model) string { return strconv.Itoa(s.PID) }},
		{title: "PPID", width: 7, right: true, optional: true,
			value: func(s proc.Snapshot, _ *Model) string { return strconv.Itoa(s.PPID) }},
		{title: "USER", width: 10, optional: true, key: sortUser,
			value: func(s proc.Snapshot, _ *Model) string { return s.User }},
		{title: "NAME", width: nameW, key: sortName, fitPrefix: true,
			value: func(s proc.Snapshot, m *Model) string {
				if m.showCmdline {
					return s.Cmdline
				}
				return s.DisplayName()
			},
			rowValue: func(r row, m *Model) string {
				if m.showCmdline {
					return r.prefix + r.snap.Cmdline
				}
				return r.prefix + r.label()
			}},
		{title: "ST", width: 3, optional: true, key: sortState,
			value: func(s proc.Snapshot, _ *Model) string { return s.State }},
		{title: "NI", width: 4, right: true, optional: true, key: sortNice,
			value: func(s proc.Snapshot, _ *Model) string { return s.NiceLabel() }},
		{title: "THR", width: 5, right: true, optional: true,
			value: func(s proc.Snapshot, _ *Model) string { return strconv.FormatInt(s.Threads, 10) }},
		{title: "CPU%", width: 7, right: true, key: sortCPU,
			value: func(s proc.Snapshot, _ *Model) string { return human.Percent(s.CPUPercent) }},
		{title: "RSS", width: 9, right: true, key: sortMem,
			value: func(s proc.Snapshot, _ *Model) string { return human.FromKiB(float64(s.RSSKiB)) }},
		{title: "ΔRSS", width: 9, right: true, optional: true, key: sortDelta,
			value: func(s proc.Snapshot, _ *Model) string { return human.SignedKiB(s.RSSDeltaKiB) }},
		{title: "RD/s", width: 9, right: true, optional: true, key: sortIO,
			value: func(s proc.Snapshot, _ *Model) string { return human.Rate(s.ReadRate) }},
		{title: "WR/s", width: 9, right: true, optional: true,
			value: func(s proc.Snapshot, _ *Model) string { return human.Rate(s.WriteRate) }},
		{title: "FD", width: 10, right: true, optional: true, key: sortFD,
			value: func(s proc.Snapshot, _ *Model) string {
				if s.FDCount < 0 {
					return "—"
				}
				if s.FDLimit > 0 {

					return strconv.Itoa(s.FDCount) + "/" + human.Compact(int64(s.FDLimit))
				}
				return strconv.Itoa(s.FDCount)
			}},
		{title: "AGE", width: 8, right: true, optional: true, key: sortAge,
			value: func(s proc.Snapshot, _ *Model) string { return human.Duration(s.Age) }},
		{title: "ANOMALY", width: 18, optional: true,
			value: func(s proc.Snapshot, m *Model) string { return m.anomalyCell(s.PID) },
			rowValue: func(r row, m *Model) string {
				txt := m.anomalyCell(r.snap.PID)
				if extra := r.anoms - len(m.anomIndex[r.snap.PID]); extra > 0 {
					if txt == "" {
						txt = "in branch"
					}
					txt += " +" + strconv.Itoa(extra)
				}
				return clip(txt, 18)
			}},
	}

	total := func(cs []colSpec) int {
		n := 0
		for _, c := range cs {
			n += c.width
		}
		return n + len(cs) - 1
	}

	for total(cols) > avail && len(cols) > 4 {
		dropped := false
		for i := len(cols) - 1; i >= 0; i-- {
			if cols[i].optional {
				cols = append(cols[:i], cols[i+1:]...)
				dropped = true
				break
			}
		}
		if !dropped {
			break
		}
	}
	for total(cols) > avail && nameW > 8 {
		for i := range cols {
			if cols[i].title == "NAME" {
				cols[i].width--
			}
		}
		nameW--
	}
	return cols
}

func (m *Model) columnHeader(cols []colSpec, inner int) string {
	var b strings.Builder
	for i, c := range cols {
		if i > 0 {
			b.WriteString(" ")
		}
		title := c.title
		if c.key != sortNone && c.key == m.sortKey {
			mark := "▲"
			if m.sortDesc {
				mark = "▼"
			}
			title += mark
		}
		cell := clip(title, c.width)
		if c.right {
			b.WriteString(human.PadLeft(cell, c.width))
		} else {
			b.WriteString(human.PadRight(cell, c.width))
		}
	}
	return colHeadStyle.Render(human.PadRight(clip(b.String(), inner), inner))
}

func (m *Model) formatRow(r row, cols []colSpec, inner int) string {
	s := r.snap
	var b strings.Builder
	for i, c := range cols {
		if i > 0 {
			b.WriteString(" ")
		}
		text := c.value(s, m)
		if c.rowValue != nil {
			text = c.rowValue(r, m)
			if c.fitPrefix && r.prefix != "" {
				text = fitTreeCell(r.prefix, text, c.width)
			}
		}
		cell := clip(text, c.width)
		if c.right {
			b.WriteString(human.PadLeft(cell, c.width))
		} else {
			b.WriteString(human.PadRight(cell, c.width))
		}
	}
	return human.PadRight(clip(b.String(), inner), inner)
}

func fitTreeCell(prefix, text string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(text) <= width {
		return text
	}
	name := strings.TrimPrefix(text, prefix)
	const minName = 4

	runes := []rune(prefix)
	for len(runes) > indentStep && lipgloss.Width(string(runes))+minName > width {
		runes = runes[indentStep:]
	}
	short := string(runes)
	room := width - lipgloss.Width(short)
	if room < 1 {
		return clip(text, width)
	}
	return short + clip(name, room)
}

func (m *Model) anomalyCell(pid int) string {
	list := m.anomIndex[pid]
	if len(list) == 0 {
		return ""
	}
	parts := make([]string, 0, len(list))
	maxSev := 0.0
	for _, a := range list {
		parts = append(parts, a.Kind.Short())
		if a.Severity > maxSev {
			maxSev = a.Severity
		}
	}
	txt := strings.Join(parts, "+")
	if len(list) > 0 {
		txt += " " + human.Duration(time.Since(list[0].Since))
	}
	return clip(txt, 18)
}

func (m *Model) rowStyle(s proc.Snapshot) lipgloss.Style {
	maxSev := 0.0
	has := false
	for _, a := range m.anomIndex[s.PID] {
		has = true
		if a.Severity > maxSev {
			maxSev = a.Severity
		}
	}
	return rowStyleFor(s, maxSev, has)
}

func (m *Model) renderTable(h int) string {
	inner := m.width - 4
	if inner < 20 {
		inner = 20
	}

	cols := m.buildColumns(inner - m.indentWidth())

	rows := h - 5
	if rows < 1 {
		rows = 1
	}

	arrow := "▲"
	if m.sortDesc {
		arrow = "▼"
	}
	mode := "flat list"
	if m.treeViewActive() {
		mode = "tree: Enter — branch"
	}
	titleLine := headerStyle.Render(m.pane.title()) + dimStyle.Render(fmt.Sprintf(
		"  ·  %s  ·  sort: %s %s  ·  filter: %s", mode, m.sortKey.title(), arrow, m.filter.title()))
	if m.search != "" || m.searching {
		titleLine += dimStyle.Render("  ·  search: ") + accStyle.Render(m.search)
	}

	lines := make([]string, 0, rows+3)
	lines = append(lines, clipPad(titleLine, inner))
	lines = append(lines, m.columnHeader(cols, inner))

	if len(m.rows) == 0 {
		msg := "no processes match the filter"
		if m.search != "" {
			msg = fmt.Sprintf("nothing found for query %q", m.search)
		}
		lines = append(lines, clipPad(warnStyle.Render(msg), inner))
		for i := 1; i < rows; i++ {
			lines = append(lines, strings.Repeat(" ", inner))
		}
	} else {
		for i := 0; i < rows; i++ {
			idx := m.scroll + i
			if idx >= len(m.rows) {
				lines = append(lines, strings.Repeat(" ", inner))
				continue
			}
			r := m.rows[idx]
			rowText := m.formatRow(r, cols, inner)
			switch {
			case idx == m.cursor:
				lines = append(lines, selectedStyle.Render(rowText))
			case m.treeMode && r.group%2 == 1:

				lines = append(lines, groupShadeStyle.Inherit(m.styleForRow(r)).Render(rowText))
			default:
				lines = append(lines, m.styleForRow(r).Render(rowText))
			}
		}
	}

	first, last := 0, 0
	if len(m.rows) > 0 {
		first = m.scroll + 1
		last = minInt(m.scroll+rows, len(m.rows))
	}
	selText := "—"
	if r, ok := m.rowAt(m.cursor); ok {
		s := r.snap
		selText = fmt.Sprintf("PID %d %s (nice %s, %s)", s.PID, s.DisplayName(), s.NiceLabel(), s.StateName)
		if r.subtree > 0 {
			selText += " · branch: " + human.Pluralf(r.subtree, "descendant", "descendants", "descendants")
		}
	}
	total := human.Pluralf(len(m.rows), "row", "rows", "rows")
	if m.treeMode && m.search == "" && m.filter == filterAll {
		total = fmt.Sprintf("%s of %d, %s",
			total, len(m.visible), human.Pluralf(m.groupCount(), "group", "groups", "groups"))
		if m.userFirst {

			mine, other := m.ownerSplit()
			total += fmt.Sprintf(" (mine %d · system %d)", mine, other)
		}
	}

	bottom := fmt.Sprintf(" showing %d–%d · %s", first, last, total)
	const sep = " · cursor: "
	if room := inner - lipgloss.Width(bottom) - lipgloss.Width(sep); room > 16 {
		bottom += sep + truncateWords(selText, room)
	}
	lines = append(lines, clipPad(dimStyle.Render(bottom), inner))

	return boxStyle.Width(inner + 2).Render(strings.Join(lines, "\n"))
}

func (m *Model) renderLog(h int) string {
	inner := m.width - 4
	if inner < 20 {
		inner = 20
	}
	rows := h - 6
	if rows < 1 {
		rows = 1
	}
	evts := m.logEvents()

	filter := ""
	if m.logFilter != logAll {
		filter = "  ·  filter: " + m.logFilter.title() + " (L — change)"
	}
	titleLine := headerStyle.Render(m.pane.title()) + dimStyle.Render(fmt.Sprintf(
		"  ·  events: %d  ·  newest first%s", len(evts), filter))

	lines := make([]string, 0, rows+5)
	lines = append(lines, clipPad(titleLine, inner))

	if len(evts) == 0 {
		hint := "log is empty: no process actions yet"
		if m.logFilter != logAll {
			hint = "nothing matches the filter: " + m.logFilter.title() + " (L — change)"
		}
		lines = append(lines, clipPad(dimStyle.Render(hint), inner))
		for i := 1; i < rows; i++ {
			lines = append(lines, strings.Repeat(" ", inner))
		}
	} else {
		m.clampLog()

		first := len(evts) - 1 - m.logScroll
		if first > len(evts)-1 {
			first = len(evts) - 1
		}
		drawn := 0
		for i := first; i >= 0 && drawn < rows; i-- {
			e := evts[i]
			target := ""
			if e.PID > 0 {
				target = fmt.Sprintf("pid=%d %s ", e.PID, clip(e.Name, 14))
			}
			line := fmt.Sprintf("%s %-6s %-8s %s%s",
				e.Time.Format("15:04:05"), e.Level, clip(e.Kind, 8), target, e.Message)
			styled := eventStyle(e.Level).Render(clip(line, inner))
			if i == len(evts)-1-m.logCursor {

				styled = clipPad(logCursorStyle.Render("› "+clip(line, inner-2)), inner)
			}
			lines = append(lines, clipPad(styled, inner))
			drawn++
		}
		for ; drawn < rows; drawn++ {
			lines = append(lines, strings.Repeat(" ", inner))
		}
	}

	lines = append(lines, clipPad(dimStyle.Render(strings.Repeat("─", inner)), inner))
	if e, ok := m.selectedEvent(); ok {
		head := fmt.Sprintf("%s  %s  %s", e.Time.Format("2006-01-02 15:04:05"), e.Level, e.Kind)
		if e.PID > 0 {
			head += fmt.Sprintf("  pid=%d %s", e.PID, e.Name)
		}
		lines = append(lines, clipPad(dimStyle.Render(head), inner))
		for _, wl := range wrapText(e.Message, inner, 2) {
			lines = append(lines, clipPad(eventStyle(e.Level).Render(wl), inner))
		}
	} else {
		lines = append(lines, clipPad(dimStyle.Render("no entry under the cursor"), inner))
	}

	bottom := dimStyle.Render(fmt.Sprintf(
		" showing %d of %d · the log keeps the last %d events · ↑/↓ select, L filter",
		minInt(rows, len(evts)), len(evts), m.cfg.UI.MaxLogLines))
	lines = append(lines, clipPad(bottom, inner))

	return boxStyle.Width(inner + 2).Render(strings.Join(lines, "\n"))
}

func wrapText(s string, width, maxLines int) []string {
	if width <= 0 || maxLines <= 0 {
		return nil
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	out := make([]string, 0, maxLines)
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, w := range words {
		if cur.Len() > 0 && lipgloss.Width(cur.String())+1+lipgloss.Width(w) > width {
			flush()
			if len(out) == maxLines {
				break
			}
		}
		if cur.Len() > 0 {
			cur.WriteString(" ")
		}
		cur.WriteString(w)
	}
	flush()
	if len(out) > maxLines {
		out = out[:maxLines]
	}

	if len(words) > 0 {
		joined := strings.Join(out, " ")
		if len(joined) < len(strings.Join(words, " ")) {
			last := len(out) - 1
			if last >= 0 {
				out[last] = human.Truncate(out[last], width-1) + "…"
			}
		}
	}
	return out
}

func eventStyle(lvl actions.Level) lipgloss.Style {
	switch lvl {
	case actions.LevelError:
		return badStyle
	case actions.LevelWarn:
		return warnStyle
	case actions.LevelAction:
		return accStyle
	default:
		return dimStyle
	}
}

func rowLabelW(width, barW int, value string) int {
	w := width - barW - lipgloss.Width(value) - 3
	if w < 6 {
		w = 6
	}
	return w
}

func (m *Model) renderGraphs(h int) string {
	inner := m.width - 4
	if inner < 20 {
		inner = 20
	}

	// Sparklines get a third of the height, the detail panels the rest:
	// the details need more lines than the graphs.
	sep := 1
	tier1H := (h - sep) / 3
	if tier1H < 6 {
		tier1H = 6
	}
	tier2H := h - sep - tier1H
	if tier2H < 4 {
		tier2H = 4
	}

	bodyH1 := tier1H - 3
	if bodyH1 < 1 {
		bodyH1 = 1
	}
	// Sparkline plus its one-line caption must fit the panel body exactly:
	// a taller graph gets its baseline cut off and looks like it is floating.
	sparkH := bodyH1 - 1
	if sparkH < 2 {
		sparkH = 2
	}
	bodyH2 := tier2H - 3
	if bodyH2 < 1 {
		bodyH2 = 1
	}

	boxW := (inner - 1) / 2
	if boxW < 20 {
		boxW = inner
	}
	sparkW := boxW - 6
	if sparkW < 8 {
		sparkW = 8
	}

	cpuHist, memHist := m.mon.SysHistory()

	cpuBody := sparkline(cpuHist, sparkW, sparkH, 100, cpuColor(m.sys.CPUPercent)) + "\n" +
		dimStyle.Render(fmt.Sprintf("now %s · avg %s · peak %s",
			human.Percent(m.sys.CPUPercent), human.Percent(avg(cpuHist)), human.Percent(maxOf(cpuHist))))
	cpuPanel := panelBoxH("CPU (system)", cpuBody, boxW, tier1H)

	memBody := sparkline(memHist, sparkW, sparkH, 100, memColor(m.sys.MemPercent())) + "\n" +
		dimStyle.Render(fmt.Sprintf("used %s of %s · free %s · dirty %s",
			human.FromKiB(float64(m.sys.MemUsedKiB())), human.FromKiB(float64(m.sys.MemTotalKiB)),
			human.FromKiB(float64(m.sys.MemAvailableKiB)), human.FromKiB(float64(m.sys.DirtyKiB))))
	memPanel := panelBoxH("MEMORY", memBody, boxW, tier1H)

	tier1 := lipgloss.JoinHorizontal(lipgloss.Top, cpuPanel, " ", memPanel)

	procPanel := panelBoxH("SELECTED PROCESS", m.selectedDetails(sparkW, sparkH, bodyH2), boxW, tier2H)
	leadersPanel := panelBoxH("LEADERS", m.topLeaders(boxW-4, bodyH2), boxW, tier2H)
	tier2 := lipgloss.JoinHorizontal(lipgloss.Top, procPanel, " ", leadersPanel)

	return lipgloss.JoinVertical(lipgloss.Left, tier1, "", tier2)
}

func (m *Model) selectedDetails(sparkW, sparkH, maxLines int) string {
	if maxLines < 3 {
		maxLines = 3
	}
	r, ok := m.rowAt(m.cursor)
	if !ok {
		return dimStyle.Render("no process selected")
	}
	s := r.snap

	lines := make([]string, 0, maxLines)
	truncated := false
	// add appends a line while the budget lasts; groups are dropped whole,
	// so nothing gets cut mid-graph or mid-row.
	add := func(s string) bool {
		if len(lines) >= maxLines {
			truncated = true
			return false
		}
		lines = append(lines, s)
		return true
	}

	add(accStyle.Render(fmt.Sprintf("%s  (PID %d, parent %d)", s.DisplayName(), s.PID, s.PPID)))
	if r.subtree > 0 && !r.open {
		add(dimStyle.Render(clip(fmt.Sprintf(
			"subtree totals: %s · Enter — expand",
			human.Pluralf(r.subtree, "descendant", "descendants", "descendants")), maxInt(sparkW+4, 20))))
	}
	add(dimStyle.Render("cmd: ") + clip(s.Cmdline, maxInt(sparkW+4, 20)))

	cardW := maxInt(sparkW+4, 24)
	add(fitLine([]string{
		keyValue("state", s.State+" ("+s.StateName+")", stateColor(s.State)),
		keyValue("nice", s.NiceLabel(), cText),
		keyValue("threads", strconv.FormatInt(s.Threads, 10), cText),
	}, "  ", cardW))
	add(fitLine([]string{
		keyValue("CPU", human.Percent(s.CPUPercent), cpuColor(s.CPUPercent)),
		keyValue("RSS", human.FromKiB(float64(s.RSSKiB)), cText),
		keyValue("swap", human.FromKiB(float64(s.SwapKiB)), cText),
	}, "  ", cardW))
	if s.Policy != proc.SchedOther {
		add(fitLine([]string{
			keyValue("scheduler", s.SchedName(), cWarn),
			keyValue("rt priority", strconv.Itoa(s.RTPriority), cText),
			keyValue("owner", s.User, cText),
		}, "  ", cardW))
	} else {
		add(fitLine([]string{
			keyValue("owner", s.User, cText),
			keyValue("PGID", strconv.Itoa(s.PGID), cText),
			keyValue("session", strconv.Itoa(s.SID), cText),
		}, "  ", cardW))
	}
	fdText := "no access"
	fdCol := lipgloss.TerminalColor(cDim)
	if s.FDCount >= 0 {
		fdText = strconv.Itoa(s.FDCount)
		if s.FDLimit > 0 {
			fdText = fmt.Sprintf("%d of %d (%s)", s.FDCount, s.FDLimit, human.Percent(s.FDPercent))
			if s.FDPercent >= m.cfg.Anomaly.FDWarnRatio*100 {
				fdCol = cWarn
			}
		}
	}
	ioText := "no access"
	ioCol := lipgloss.TerminalColor(cDim)
	if s.IOAccessible {
		ioText = fmt.Sprintf("%s / %s", human.Rate(s.ReadRate), human.Rate(s.WriteRate))
		ioCol = cText
	}
	add(fmt.Sprintf("%s  %s", keyValue("FD", fdText, fdCol), keyValue("I/O r/w", ioText, ioCol)))
	add(keyValue("running", human.Duration(s.Age), cText) +
		dimStyle.Render("  (since "+s.StartTime.Format("15:04:05")+")"))

	hist := m.mon.RSSHistory(s.PID)
	if len(hist) >= 3 {
		slope, r2 := anomaly.Trend(hist, m.mon.Options().Interval)
		drop := anomaly.MaxRelativeDrop(hist)
		slopeCol := lipgloss.TerminalColor(cText)
		verdict := "stable"
		switch {
		case slope >= m.cfg.Anomaly.LeakMinSlopeKiBPerSec && r2 >= m.cfg.Anomaly.LeakMinR2 && drop <= m.cfg.Anomaly.LeakMaxDropRatio:
			slopeCol = cBad
			verdict = "looks like a leak"
		case slope > 0:
			slopeCol = cWarn
			verdict = "growing"
		case slope < 0:
			verdict = "releasing"
		}
		add(keyValue("RSS trend", fmt.Sprintf("%+s/s, R²=%.2f", human.FromKiB(slope), r2), slopeCol))

		graphH := minInt(sparkH, 3)
		graph, lo, hi := trendline(hist, sparkW, graphH, cAccent2)
		graphLines := strings.Split(graph, "\n")
		if len(lines)+len(graphLines)+1 <= maxLines {
			for _, gl := range graphLines {
				add(gl)
			}
			caption := verdict + " · " + human.FromKiB(lo) + " … " + human.FromKiB(hi)
			if drop > 0.005 {
				caption += " · drop " + human.Percent(drop*100)
			}
			add(clip(dimStyle.Render(caption), maxInt(sparkW+4, 20)))
		} else {
			// No room for the graph: keep the one-line verdict instead.
			add(clip(dimStyle.Render(verdict), maxInt(sparkW+4, 20)))
		}
	} else {
		add(dimStyle.Render("RSS trend: not enough data (need at least 3 snapshots)"))
	}

	if list := m.anomIndex[s.PID]; len(list) > 0 {
		for _, a := range list {
			add(lipgloss.NewStyle().Foreground(severityColor(a.Severity)).
				Render(fmt.Sprintf("⚠ %s (%s): %s", a.Kind.Title(), human.Duration(time.Since(a.Since)), a.Detail)))
		}
	}

	if truncated {
		lines[maxLines-1] = dimStyle.Render(" … (does not fit)")
	}
	return strings.Join(lines, "\n")
}

func topByCPU(procs []proc.Snapshot) []proc.Snapshot {
	out := make([]proc.Snapshot, len(procs))
	copy(out, procs)
	sort.Slice(out, func(i, j int) bool { return out[i].CPUPercent > out[j].CPUPercent })
	return out
}

func topByMem(procs []proc.Snapshot) []proc.Snapshot {
	out := make([]proc.Snapshot, len(procs))
	copy(out, procs)
	sort.Slice(out, func(i, j int) bool { return out[i].RSSKiB > out[j].RSSKiB })
	return out
}

func (m *Model) topLeaders(width, maxLines int) string {
	if width < 20 {
		width = 20
	}
	if maxLines < 4 {
		maxLines = 4
	}
	barW := 10
	byCPU, byMem := m.leaderCPU, m.leaderMem

	// Split the budget between the two sections evenly, so BY MEMORY does
	// not starve when the terminal is short.
	slots := maxLines - 2 // minus the two section headers
	if slots < 2 {
		slots = 2
	}
	cpuN := minInt(5, (slots+1)/2)
	memN := minInt(5, slots/2)

	var lines []string
	truncated := false
	add := func(s string) {
		if len(lines) >= maxLines {
			truncated = true
			return
		}
		lines = append(lines, s)
	}

	add(dimStyle.Render("BY CPU"))
	maxCPU := 1.0
	if len(byCPU) > 0 && byCPU[0].CPUPercent > maxCPU {
		maxCPU = byCPU[0].CPUPercent
	}
	for i := 0; i < cpuN && i < len(byCPU); i++ {
		s := byCPU[i]
		// Fixed-width value: the label column must not resize when the
		// percentage changes length (9.9% vs 104.1%), otherwise the names
		// get re-truncated and the whole row visibly shifts every tick.
		value := fmt.Sprintf("%6s", human.Percent(s.CPUPercent))
		add(clipPad(hbarRow(s.DisplayName(), rowLabelW(width, barW, value),
			s.CPUPercent/maxCPU, barW, value, cpuColor(s.CPUPercent)), width))
	}

	add(dimStyle.Render("BY MEMORY"))
	maxMem := int64(1)
	if len(byMem) > 0 && byMem[0].RSSKiB > maxMem {
		maxMem = byMem[0].RSSKiB
	}
	for i := 0; i < memN && i < len(byMem); i++ {
		s := byMem[i]
		frac := float64(s.RSSKiB) / float64(maxMem)
		pct := 0.0
		if m.sys.MemTotalKiB > 0 {
			pct = float64(s.RSSKiB) / float64(m.sys.MemTotalKiB) * 100
		}
		// Same fixed-width trick as above: memory sizes vary from "9.4 GiB"
		// to "745.2 MiB", the value column must stay the same width.
		value := fmt.Sprintf("%10s %6s", human.FromKiB(float64(s.RSSKiB)), human.Percent(pct))
		add(clipPad(hbarRow(s.DisplayName(), rowLabelW(width, barW, value),
			frac, barW, value, cAccent2), width))
	}

	if len(m.anoms) > 0 {
		add(dimStyle.Render("ANOMALIES"))
		for i, a := range m.anoms {
			if i >= 5 {
				add(dimStyle.Render(fmt.Sprintf("…and %d more", len(m.anoms)-5)))
				break
			}
			line := fmt.Sprintf("%s %d %s: %s", a.Kind.Short(), a.PID, a.Name, a.Detail)
			add(clipPad(lipgloss.NewStyle().Foreground(severityColor(a.Severity)).
				Render(clip(line, width)), width))
		}
	}

	if truncated {
		lines[maxLines-1] = dimStyle.Render(clipPad(" … (does not fit)", width))
	}
	return strings.Join(lines, "\n")
}

func (m *Model) renderConfirm(h int) string {
	c := m.confirm
	if c == nil {
		return ""
	}
	opts := m.act.DefaultKillOptions()

	var b strings.Builder
	b.WriteString(badStyle.Render(fmt.Sprintf(" SMART KILL — PID %d ", c.pid)) + "\n")
	b.WriteString(accStyle.Render(fmt.Sprintf("%s  (owner: %s)", c.name, c.user)) + "\n")
	if !c.start.IsZero() {
		b.WriteString(dimStyle.Render(fmt.Sprintf("started %s · running for %s",
			c.start.Format("02.01.2006 15:04:05"), human.Duration(time.Since(c.start)))) + "\n")
	}
	if c.parentPID > 0 {
		b.WriteString(dimStyle.Render(fmt.Sprintf("parent: PID %d (%s)", c.parentPID, c.parentName)) + "\n")
	}
	if len(c.tree) > 0 {
		b.WriteString(dimStyle.Render(fmt.Sprintf("children: %d, total RSS %s",
			len(c.tree), human.FromKiB(float64(c.treeRSS)))) + "\n")
	}
	b.WriteString("\n")
	scopeText := "this process only"
	if c.scope == actions.ScopeTree {
		scopeText = fmt.Sprintf("WHOLE TREE — %d processes", len(c.tree)+1)
		b.WriteString(warnStyle.Render(fmt.Sprintf("  ▶ %s (leaves first, root last)", scopeText)) + "\n")
	} else {
		b.WriteString(accStyle.Render("  ▶ "+scopeText) + "\n")
		if len(c.tree) > 0 {
			b.WriteString(dimStyle.Render("    t — kill together with children") + "\n")
		}
	}
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("The process will be terminated as follows:") + "\n")
	b.WriteString(fmt.Sprintf("  1. SIGTERM  — graceful termination, wait %s\n", human.Duration(opts.Graceful)))
	coreState := "off"
	if c.coredump {
		coreState = "on"
	}
	b.WriteString(fmt.Sprintf("  2. SIGABRT  — core dump [%s], wait %s\n", coreState, human.Duration(opts.CoreWait)))
	b.WriteString(fmt.Sprintf("  3. SIGKILL  — unconditional kill, wait %s\n", human.Duration(opts.FinalWait)))

	if c.user != "" && c.pid > 0 {
		if s, ok := m.selected(); ok && s.PID == c.pid && s.UID != m.ownUID {
			b.WriteString("\n" + warnStyle.Render("  ⚠ the process belongs to another user: root is required") + "\n")
		}
		if c.coredump && !proc.CoreDumpEnabled(c.pid) {
			b.WriteString("\n" + warnStyle.Render("  ⚠ RLIMIT_CORE = 0: no core dump will be written (enable with `ulimit -c unlimited`)") + "\n")
		}
	}

	b.WriteString("\n")
	if c.running {
		b.WriteString(badStyle.Render(fmt.Sprintf("  ▶ running: %s — %s", c.stage, c.detail)) + "\n")
		b.WriteString(dimStyle.Render(fmt.Sprintf("  elapsed %s · quitting is blocked until it finishes",
			human.Duration(time.Since(c.started)))) + "\n")
	} else {
		b.WriteString(keyStyle.Render("  y / Enter") + dimStyle.Render(" — confirm    ") +
			keyStyle.Render("c") + dimStyle.Render(" — core    ") +
			keyStyle.Render("t") + dimStyle.Render(" — scope    ") +
			keyStyle.Render("n / Esc") + dimStyle.Render(" — cancel") + "\n")
	}

	maxW := m.width - 6
	if maxW < 24 {
		maxW = 24
	}
	lines := strings.Split(strings.TrimRight(b.String(), "\n"), "\n")
	for i, ln := range lines {
		if lipgloss.Width(ln) > maxW {
			lines[i] = lipgloss.NewStyle().MaxWidth(maxW).Render(ln)
		}
	}

	dialog := dialogStyle.Render(strings.Join(lines, "\n"))
	return lipgloss.Place(m.width, h, lipgloss.Center, lipgloss.Center, dialog)
}

func (m *Model) renderHelp(h int) string {
	inner := m.width - 4
	if inner < 20 {
		inner = 20
	}

	colW := (inner - 3) / 2
	oneCol := colW < 48
	if oneCol {
		colW = inner
	}
	keyW := 20
	if oneCol {
		keyW = 24
	}

	left := []string{
		headerStyle.Render("NAVIGATION"),
		hintW("Tab / Shift+Tab", "next / previous tab", keyW, colW),
		hintW("1…6, 9", "tabs: processes / stuck / load / AI / groups / security / log", keyW, colW),
		hintW("↑ / ↓ , j / k", "select a row", keyW, colW),
		hintW("PgUp / PgDn", "page up / down", keyW, colW),
		hintW("Home / End , g / G", "to start / to end", keyW, colW),
		hintW("mouse wheel", "scroll, click — select", keyW, colW),
		"",
		headerStyle.Render("PROCESS TREE"),
		hintW("Enter", "expand / collapse a branch", keyW, colW),
		hintW("← / →", "collapse (to parent) / expand", keyW, colW),
		hintW("T", "tree ⇄ flat list", keyW, colW),
		hintW("u", "own branches first / global sort", keyW, colW),
		hintW("e / E", "expand / collapse all branches", keyW, colW),
		note("A collapsed row «chromium (39)» shows the totals of the whole subtree: CPU, memory, threads, fds, I/O. Children are always in ascending PID order and never jump. By default (u) own branches come before system ones — within a group the selected column sets the order.", colW),
		"",
		headerStyle.Render("STUCK (tab 2)"),
		hintW("Enter", "to the process on the Processes tab", keyW, colW),
		hintW("c", "SIGCONT: resume a stop (Ctrl+Z)", keyW, colW),
		hintW("a", "ask the local model about the cause", keyW, colW),
		hintW("r", "recompute the list immediately", keyW, colW),
		note("D — waiting for I/O, R — burning CPU for nothing, Z — zombie, T — stopped by a signal, RT — real-time. Each row shows the verdict, how long the state lasts and what to do. Kernel threads are excluded.", colW),
		note("A zombie cannot be \"killed\": it is already dead. Kill the parent that never reaps the status.", colW),
		"",
		headerStyle.Render("TABLE"),
		hintW("s / S", "sort column", keyW, colW),
		hintW("d", "sort direction", keyW, colW),
		hintW("f", "filter: all / anomalous / mine", keyW, colW),
		hintW("/", "search; x — clear", keyW, colW),
		hintW("c", "full command line", keyW, colW),
		hintW("r", "manual /proc snapshot", keyW, colW),
	}
	right := []string{
		headerStyle.Render("ACTIONS"),
		hintW("F7", fmt.Sprintf("renice +%d (lower)", m.act.ReniceStep()), keyW, colW),
		hintW("F8", fmt.Sprintf("renice −%d (needs root)", m.act.ReniceStep()), keyW, colW),
		hintW("F9", "Smart Kill: TERM → ABRT → KILL", keyW, colW),
		hintW("y / Enter", "confirm Smart Kill", keyW, colW),
		hintW("c (in menu)", "core dump stage", keyW, colW),
		hintW("t (in menu)", "this process or the whole tree", keyW, colW),
		hintW("n / Esc", "cancel", keyW, colW),
		"",
		headerStyle.Render("PROCESS GROUPS (tab 5)"),
		hintW("Enter", "group contents: which processes will die", keyW, colW),
		hintW("F9 / y", "kill the whole group", keyW, colW),
		hintW("x / X", fmt.Sprintf("nice ±%d for the whole group", m.act.ReniceStep()), keyW, colW),
		hintW("← / → , Tab", "in the dialog: pick \"kill\" / \"cancel\"", keyW, colW),
		note("A group is a category: browsers (44 chromium processes), messengers, telemetry, games, builds, documents, containers, editors. The full PID list is shown before killing.", colW),
		note("⛔ — the group cannot be killed in one action: system services, terminals and shells, VPN, «misc». The Deadeye parent chain, init and kernel threads are protected separately.", colW),
		"",
		headerStyle.Render("SECURITY (tab 6)"),
		hintW("r", "check the system (on demand, not in the background)", keyW, colW),
		hintW("L", "level filter: all → critical → high → medium", keyW, colW),
		hintW("m", "variant: local only ⇄ local + DeepSeek", keyW, colW),
		hintW("e", "hash reputation check (variant 2)", keyW, colW),
		hintW("Enter", "to the process of the finding", keyW, colW),
		hintW("a", "ask the local model about the finding", keyW, colW),
		note("Two variants, chosen with the m key: local heuristics only (default) or local heuristics plus a hash check through the DeepSeek API. The variant is shown in the tab header.", colW),
		note("What we look at: launches from /tmp and /dev/shm, remote binaries, curl | sh, base64 -d | sh, nc -e, the pool protocol, LD_PRELOAD and LD_AUDIT, autostart entries, listening ports, files not owned by any package.", colW),
		note("Spending is capped: first the on-disk hashes cache, then the daily request limit, and only then the network. File contents never leave the machine — only the hash, path, size and the evidence text.", colW),
		"",
		headerStyle.Render("SYSTEM (tab 7)"),
		hintW("Enter", "run the action", keyW, colW),
		hintW("y / n", "confirm / cancel the action marked «!»", keyW, colW),
		hintW("C", "clear output", keyW, colW),
		note("One password per session: the first root action invokes pkexec, then commands go over a local socket without new password prompts. Only allowlisted commands run (systemctl, pacman, rfkill, ufw, etc.); no shell is invoked.", colW),
		note("The «summary» section runs without root and instantly; «suspend» warns about the known xhci_hcd kernel bug (hcd_pci_suspend -16).", colW),
		"",
		headerStyle.Render("AI (tab 4)"),
		hintW("a", "explain the selected process", keyW, colW),
		hintW("r", "check Ollama availability", keyW, colW),
		hintW("Esc", "cancel the request", keyW, colW),
		note("There is no free-form input: the program suggests actions and the model only explains the result. It is called only on an explicit keypress and is unloaded from memory right away (keep_alive=0).", colW),
		"",
		headerStyle.Render("TERMINAL (tab 8)"),
		hintW("Esc / Ctrl+Q", "detach — the shell keeps running in the background", keyW, colW),
		note("A real shell in a pseudo-terminal: any commands run right here. Full-screen editors are not supported.", colW),
		"",
		headerStyle.Render("LAUNCH (tab 0)"),
		hintW("Enter", "launch the program / toggle autostart", keyW, colW),
		hintW("a", "add a command to autostart", keyW, colW),
		hintW("r", "reload the Hyprland files", keyW, colW),
		note("Reads ~/.config/hypr/custom/execs.lua (hl.exec_cmd) and hyprland.conf (exec-once): a line can be disabled or enabled back.", colW),
		"",
		headerStyle.Render("LOG"),
		hintW("↑ / ↓", "select an entry", keyW, colW),
		hintW("L", "filter: all / warn / error / actions", keyW, colW),
		hintW("← / →", "scroll", keyW, colW),
		note("The full text of the selected entry is shown at the bottom of the pane: list lines are clipped to the terminal width.", colW),
		"",
		headerStyle.Render("OTHER"),
		hintW("?", "this help", keyW, colW),
		hintW("q / Ctrl+C", "safe quit", keyW, colW),
		note("A Russian keyboard layout is understood automatically: each Cyrillic letter acts as the Latin key at the same position.", colW),
		note("Quitting during Smart Kill is blocked: the process must not be abandoned between SIGTERM and SIGKILL.", colW),
		note("Colors are disabled by the NO_COLOR=1 environment variable.", colW),
	}

	items := right
	if oneCol {
		items = append(append([]string{}, left...), "")
		items = append(items, right...)
	}
	renderCol := func(list []string) string {
		out := make([]string, 0, len(list))
		for _, it := range list {
			out = append(out, clipPad(it, colW))
		}
		return strings.Join(out, "\n")
	}
	var body string
	if oneCol {
		body = renderCol(items)
	} else {
		body = lipgloss.JoinHorizontal(lipgloss.Top, renderCol(left), "   ", renderCol(right))
	}

	lines := strings.Split(body, "\n")
	m.helpTotal = len(lines)
	rows := h - 4
	if rows < 1 {
		rows = 1
	}
	maxScroll := len(lines) - rows
	if maxScroll < 0 {
		maxScroll = 0
	}
	if m.helpScroll > maxScroll {
		m.helpScroll = maxScroll
	}
	if m.helpScroll < 0 {
		m.helpScroll = 0
	}
	hidden := 0
	if len(lines) > rows {
		hidden = len(lines) - (m.helpScroll + rows)
		if hidden < 0 {
			hidden = 0
		}
		lines = lines[m.helpScroll : m.helpScroll+rows]
	}
	if hidden > 0 {

		lines[len(lines)-1] = clipPad(dimStyle.Render(fmt.Sprintf(
			"↓ / PgDn — %s more  ·  ↑ — back",
			human.Pluralf(hidden, "line", "lines", "lines"))), colW)
	}
	tip := "  ·  ? — close"
	if m.helpTotal > rows {
		tip = "  ·  ↑/↓ scroll  ·  ? — close"
	}
	title := clipPad(headerStyle.Render("KEYBOARD HELP")+dimStyle.Render(tip), inner)
	content := title + "\n" + strings.Join(lines, "\n")
	return boxStyle.Width(inner + 2).Render(padLines(content, inner))
}

func hintW(key, desc string, keyW, colW int) string {
	room := colW - 2 - keyW
	if room < 4 {
		room = 4
	}
	return "  " + keyStyle.Render(human.PadRight(human.Truncate(key, keyW), keyW)) +
		dimStyle.Render(human.Truncate(desc, room))
}

func note(text string, colW int) string {
	lines := wrapText(text, colW-2, 4)
	for i, l := range lines {
		lines[i] = dimStyle.Render(l)
	}
	return "  " + strings.Join(lines, "\n  ")
}

func (m *Model) renderFooter() string {

	hints := []struct{ key, desc string }{
		{"q", "quit"},
		{"Tab", "tabs"},
	}
	switch m.pane {
	case paneProcesses:
		if m.treeIdx != nil {
			hints = append(hints,
				struct{ key, desc string }{"Enter", "branch"},
				struct{ key, desc string }{"←/→", "fold/unfold"},
				struct{ key, desc string }{"T", "flat list"},
				struct{ key, desc string }{"e/E", "all branches"})
		} else {
			hints = append(hints, struct{ key, desc string }{"T", "tree"})
		}
		hints = append(hints,
			struct{ key, desc string }{"↑↓/jk", "pick"},
			struct{ key, desc string }{"s/S", "sort"},
			struct{ key, desc string }{"d", "order"},
			struct{ key, desc string }{"f", "filter"},
			struct{ key, desc string }{"/", "search"},
			struct{ key, desc string }{"c", "cmdline"},
			struct{ key, desc string }{"F7/F8", "nice ±"},
			struct{ key, desc string }{"F9", "Smart Kill"},
			struct{ key, desc string }{"?", "help"})
	case paneHung:
		hints = append(hints,
			struct{ key, desc string }{"↑↓/jk", "pick"},
			struct{ key, desc string }{"Enter", "to process"},
			struct{ key, desc string }{"c", "SIGCONT"},
			struct{ key, desc string }{"a", "ask AI"},
			struct{ key, desc string }{"r", "recount"},
			struct{ key, desc string }{"F9", "Smart Kill"},
			struct{ key, desc string }{"?", "help"})
	case paneSecurity:
		hints = append(hints,
			struct{ key, desc string }{"↑↓/jk", "pick finding"},
			struct{ key, desc string }{"r", "scan"},
			struct{ key, desc string }{"L", "level filter"},
			struct{ key, desc string }{"m", "mode: local / +DeepSeek"},
			struct{ key, desc string }{"e", "hash reputation"},
			struct{ key, desc string }{"Enter", "to process"},
			struct{ key, desc string }{"?", "help"})
	case paneSystem:
		hints = append(hints,
			struct{ key, desc string }{"↑↓/jk", "pick action"},
			struct{ key, desc string }{"Enter", "run"},
			struct{ key, desc string }{"y", "confirm"},
			struct{ key, desc string }{"C", "clear output"},
			struct{ key, desc string }{"?", "help"})
	case paneTerminal:
		hints = append(hints,
			struct{ key, desc string }{"Esc / Ctrl+Q", "detach"},
			struct{ key, desc string }{"any keys", "shell input"},
			struct{ key, desc string }{"?", "help"})
	case paneLaunch:
		hints = append(hints,
			struct{ key, desc string }{"↑↓/jk", "pick"},
			struct{ key, desc string }{"Enter", "launch / toggle"},
			struct{ key, desc string }{"a", "add"},
			struct{ key, desc string }{"r", "reload"},
			struct{ key, desc string }{"?", "help"})
	case paneServers:
		hints = append(hints,
			struct{ key, desc string }{"↑↓/jk", "pick"},
			struct{ key, desc string }{"Enter", "open panel"},
			struct{ key, desc string }{"a", "add"},
			struct{ key, desc string }{"d", "delete"},
			struct{ key, desc string }{"?", "help"})
	case paneLog:
		hints = append(hints,
			struct{ key, desc string }{"↑↓/jk", "pick"},
			struct{ key, desc string }{"←/→", "scroll"},
			struct{ key, desc string }{"PgUp/PgDn", "page"},
			struct{ key, desc string }{"?", "help"})
	default:
		hints = append(hints,
			struct{ key, desc string }{"↑↓/jk", "pick"},
			struct{ key, desc string }{"?", "help"})
	}
	var parts []string
	for _, hh := range hints {
		parts = append(parts, keyStyle.Render(hh.key)+dimStyle.Render(" "+hh.desc))
	}
	sep := dimStyle.Render(" · ")
	dots := dimStyle.Render(" · …")
	sepW, dotsW := lipgloss.Width(sep), lipgloss.Width(dots)

	var b strings.Builder
	used, all := 0, true
	for _, p := range parts {
		add := lipgloss.Width(p)
		if used > 0 {
			add += sepW
		}
		if used+add+dotsW > m.width {
			all = false
			break
		}
		if used > 0 {
			b.WriteString(sep)
		}
		b.WriteString(p)
		used += add
	}
	if !all {
		b.WriteString(dots)
	}
	first := clipPad(b.String(), m.width)

	var second string
	switch {
	case m.searching:
		second = keyStyle.Render(" search: ") + accStyle.Render(m.search) +
			dimStyle.Render("▌  Enter — apply, Esc — cancel")
	case m.activeStatus() != "":
		st := okStyle
		if m.statusIsErr {
			st = badStyle
		}
		second = st.Render(" " + m.activeStatus())
	default:
		if s, ok := m.selected(); ok {

			second = dimStyle.Render(fmt.Sprintf(" selected PID %d · %s · %s",
				s.PID, s.DisplayName(), human.TruncateMiddle(s.Cmdline, maxInt(m.width-40, 20))))
		} else {
			second = dimStyle.Render(" list is empty")
		}
	}
	return lipgloss.JoinVertical(lipgloss.Left, first, clipPad(second, m.width))
}

func panelBox(title, content string, totalWidth int) string {
	innerW := totalWidth - 4
	if innerW < 8 {
		innerW = 8
	}
	body := clipPad(headerStyle.Render(title), innerW) + "\n" + padLines(content, innerW)
	return boxStyle.Width(innerW + 2).Render(body)
}

func clipPad(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if lipgloss.Width(s) > width {
		s = lipgloss.NewStyle().MaxWidth(width).Render(s)
	}
	if w := lipgloss.Width(s); w < width {
		return s + strings.Repeat(" ", width-w)
	}
	return s
}

func padLines(s string, width int) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = clipPad(l, width)
	}
	return strings.Join(lines, "\n")
}

func avg(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func maxOf(values []float64) float64 {
	max := 0.0
	for _, v := range values {
		if v > max {
			max = v
		}
	}
	return max
}
