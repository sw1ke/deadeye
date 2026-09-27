package ui

import (
	"context"
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/charmbracelet/lipgloss"

	"deadeye/internal/human"
	"deadeye/internal/proc"
	"deadeye/internal/security"
)

type secScanMsg struct {
	rep security.Report
	err error
}

type secExternalMsg struct {
	rep security.Report
	err error
}

func (m *Model) secInit() {
	if m.sec == nil {
		cfg := m.cfg.SecurityConfig()
		m.sec = security.NewScanner(cfg)
		if cfg.DeepSeek.Enabled && cfg.DeepSeek.APIKey != "" {
			m.secClient = security.NewDeepSeekClient(cfg.DeepSeek)

			m.secMode = 1
		}
	}
}

func (m *Model) secScan() tea.Cmd {
	m.secInit()
	if m.secBusy {
		m.setStatus("scan already running", true, 3*time.Second)
		return nil
	}
	m.secBusy = true
	m.setStatus("checking: processes, autostart, network…", false, 0)

	sc := m.sec
	procs := make([]proc.Snapshot, len(m.procs))
	copy(procs, m.procs)

	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		rep := sc.Scan(ctx, procs)
		if len(rep.Errors) > 0 {
			return secScanMsg{rep: rep, err: fmt.Errorf("%s", strings.Join(rep.Errors, "; "))}
		}
		return secScanMsg{rep: rep}
	}
}

func (m *Model) secApply(rep security.Report) {
	m.secReport = rep
	m.secBusy = false
	m.secFilterItems()
}

func secMinTitle(l security.Level) string {
	switch l {
	case security.LevelNote:
		return "all findings"
	case security.LevelLow:
		return "≥ low"
	case security.LevelMedium:
		return "≥ medium"
	case security.LevelHigh:
		return "≥ high"
	case security.LevelCritical:
		return "critical only"
	}
	return "all findings"
}

func (m *Model) secFilterItems() {
	prev := -1
	if f, ok := m.secSelected(); ok {
		prev = f.PID
		if prev == 0 {
			prev = -2
		}
	}
	out := make([]security.Finding, 0, len(m.secReport.Findings))
	for _, f := range m.secReport.Findings {
		if f.Level >= m.secMin {
			out = append(out, f)
		}
	}
	m.secItems = out
	m.secFixCursor(prev)
}

func (m *Model) secFixCursor(prevPID int) {
	if len(m.secItems) == 0 {
		m.secCursor, m.secScroll = 0, 0
		return
	}
	if prevPID > 0 {
		for i, f := range m.secItems {
			if f.PID == prevPID {
				m.secCursor = i
				m.secScrollTo(i)
				return
			}
		}
	}
	if m.secCursor >= len(m.secItems) {
		m.secCursor = len(m.secItems) - 1
	}
	if m.secCursor < 0 {
		m.secCursor = 0
	}
	m.secScrollTo(m.secCursor)
}

func (m *Model) secSelected() (security.Finding, bool) {
	if m.secCursor < 0 || m.secCursor >= len(m.secItems) {
		return security.Finding{}, false
	}
	return m.secItems[m.secCursor], true
}

func (m *Model) secMove(n int) {
	if len(m.secItems) == 0 {
		m.secCursor = 0
		return
	}
	m.secCursor += n
	if m.secCursor < 0 {
		m.secCursor = 0
	}
	if m.secCursor > len(m.secItems)-1 {
		m.secCursor = len(m.secItems) - 1
	}
	m.secScrollTo(m.secCursor)
}

func (m *Model) secVisible() int {
	v := m.bodyHeight - 3 - m.secDetailHeight()
	if v < 1 {
		v = 1
	}
	return v
}

func (m *Model) secDetailHeight() int {
	n := len(m.secDetailLines(80))
	max := m.bodyHeight - 5
	if max < 2 {
		max = 2
	}
	if n > max {
		n = max
	}
	return n
}

func (m *Model) secScrollTo(i int) {
	vis := m.secVisible()
	if i < m.secScroll {
		m.secScroll = i
	}
	if i >= m.secScroll+vis {
		m.secScroll = i - vis + 1
	}
	if m.secScroll < 0 {
		m.secScroll = 0
	}
}

type secWidths struct {
	mark, kind, subject, detail int
}

func secWidthsFor(inner int) secWidths {
	w := secWidths{mark: 4, kind: 26, subject: 26, detail: 30}
	switch {
	case inner >= 120:
		w.detail = inner - w.mark - w.kind - w.subject
	case inner >= 96:
		w.subject = 20
		w.detail = inner - w.mark - w.kind - w.subject
	case inner >= 72:
		w.kind = 18
		w.subject = 0
		w.detail = inner - w.mark - w.kind
	default:
		w.kind = 14
		w.subject = 0
		w.detail = inner - w.mark - w.kind
	}
	if w.detail < 6 {
		w.detail = 6
	}
	return w
}

func secLevelStyle(l security.Level) lipgloss.Style {
	switch {
	case l >= security.LevelCritical:
		return rowBadStyle
	case l >= security.LevelHigh:
		return rowWarnStyle
	case l >= security.LevelMedium:
		return rowStyle
	default:
		return rowDimStyle
	}
}

func secRow(f security.Finding, w secWidths) string {
	var b strings.Builder

	b.WriteString(pad(f.Level.Mark(), w.mark))
	b.WriteString(pad(clipTo(f.Kind, w.kind-1), w.kind))
	if w.subject > 0 {
		subject := f.Subject
		if f.PID > 0 && subject == "" {
			subject = fmt.Sprintf("PID %d", f.PID)
		}
		b.WriteString(pad(clipTo(subject, w.subject-1), w.subject))
	}
	b.WriteString(clipTo(f.Detail, w.detail))
	return b.String()
}

func (m *Model) renderSec(h int) string {
	inner := m.width - 4
	if inner < 24 {
		inner = 24
	}
	var b strings.Builder

	b.WriteString(clipPad(headerStyle.Render(m.pane.title()), inner))
	b.WriteString("\n")

	modeLine := "  MODE:  "
	left := "LOCAL ONLY"
	right := "LOCAL + DEEPSEEK"
	if m.secMode == 1 {
		modeLine += dimStyle.Render("[ ") + textStyle.Render(left) + dimStyle.Render(" ]  ") +
			selectedStyle.Render("[ "+right+" ]")
	} else {
		modeLine += selectedStyle.Render("[ "+left+" ]") +
			dimStyle.Render("  [ ") + textStyle.Render(right) + dimStyle.Render(" ]")
	}
	modeLine += dimStyle.Render("   —  m toggles")
	b.WriteString(clipPad(modeLine, inner))
	b.WriteString("\n")

	b.WriteString(clipPad(dimStyle.Render(" "+m.secSummaryLine(inner)), inner))
	b.WriteString("\n")

	if m.secBusy {
		b.WriteString(clipPad(accStyle.Render(" scanning…"), inner))
		b.WriteString("\n")
		return padToHeight(b.String(), h, m.width)
	}

	if m.secReport.ScannedAt.IsZero() {

		b.WriteString(fitLines(m.secEmptyIntro(inner), h-2))
		return padToHeight(b.String(), h, m.width)
	}

	if len(m.secItems) == 0 {
		b.WriteString(fitLines(m.secEmptyResult(inner), h-2))
		return padToHeight(b.String(), h, m.width)
	}

	w := secWidthsFor(inner)
	b.WriteString(colHeadStyle.Render(clipTo(secHeaderRow(w), inner)))
	b.WriteString("\n")

	detail := m.secDetailLines(inner)
	vis := h - 3 - len(detail)
	if vis < 1 {
		vis = 1
	}
	if m.secScroll > len(m.secItems)-vis {
		m.secScroll = len(m.secItems) - vis
	}
	if m.secScroll < 0 {
		m.secScroll = 0
	}
	end := m.secScroll + vis
	if end > len(m.secItems) {
		end = len(m.secItems)
	}
	for i := m.secScroll; i < end; i++ {
		f := m.secItems[i]
		line := clipTo(secRow(f, w), inner)
		if i == m.secCursor {
			b.WriteString(selectedStyle.Render(line))
		} else {
			b.WriteString(secLevelStyle(f.Level).Render(line))
		}
		b.WriteString("\n")
	}

	table := padToHeight(b.String(), h-len(detail), m.width)

	var out strings.Builder
	out.WriteString(table)

	if !strings.HasSuffix(table, "\n") {
		out.WriteString("\n")
	}
	for _, ln := range detail {
		out.WriteString(clipPad(ln, inner))
		out.WriteString("\n")
	}
	return padToHeight(out.String(), h, m.width)
}

func secHeaderRow(w secWidths) string {
	var b strings.Builder
	b.WriteString(pad(" ", w.mark))
	b.WriteString(pad("WHAT", w.kind-1))
	if w.subject > 0 {
		b.WriteString(pad("WHERE", w.subject-1))
	}
	b.WriteString("WHY SUSPICIOUS")
	return b.String()
}

func (m *Model) secVariant() string {
	cfg := m.cfg.SecurityConfig()
	if !cfg.Enabled {
		return "scanner disabled ([security].enabled = false)"
	}
	if m.secMode == 0 {
		return "variant 1: local checks only · m — enable hash reputation"
	}
	if !cfg.DeepSeek.Enabled || cfg.DeepSeek.APIKey == "" {
		return "variant 2: on, but no api_key ([security.deepseek].api_key)"
	}
	left := cfg.DeepSeek.MaxRequestsPerDay - m.secReport.ExternalCalls
	return fmt.Sprintf("variant 2: local + DeepSeek hash reputation (%d left) · m — turn off",
		left)
}

func (m *Model) secSummaryLine(inner int) string {
	rep := m.secReport
	c := rep.Counts()
	parts := []string{
		fmt.Sprintf("!!! %d", c[security.LevelCritical]),
		fmt.Sprintf("!! %d", c[security.LevelHigh]),
		fmt.Sprintf("! %d", c[security.LevelMedium]),
		fmt.Sprintf("+ %d", c[security.LevelLow]),
	}
	s := strings.Join(parts, "  ·  ") + fmt.Sprintf("  ·  %d total", len(rep.Findings))

	appendIfFits := func(part string) {
		candidate := s + "  ·  " + part
		if lipgloss.Width(candidate) <= inner-2 {
			s = candidate
		}
	}
	appendIfFits(fmt.Sprintf("filter: %s (L)", secMinTitle(m.secMin)))
	appendIfFits(fmt.Sprintf("processes %d · autostarts %d · listeners %d",
		rep.ProcsSeen, rep.Autostarts, rep.Listeners))
	return s
}

func (m *Model) secEmptyIntro(inner int) string {
	var b strings.Builder
	for _, ln := range []string{
		"",
		" Press r to check the system.",
		"",
		" What this tab checks:",
		"   processes    launch from /tmp, /dev/shm, /mnt; deleted binary; file,",
		"                writable by everyone; pool protocol, curl | sh,",
		"                base64 -d | sh, nc -e, LD_PRELOAD and LD_AUDIT in environment;",
		"   autostart    ~/.config/autostart, systemd units, hypr, fish, .bashrc,",
		"                cron — and system file ownership by packages;",
		"   network      who listens on ports and whether a socket is visible",
		"                beyond this machine.",
		"",
		" Findings are ranked by severity: !!! critical, !! high,",
		" ! medium, + low. The list is sorted from worst to best.",
		"",
		" These are heuristics, not an antivirus database: they catch behavior and file location,",
	} {
		b.WriteString(dimStyle.Render(clipTo(ln, inner)))
		b.WriteString("\n")
	}
	if m.secErr != "" {
		b.WriteString(badStyle.Render(clipTo(" "+m.secErr, inner)))
		b.WriteString("\n")
	}
	return b.String()
}

func (m *Model) secEmptyResult(inner int) string {
	var b strings.Builder
	lines := []string{
		"",
		fmt.Sprintf(" Scan completed %s in %s.",
			m.secReport.ScannedAt.Format("15:04:05"),
			m.secReport.Duration.Round(time.Millisecond)),
		fmt.Sprintf(" Processes: %d · autostart entries: %d · listening sockets: %d.",
			m.secReport.ProcsSeen, m.secReport.Autostarts, m.secReport.Listeners),
		"",
		fmt.Sprintf(" Nothing matches the «%s» filter.", secMinTitle(m.secMin)),
		" Press L to loosen the filter, or r to scan again.",
	}
	if m.secReport.FilesHashed > 0 {
		lines = append(lines, fmt.Sprintf(" Hashes computed: %d.", m.secReport.FilesHashed))
	}
	for _, ln := range lines {
		b.WriteString(dimStyle.Render(clipTo(ln, inner)))
		b.WriteString("\n")
	}
	return b.String()
}

func (m *Model) secDetailLines(inner int) []string {
	f, ok := m.secSelected()
	if !ok {
		return []string{"", dimStyle.Render(clipTo(" Nothing selected.", inner))}
	}
	title := titleStyle.Render(clipTo(" "+f.Title(), inner))
	head := []string{"", title}
	evidence := make([]string, 0, 4)
	for i, ev := range f.Evidence {
		if i >= 3 {
			evidence = append(evidence,
				dimStyle.Render(clipTo(fmt.Sprintf(" …and %d more clues", len(f.Evidence)-3), inner)))
			break
		}
		evidence = append(evidence, dimStyle.Render(clipTo(" · "+ev, inner)))
	}
	facts := []string{textStyle.Render(clipTo(" Indicator: "+f.Detail, inner))}
	facts = append(facts, evidence...)
	if f.SHA256 != "" {
		facts = append(facts, dimStyle.Render(clipTo(
			fmt.Sprintf(" SHA-256 %s (%s)", human.TruncateMiddle(f.SHA256, 24),
				human.Bytes(float64(f.Size))), inner)))
	}
	if f.Verdict != "" {
		facts = append(facts, accStyle.Render(clipTo(" DeepSeek: "+f.Verdict, inner)))
	}
	tail := make([]string, 0, 2)
	if f.Action != "" {
		tail = append(tail, warnStyle.Render(clipTo(" What to do: "+f.Action, inner)))
	}
	if f.PID > 0 {
		tail = append(tail, dimStyle.Render(clipTo(
			fmt.Sprintf(" Enter — to process %d · F9 — kill · a — ask AI", f.PID), inner)))
	} else {
		tail = append(tail, dimStyle.Render(clipTo(
			" No process: this finding is about a file or configuration", inner)))
	}

	lines := make([]string, 0, len(head)+len(facts)+len(tail))
	lines = append(lines, head...)
	lines = append(lines, facts...)
	lines = append(lines, tail...)

	max := m.bodyHeight - 5
	if max < len(head)+len(tail)+1 {
		max = len(head) + len(tail) + 1
	}
	for len(lines) > max && len(evidence) > 0 {
		dropAt := len(head) + 1 + len(evidence) - 1
		if dropAt >= len(lines) {
			break
		}
		lines = append(lines[:dropAt], lines[dropAt+1:]...)
		evidence = evidence[:len(evidence)-1]
	}
	for len(lines) > max && len(lines) > len(head)+len(tail) {
		lines = append(lines[:len(head)+1], lines[len(head)+2:]...)
	}
	return lines
}

func (m *Model) handleSecKey(msg tea.KeyMsg) (tea.Cmd, bool) {
	switch msg.String() {
	case "up", "k":
		m.secMove(-1)
		return nil, true
	case "down", "j":
		m.secMove(1)
		return nil, true
	case "pgup":
		m.secMove(-m.secVisible())
		return nil, true
	case "pgdown":
		m.secMove(m.secVisible())
		return nil, true
	case "g", "home":
		m.secMove(-len(m.secItems) - 1)
		return nil, true
	case "G", "end":
		m.secMove(len(m.secItems) + 1)
		return nil, true
	case "r":
		m.secErr = ""
		return m.secScan(), true
	case "L", "l":
		m.secCycleFilter()
		return nil, true
	case "m":
		m.secToggleMode()
		return nil, true
	case "e":
		return m.secExternal(), true
	case "a":
		return m.secAskAI(), true
	case "enter":
		return m.secJump(), true
	}
	return nil, false
}

func (m *Model) secCycleFilter() {
	switch m.secMin {
	case security.LevelNote:
		m.secMin = security.LevelCritical
	case security.LevelCritical:
		m.secMin = security.LevelHigh
	case security.LevelHigh:
		m.secMin = security.LevelMedium
	case security.LevelMedium:
		m.secMin = security.LevelLow
	default:
		m.secMin = security.LevelNote
	}
	m.secFilterItems()
	m.setStatus("filter: "+secMinTitle(m.secMin), false, 3*time.Second)
}

func (m *Model) secToggleMode() {
	m.secInit()
	cfg := m.cfg.SecurityConfig()
	if m.secMode == 0 {
		if !cfg.DeepSeek.Enabled || cfg.DeepSeek.APIKey == "" {
			m.setStatus("variant 2 needs an api_key: [security.deepseek].api_key", true, 6*time.Second)
			return
		}
		m.secMode = 1
		m.setStatus("variant 2: local checks + DeepSeek hash reputation", false, 4*time.Second)
		return
	}
	m.secMode = 0
	m.setStatus("variant 1: local checks only", false, 4*time.Second)
}

func (m *Model) secJump() tea.Cmd {
	f, ok := m.secSelected()
	if !ok || f.PID <= 0 {
		m.setStatus("this finding has no process: it is a file or configuration", true, 4*time.Second)
		return nil
	}
	m.setPane(paneProcesses)
	if !m.selectPID(f.PID) {

		for _, pid := range m.ancestorPIDs(f.PID) {
			m.expanded[pid] = true
		}
		m.recompute()
		if !m.selectPID(f.PID) {
			m.setStatus(fmt.Sprintf("process %d has already vanished from the list", f.PID), true, 4*time.Second)
			return nil
		}
	}
	m.setStatus(fmt.Sprintf("process %d (%s)", f.PID, f.Subject), false, 4*time.Second)
	return nil
}

func (m *Model) secExternal() tea.Cmd {
	m.secInit()
	if m.secMode == 0 {
		m.setStatus("external check is off: turn on variant 2 with m", true, 6*time.Second)
		return nil
	}
	cfg := m.cfg.SecurityConfig()
	if !cfg.DeepSeek.Enabled || cfg.DeepSeek.APIKey == "" {
		m.setStatus("variant 2 is on, but no api_key: [security.deepseek].api_key", true, 6*time.Second)
		return nil
	}
	if m.secBusy {
		m.setStatus("wait for the current scan to finish", true, 3*time.Second)
		return nil
	}
	if len(m.secReport.Findings) == 0 {
		m.setStatus("press r first: there is nothing to check by hash yet", true, 5*time.Second)
		return nil
	}
	m.secBusy = true
	m.setStatus("checking hash reputation…", false, 0)

	sc := m.sec
	rep := m.secReport
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		out := sc.External(ctx, rep, nil)
		return secExternalMsg{rep: out}
	}
}

func (m *Model) secAskAI() tea.Cmd {
	f, ok := m.secSelected()
	if !ok {
		m.setStatus("no finding selected", true, 3*time.Second)
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Found on my machine (Linux):\nseverity: %s\nindicator: %s\ndetail: %s\n",
		f.Level, f.Kind, f.Detail)
	if f.Path != "" {
		fmt.Fprintf(&b, "file: %s\n", f.Path)
	}
	if f.PID > 0 {
		fmt.Fprintf(&b, "process: PID %d (%s)\n", f.PID, f.Subject)
	}
	for i, ev := range f.Evidence {
		if i >= 4 {
			break
		}
		fmt.Fprintf(&b, "clue: %s\n", ev)
	}
	if f.SHA256 != "" {
		fmt.Fprintf(&b, "SHA-256: %s\n", f.SHA256)
	}
	if f.Verdict != "" {
		fmt.Fprintf(&b, "the external check said: %s\n", f.Verdict)
	}
	b.WriteString("Is this malware, a legitimate program, or a false positive? " +
		"What exactly should I check and what should I do? Answer briefly.")

	return m.aiAskPrepared(systemPromptSecurity, b.String(), f.PID)
}

const systemPromptSecurity = `You are a security assistant for an ordinary user's Linux machine.
You are given a local scanner finding: severity, indicator, clues, file path.
Answer in Russian, in 4-6 short sentences, without an introduction.
First say whether it looks like malware, a legitimate program, or a false positive.
Then give 2-3 concrete verification steps (you may name commands).
Do not make up facts that are not in the finding.`

func fitLines(s string, n int) string {
	if n <= 0 {
		return ""
	}
	lines := strings.Split(s, "\n")

	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if len(lines) <= n {
		return strings.Join(lines, "\n") + "\n"
	}
	kept := lines[:n]

	if n >= 2 {
		kept[n-1] = dimStyle.Render(fmt.Sprintf(" …%d more lines of explanation did not fit (terminal is short)",
			len(lines)-n+1))
	}
	return strings.Join(kept, "\n") + "\n"
}

func pad(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if w := lipgloss.Width(s); w >= width {
		return s
	} else {
		return s + strings.Repeat(" ", width-w)
	}
}
