package ui

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"deadeye/internal/ai"
	"deadeye/internal/proc"
)

const aiInputLimit = 400

type aiEntryKind int

const (
	aiNote aiEntryKind = iota
	aiQuestion
	aiAnswer
	aiError
)

type aiEntry struct {
	kind  aiEntryKind
	title string
	text  string
	at    time.Time
	pid   int
}

type aiAnswerMsg struct {
	entry aiEntry
	err   error
}

type aiStatusMsg ai.Status

func (m *Model) aiExplainSelected() tea.Cmd {
	s, ok := m.selected()
	if !ok {
		m.setStatus("no process selected", true, 4*time.Second)
		return nil
	}
	return m.aiExplain(s.PID)
}

func (m *Model) aiExplain(pid int) tea.Cmd {
	var s proc.Snapshot
	found := false
	for _, p := range m.procs {
		if p.PID == pid {
			s, found = p, true
			break
		}
	}
	if !found {
		m.setStatus(fmt.Sprintf("PID %d is no longer visible in /proc", pid), true, 5*time.Second)
		return nil
	}

	anoms := m.anomIndex[pid]
	desc := countDescendants(m.procs, pid)
	digest := ai.ProcessDigest(s, anoms, desc, m.sys.Uptime)

	e := aiEntry{
		kind:  aiQuestion,
		title: fmt.Sprintf("digest for PID %d (%s)", pid, s.DisplayName()),
		text:  digest,
		pid:   pid,
	}
	m.journal.Actionf("ai", pid, s.DisplayName(),
		"asked the local model for an explanation (digest %d chars, %d anomalies)",
		len(digest), len(anoms))
	m.setPane(paneAI)
	return m.aiAsk(e, m.cfg.AI.SystemPrompt, ai.ExplainProcessPrompt(digest))
}

func (m *Model) aiAskSystem(question string) tea.Cmd {
	question = strings.TrimSpace(question)
	if question == "" {
		return nil
	}
	digest := m.systemDigestForAI()
	e := aiEntry{kind: aiQuestion, title: "question about the system", text: question}
	m.journal.Actionf("ai", 0, "", "free-form question to the model: %s", truncateWords(question, 80))
	return m.aiAsk(e, m.cfg.AI.SystemPrompt,
		digest+"\n\nUser question: "+question)
}

func (m *Model) systemDigestForAI() string {
	running, blocked, zombies := 0, 0, 0
	for _, s := range m.procs {
		switch s.State {
		case proc.StateRunning:
			running++
		case proc.StateDiskSleep:
			blocked++
		case proc.StateZombie:
			zombies++
		}
	}
	top := append([]proc.Snapshot(nil), m.procs...)
	sort.SliceStable(top, func(i, j int) bool { return top[i].CPUPercent > top[j].CPUPercent })
	if len(top) > 8 {
		top = top[:8]
	}
	memUsed := float64(m.sys.MemTotalKiB) - float64(m.sys.MemAvailableKiB)
	return ai.SystemDigest(len(m.procs), running, blocked, zombies,
		m.sys.CPUPercent, memUsed, float64(m.sys.MemTotalKiB), top, m.sys.Uptime)
}

type aiPendingAsk struct {
	system string
	prompt string
	pid    int
}

func (m *Model) aiAsk(e aiEntry, system, prompt string) tea.Cmd {
	if m.aiBusy {
		m.setStatus("the previous request to the model has not finished yet (Esc — cancel)", false, 5*time.Second)
		return nil
	}
	if m.ai == nil {
		m.setStatus("the local model client is not initialized", true, 6*time.Second)
		return nil
	}
	e.at = time.Now()
	m.pushAI(e)

	switch {
	case m.aiStatus.Available:
		return m.aiAskPrepared(system, prompt, e.pid)
	case m.aiStatus.CheckedAt.IsZero():
		m.aiPending = &aiPendingAsk{system: system, prompt: prompt, pid: e.pid}
		m.aiProbed = true
		m.setStatus("checking local model availability…", false, 6*time.Second)
		return m.aiProbe()
	}
	m.pushAI(aiEntry{kind: aiError, title: "model unavailable",
		text: m.aiUnavailableText()})
	return nil
}

func (m *Model) aiAskPrepared(system, prompt string, pid int) tea.Cmd {
	m.aiBusy = true
	ctx, cancel := context.WithCancel(context.Background())
	m.aiCancel = cancel

	client := m.ai
	return func() tea.Msg {
		defer cancel()
		text, err := client.Generate(ctx, system, prompt)
		if err != nil {
			return aiAnswerMsg{entry: aiEntry{kind: aiError,
				title: "the request to the model failed"}, err: err}
		}
		return aiAnswerMsg{entry: aiEntry{kind: aiAnswer,
			title: "answer from " + client.Config().Model, text: text, pid: pid}}
	}
}

func (m *Model) aiCancelRequest() {
	if !m.aiBusy {
		return
	}
	if m.aiCancel != nil {
		m.aiCancel()
		m.aiCancel = nil
	}
	m.aiBusy = false
	m.pushAI(aiEntry{kind: aiNote, title: "request cancelled",
		text: "No answer was received. keep_alive = 0, so the model weights did not stay in memory."})
	m.setStatus("the request to the model was cancelled", false, 4*time.Second)
}

func (m *Model) pushAI(e aiEntry) {
	if e.at.IsZero() {
		e.at = time.Now()
	}
	m.aiChat = append(m.aiChat, e)

	if max := 200; len(m.aiChat) > max {
		m.aiChat = m.aiChat[len(m.aiChat)-max:]
	}
	m.aiScroll = 0
}

func (m *Model) aiUnavailableText() string {
	st := m.aiStatus
	if st.Endpoint == "" && m.ai != nil {
		st.Endpoint = m.ai.Config().Endpoint
	}
	if st.Model == "" && m.ai != nil {
		st.Model = m.ai.Config().Model
	}
	var b strings.Builder
	if st.Err != "" {
		fmt.Fprintf(&b, "%s.\n\n", st.Err)
	}
	b.WriteString("The local model is not installed yet. Once, on this machine:\n")
	b.WriteString("  1. curl -fsSL https://ollama.com/install.sh | sh\n")
	fmt.Fprintf(&b, "  2. ollama pull %s\n", st.Model)
	b.WriteString("After that the model starts by itself when you open the tab: no\n")
	b.WriteString("servers or commands need to be started by hand.\n\n")
	b.WriteString("The program works without the model too: measurements, anomalies,\n")
	b.WriteString("the tree, groups and Smart Kill do not depend on it.")
	return b.String()
}

func (m *Model) aiEnsureProbed() tea.Cmd {
	if m.pane != paneAI || m.aiProbed || m.ai == nil {
		return nil
	}
	m.aiProbed = true
	return m.aiProbe()
}

func (m *Model) aiProbe() tea.Cmd {
	if m.ai == nil {
		return nil
	}
	client := m.ai
	return func() tea.Msg {
		if !m.aiAutoStartDone {

			ctx0, cancel0 := context.WithTimeout(context.Background(), 1200*time.Millisecond)
			up0 := client.Probe(ctx0).Available
			cancel0()
			if !up0 {
				if path, err := exec.LookPath("ollama"); err == nil {
					m.startOllama(path)
					time.Sleep(1500 * time.Millisecond)
				}
			}
			m.aiAutoStartDone = true
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return aiStatusMsg(client.Probe(ctx))
	}
}

func (m *Model) startOllama(path string) {
	cmd := exec.Command(path, "serve")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0); err == nil {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, devnull, devnull
		defer devnull.Close()
	}
	if err := cmd.Start(); err == nil {
		go cmd.Wait()
	}
}

func (m *Model) renderAI(h int) string {
	inner := m.width - 4
	if inner < 24 {
		inner = 24
	}
	st := m.aiStatus

	var lines []string
	switch {
	case m.aiBusy:
		lines = append(lines, accStyle.Render(clipPad(
			" model "+st.Model+" is answering… (Esc — cancel)", inner)))
	case st.Available:
		lines = append(lines, okStyle.Render(clipPad(fmt.Sprintf(
			" model %s · %s · poll %d ms · unloads after answering (keep_alive = 0)",
			st.Model, st.Endpoint, st.LatencyMs), inner)))
	case st.CheckedAt.IsZero():
		lines = append(lines, dimStyle.Render(clipPad(
			" model availability not checked yet — press r", inner)))
	default:
		lines = append(lines, warnStyle.Render(clipPad(
			" model unavailable: "+st.Err, inner)))
	}
	lines = append(lines, dimStyle.Render(clipPad(
		" a — explain the selected process · r — recheck · Esc — cancel", inner)))
	lines = append(lines, "")

	bodyH := h - 8
	if bodyH < 3 {
		bodyH = 3
	}

	rendered := make([]string, 0, len(m.aiChat)*4+8)
	if len(m.aiChat) == 0 {
		rendered = append(rendered,
			dimStyle.Render(clipPad(" Feed is empty.", inner)),
			dimStyle.Render(clipPad(" Select a process on the «Processes» tab and press a —", inner)),
			dimStyle.Render(clipPad(" the model will explain what it is and whether its numbers are normal.", inner)),
			"")
		if !st.Available {
			for _, l := range strings.Split(m.aiUnavailableText(), "\n") {
				rendered = append(rendered, dimStyle.Render(clipPad(" "+l, inner)))
			}
		}
	} else {
		for _, e := range m.aiChat {
			rendered = append(rendered, m.renderAIEntry(e, inner)...)
		}
	}

	if m.aiScroll < 0 {
		m.aiScroll = 0
	}
	maxScroll := len(rendered) - bodyH
	if maxScroll < 0 {
		maxScroll = 0
	}
	if m.aiScroll > maxScroll {
		m.aiScroll = maxScroll
	}
	end := len(rendered) - m.aiScroll
	start := end - bodyH
	if start < 0 {
		start = 0
	}
	visible := rendered[start:end]
	for len(visible) < bodyH {
		visible = append(visible, "")
	}
	lines = append(lines, visible...)
	if start > 0 {
		lines[len(lines)-bodyH] = dimStyle.Render(clipPad(
			fmt.Sprintf(" ↑ %d more lines above (PgUp)", start), inner))
	}

	hint := " a — explain the selected process · r — check model · Esc — cancel"
	lines = append(lines, dimStyle.Render(clipPad(hint, inner)))

	title := "AI  ·  local model explains /proc numbers"
	return panelBoxH(clipPad(headerStyle.Render(title), inner),
		strings.Join(lines, "\n"), m.width, h)
}

func (m *Model) renderAIEntry(e aiEntry, inner int) []string {
	head := fmt.Sprintf(" %s  %s", e.at.Format("15:04:05"), e.title)
	switch e.kind {
	case aiQuestion:
		head = accStyle.Render(clipPad(head, inner))
	case aiAnswer:
		head = okStyle.Render(clipPad(head, inner))
	case aiError:
		head = badStyle.Render(clipPad(head, inner))
	default:
		head = dimStyle.Render(clipPad(head, inner))
	}
	out := []string{head}
	body := e.text
	if body == "" {
		body = "(empty)"
	}

	maxLines := 10
	switch e.kind {
	case aiQuestion:
		maxLines = 3
	case aiError, aiNote:
		maxLines = 40
	}
	for _, l := range wrapText(body, inner-4, maxLines) {
		out = append(out, clipPad("   "+l, inner))
	}
	out = append(out, "")
	return out
}

func (m *Model) handleAIKey(msg tea.Msg) (tea.Cmd, bool) {
	key, ok := msg.(tea.KeyMsg)
	if !ok {
		return nil, false
	}
	k := key.String()

	rows := m.bodyHeight - 8
	if rows < 1 {
		rows = 1
	}
	switch k {
	case "/", "i", ".":

		m.setStatus("no free-form input: a — explain the process, r — check the model", false, 4*time.Second)
		return nil, true
	case "a":
		if m.selectedPID <= 0 {
			m.setStatus("first select a process on the «Processes» tab", true, 5*time.Second)
			return nil, true
		}
		return m.aiExplain(m.selectedPID), true
	case "r":
		m.setStatus("checking local model availability…", false, 4*time.Second)
		return m.aiProbe(), true
	case "esc":
		m.aiCancelRequest()
		return nil, true
	case "up", "k":
		m.aiScroll += rows
		return nil, true
	case "down", "j":
		m.aiScroll -= rows
		if m.aiScroll < 0 {
			m.aiScroll = 0
		}
		return nil, true
	case "pgup", "ctrl+u":
		m.aiScroll += rows * 2
		return nil, true
	case "pgdown", "ctrl+d":
		m.aiScroll -= rows * 2
		if m.aiScroll < 0 {
			m.aiScroll = 0
		}
		return nil, true
	case "g":
		m.aiScroll = 1 << 20
		return nil, true
	case "G":
		m.aiScroll = 0
		return nil, true
	}
	return nil, false
}

func trimLastWord(s string) string {
	r := []rune(strings.TrimRight(s, " "))
	i := len(r) - 1
	for i >= 0 && r[i] != ' ' {
		i--
	}
	return strings.TrimRight(string(r[:i+1]), " ")
}

func countDescendants(list []proc.Snapshot, pid int) int {
	kids := make(map[int][]int, len(list))
	for _, s := range list {
		if s.PPID > 0 && s.PPID != s.PID {
			kids[s.PPID] = append(kids[s.PPID], s.PID)
		}
	}
	seen := make(map[int]bool, 16)

	seen[pid] = true
	var walk func(p, depth int)
	walk = func(p, depth int) {
		if depth > 32 {
			return
		}
		for _, c := range kids[p] {
			if seen[c] {
				continue
			}
			seen[c] = true
			walk(c, depth+1)
		}
	}
	walk(pid, 0)

	return len(seen) - 1
}
