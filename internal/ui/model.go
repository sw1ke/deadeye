package ui

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"deadeye/internal/actions"
	"deadeye/internal/ai"
	"deadeye/internal/anomaly"
	"deadeye/internal/config"
	"deadeye/internal/groups"
	"deadeye/internal/human"
	"deadeye/internal/hung"
	"deadeye/internal/launch"
	"deadeye/internal/monitor"
	"deadeye/internal/proc"
	"deadeye/internal/security"
	"deadeye/internal/servers"
	"deadeye/internal/sysinfo"
	"deadeye/internal/system"
	"deadeye/internal/terminal"
)

type filterMode int

const (
	filterAll filterMode = iota
	filterAnomalous
	filterMine
	filterActive
	filterCount
)

func (f filterMode) next() filterMode { return filterMode((int(f) + 1) % int(filterCount)) }

func (f filterMode) title() string {
	switch f {
	case filterAll:
		return "all processes"
	case filterAnomalous:
		return "anomalous only"
	case filterMine:
		return "mine only (uid " + strconv.Itoa(os.Getuid()) + ")"
	case filterActive:
		return "active only (R/D)"
	}
	return "?"
}

type sortKey int

const (
	sortNone sortKey = iota
	sortCPU
	sortTotal
	sortMem
	sortDelta
	sortIO
	sortFD
	sortPID
	sortName
	sortUser
	sortAge
	sortNice
	sortState
	sortKeyCount
)

func (k sortKey) next() sortKey {
	n := int(k) + 1
	if n < int(sortCPU) || n >= int(sortKeyCount) {
		return sortCPU
	}
	return sortKey(n)
}

func (k sortKey) prev() sortKey {
	n := int(k) - 1
	if n < int(sortCPU) || n >= int(sortKeyCount) {
		return sortKey(int(sortKeyCount) - 1)
	}
	return sortKey(n)
}

func (k sortKey) title() string {
	switch k {
	case sortCPU:
		return "CPU%"
	case sortTotal:
		return "TOTAL"
	case sortMem:
		return "RSS"
	case sortDelta:
		return "ΔRSS"
	case sortIO:
		return "I/O"
	case sortFD:
		return "fds"
	case sortPID:
		return "PID"
	case sortName:
		return "name"
	case sortUser:
		return "user"
	case sortAge:
		return "age"
	case sortNice:
		return "nice"
	case sortState:
		return "state"
	}
	return "?"
}

func sortKeyFromString(s string) sortKey {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "pid":
		return sortPID
	case "name":
		return sortName
	case "user":
		return sortUser
	case "total":
		return sortTotal
	case "mem", "rss":
		return sortMem
	case "delta", "drss":
		return sortDelta
	case "io":
		return sortIO
	case "fd":
		return sortFD
	case "age":
		return sortAge
	case "nice":
		return sortNice
	case "state":
		return sortState
	case "none":
		return sortPID
	default:
		return sortCPU
	}
}

type dataMsg struct{}

type clockMsg time.Time

type contMsg struct {
	pid  int
	name string
	err  error
}

type reniceMsg struct {
	pid     int
	name    string
	oldNice int
	newNice int
	err     error
}

type killStageMsg actions.StageRecord

type noteMsg struct {
	text  string
	isErr bool
}

type killDoneMsg struct {
	report actions.KillReport
	err    error
}

type confirmState struct {
	pid      int
	name     string
	user     string
	start    time.Time
	coredump bool

	scope      actions.KillScope
	tree       []int
	treeRSS    int64
	parentPID  int
	parentName string
	running    bool
	stage      string
	detail     string
	started    time.Time
}

type Model struct {
	cfg     *config.Config
	mon     *monitor.Monitor
	det     *anomaly.Detector
	act     *actions.Manager
	journal *actions.Log
	version string
	program *tea.Program

	updates <-chan struct{}

	procs     []proc.Snapshot
	visible   []proc.Snapshot
	rows      []row
	sys       sysinfo.Stats
	anoms     []anomaly.Anomaly
	anomIndex map[int][]anomaly.Anomaly
	events    []actions.Event

	width, height int
	ready         bool
	bodyHeight    int
	tableTop      int

	pane      pane
	nyanFrame int
	cursor    int
	// cursorMoved becomes true once the user moves the selection manually.
	// Until then the cursor just stays on the top row: the first snapshots
	// have no CPU data yet, the sort is degenerate, and pinning whatever
	// happens to sit at row 0 (usually PID 1) would drag the whole view to
	// the bottom of the list.
	cursorMoved bool
	scroll      int
	logScroll   int

	transparentNames []string

	helpScroll int
	helpTotal  int

	logCursor int
	logFilter logFilter

	selectedPID   int
	selectedStart time.Time

	sortKey     sortKey
	sortDesc    bool
	filter      filterMode
	search      string
	searching   bool
	showCmdline bool
	showHelp    bool

	treeMode   bool
	treeDepth  int
	treeIdx    *treeIndex
	expanded   map[int]bool
	sortSettle time.Duration
	userFirst  bool
	lastSort   time.Time
	rootOrder  []int

	// LEADERS lists: re-sorted on the settle timer, not on every tick.
	leaderCPU []proc.Snapshot
	leaderMem []proc.Snapshot
	leaderAt  time.Time

	smooth  map[int]float64
	lastSig string

	confirm *confirmState

	groupList   []groups.Group
	groupShown  []groups.Group
	groupLines  []groupLine
	groupCursor int
	groupScroll int
	groupOpen   map[groups.Kind]bool
	groupCache  map[string]groups.Kind
	groupKill   *groupKill

	ownPID int

	ai       *ai.Client
	aiStatus ai.Status
	aiChat   []aiEntry
	aiInput  string
	aiTyping bool
	aiBusy   bool
	aiScroll int
	aiCancel context.CancelFunc

	aiProbed bool

	aiPending *aiPendingAsk

	hungTracker     *hung.Tracker
	hungItems       []hung.Item
	hungCursor      int
	hungScroll      int
	hungSelectedPID int

	sec       *security.Scanner
	secClient *security.DeepSeekClient
	secReport security.Report
	secItems  []security.Finding
	secMin    security.Level
	secCursor int
	secScroll int
	secBusy   bool
	secErr    string
	secMode   int

	sysSections  []sysSection
	sysItems     []system.Spec
	sysCursor    int
	sysScroll    int
	sysBusy      bool
	sysResult    system.Result
	sysHasResult bool
	sysConfirm   *system.Spec
	sysPending   *system.Spec
	sysR         *system.Runner
	sysInput     bool
	sysInputBuf  string
	sysInputSpec system.Spec
	sysInputAsk  string

	term        *terminal.Terminal
	termErr     string
	termReading bool

	aiAutoStartDone bool

	launchFiles      []string
	launchItems      []launch.Entry
	launchAppsLoaded []launch.App
	launchCursor     int
	launchScroll     int
	launchInput      bool
	launchInputB     string
	launchMsg        string
	launchFilter     string
	launchFiltering  bool

	srvLoaded  bool
	srvList    []servers.Server
	srvCursor  int
	srvScroll  int
	srvInput   bool
	srvInputB  string
	srvStep    int
	srvDraft   servers.Server
	srvMsg     string
	srvBusy    bool
	srvTunnels map[string]*servers.Tunnel

	status      string
	statusIsErr bool
	statusUntil time.Time

	ownUID    int
	startedAt time.Time
	quitting  bool
	fatalErr  error
}

func NewModel(cfg *config.Config, mon *monitor.Monitor, det *anomaly.Detector,
	act *actions.Manager, journal *actions.Log, version string, updates <-chan struct{}) *Model {

	transparent := make([]string, 0, len(cfg.UI.TransparentNames))
	for _, n := range cfg.UI.TransparentNames {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" {
			transparent = append(transparent, n)
		}
	}

	return &Model{
		cfg:              cfg,
		mon:              mon,
		det:              det,
		act:              act,
		journal:          journal,
		version:          version,
		updates:          updates,
		anomIndex:        make(map[int][]anomaly.Anomaly),
		pane:             paneProcesses,
		sortKey:          sortKeyFromString(cfg.UI.SortColumn),
		sortDesc:         cfg.UI.SortDesc,
		filter:           filterAll,
		showCmdline:      cfg.UI.ShowCmdline,
		ownUID:           os.Getuid(),
		treeMode:         cfg.UI.TreeView,
		expanded:         make(map[int]bool),
		sortSettle:       time.Duration(cfg.UI.SortSettleMs) * time.Millisecond,
		userFirst:        cfg.UI.UserFirst,
		transparentNames: transparent,
		groupOpen:        make(map[groups.Kind]bool),
		groupCache:       make(map[string]groups.Kind, 64),
		ownPID:           os.Getpid(),
		ai:               ai.NewClient(cfg.AI),
	}
}

func (m *Model) SetProgram(p *tea.Program) { m.program = p }

func (m *Model) Init() tea.Cmd {
	m.startedAt = time.Now()
	m.refresh()
	m.setStatus("Deadeye started. q — quit, ? — help", false, 10*time.Second)
	if err := m.mon.LastError(); err != nil {
		m.setStatus("collector error: "+err.Error(), true, 15*time.Second)
	}
	return tea.Batch(waitForData(m.updates), tickClock(time.Second), tickNyan())
}

func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:

		m.width, m.height = msg.Width, msg.Height
		m.ready = msg.Width >= 60 && msg.Height >= 12
		m.clampScroll()
		if m.term != nil {
			m.termResize()
		}
		return m, nil

	case dataMsg:
		m.refresh()
		return m, waitForData(m.updates)

	case clockMsg:

		return m, tickClock(time.Second)

	case nyanMsg:
		m.nyanFrame++
		return m, tickNyan()

	case termOutputMsg:

		m.termReading = false
		if m.pane == paneTerminal && m.term != nil && !m.term.Closed() {
			m.termReading = true
			return m, m.termRead()
		}
		return m, nil

	case termClosedMsg:
		m.termReading = false
		m.setStatus("shell exited", false, 5*time.Second)
		return m, nil

	case termResizeMsg:
		m.termResize()
		return m, nil

	case secScanMsg:
		m.secBusy = false
		if msg.err != nil {
			m.secErr = msg.err.Error()
			m.setStatus("check finished with findings: "+msg.err.Error(), true, 8*time.Second)
		} else {
			m.secErr = ""
			m.setStatus(fmt.Sprintf("check done: %s", msg.rep.Summary()), false, 8*time.Second)
		}
		m.secApply(msg.rep)
		return m, nil

	case secExternalMsg:
		m.secBusy = false
		if msg.err != nil {
			m.setStatus("external check failed: "+msg.err.Error(), true, 8*time.Second)
			return m, nil
		}
		m.secApply(msg.rep)
		m.setStatus(fmt.Sprintf("external check: %d requests, %d skipped by limit",
			msg.rep.ExternalCalls, msg.rep.ExternalSkipped), false, 8*time.Second)
		if msg.rep.ExternalCalls > 0 {
			m.journal.Actionf("security", 0, "",
				"hash reputation check: %d requests to DeepSeek", msg.rep.ExternalCalls)
		}
		return m, nil

	case sysResultMsg:
		return m, m.handleSysResult(msg)

	case srvTunnelMsg:
		return m, m.srvTunnelOpened(msg)

	case sysNeedRootMsg:
		return m, m.sysNeedRoot(msg)

	case sysStartMsg:
		return m, m.sysStarted(msg)

	case contMsg:
		if msg.err != nil {
			m.setStatus(fmt.Sprintf("SIGCONT PID %d: %v", msg.pid, msg.err), true, 10*time.Second)
			m.journal.Errorf("signal", msg.pid, msg.name, "SIGCONT not sent: %v", msg.err)
		} else {
			m.setStatus(fmt.Sprintf("PID %d (%s): SIGCONT sent, process resumed", msg.pid, msg.name), false, 6*time.Second)
			m.journal.Actionf("signal", msg.pid, msg.name, "SIGCONT sent")
		}
		m.refresh()
		return m, nil

	case reniceMsg:
		if msg.err != nil {
			m.setStatus(fmt.Sprintf("nice PID %d: %v", msg.pid, msg.err), true, 10*time.Second)
		} else {
			m.setStatus(fmt.Sprintf("PID %d (%s): nice %d → %d", msg.pid, msg.name, msg.oldNice, msg.newNice), false, 6*time.Second)
		}
		m.refresh()
		return m, nil

	case aiAnswerMsg:
		m.aiBusy = false
		if msg.err != nil {
			if context.Canceled == msg.err || strings.Contains(msg.err.Error(), "context canceled") {
				break
			}
			msg.entry.text = msg.err.Error()
			if m.ai != nil && !strings.Contains(msg.err.Error(), "not responding") {
				msg.entry.text += "\n\n" + m.aiUnavailableText()
			}
			m.pushAI(msg.entry)
			m.setStatus("model did not respond: "+truncateWords(msg.err.Error(), 60), true, 12*time.Second)
			m.journal.Errorf("ai", msg.entry.pid, "", "model request failed: %v", msg.err)
		} else {
			m.pushAI(msg.entry)
			m.setStatus("model responded", false, 5*time.Second)
		}
		return m, nil

	case aiStatusMsg:
		m.aiStatus = ai.Status(msg)
		pend := m.aiPending
		m.aiPending = nil
		if m.aiStatus.Available {
			m.setStatus(fmt.Sprintf("local model available: %s (%s)",
				m.aiStatus.Model, m.aiStatus.Endpoint), false, 6*time.Second)
			if pend != nil {

				return m, m.aiAskPrepared(pend.system, pend.prompt, pend.pid)
			}
			return m, nil
		}
		m.setStatus("model unavailable: "+m.aiStatus.Err, true, 10*time.Second)
		if pend != nil {
			m.pushAI(aiEntry{kind: aiError, title: "model unavailable",
				text: m.aiUnavailableText()})
		}
		return m, nil

	case groupStageMsg:
		if m.groupKill != nil && m.groupKill.running {
			m.groupKill.stage = string(msg)
		}
		return m, nil

	case groupKillMsg:
		m.groupKill = nil
		switch {
		case msg.failed > 0 && msg.done == 0:
			m.setStatus(fmt.Sprintf("group %s: nothing killed, errors %d (%s)",
				msg.title, msg.failed, strings.Join(msg.errs, "; ")), true, 20*time.Second)
		case msg.failed > 0:
			m.setStatus(fmt.Sprintf("group %s: killed %d, errors %d (%s)",
				msg.title, msg.done, msg.failed, strings.Join(msg.errs, "; ")), true, 20*time.Second)
		default:
			m.setStatus(fmt.Sprintf("group %s: killed %s, %d total with children",
				msg.title,
				human.Pluralf(msg.done, "process", "processes", "processes"), msg.procs),
				false, 10*time.Second)
		}
		m.journal.Actionf("groups", 0, msg.title,
			"group kill finished: %d ok, %d errors, %d processes with children",
			msg.done, msg.failed, msg.procs)
		m.refresh()
		return m, nil

	case groupReniceMsg:
		if msg.fail > 0 && msg.done == 0 {
			m.setStatus(fmt.Sprintf("group %s: renice %+d failed (%s)",
				msg.title, msg.delta, msg.last), true, 12*time.Second)
		} else {
			m.setStatus(fmt.Sprintf("group %s: nice %+d for %s (%d errors)",
				msg.title, msg.delta,
				human.Pluralf(msg.done, "process", "processes", "processes"), msg.fail),
				msg.fail > 0, 10*time.Second)
		}
		m.refresh()
		return m, nil

	case killStageMsg:
		if m.confirm != nil && m.confirm.running {
			m.confirm.stage = msg.Stage
			m.confirm.detail = msg.Detail
		}
		return m, nil

	case noteMsg:

		m.setStatus(msg.text, msg.isErr, 12*time.Second)
		m.events = m.journal.Events()
		return m, nil

	case killDoneMsg:
		m.confirm = nil
		if msg.err != nil {
			m.setStatus("Smart Kill: "+msg.err.Error(), true, 15*time.Second)
		} else {
			text := "Smart Kill: " + msg.report.Summary()
			if msg.report.Note != "" {
				text += " — " + msg.report.Note
			}
			m.setStatus(text, msg.report.Note != "", 15*time.Second)
		}
		m.events = m.journal.Events()
		m.refresh()
		return m, nil

	case tea.MouseMsg:
		return m.handleMouse(msg)

	case tea.KeyMsg:
		mm, cmd := m.handleKey(msg)
		m2, ok := mm.(*Model)
		if !ok {
			return mm, cmd
		}
		if m2.pane == paneTerminal && m2.term != nil && !m2.termReading && !m2.term.Closed() {
			m2.termReading = true
			return m2, tea.Batch(cmd, m2.termRead())
		}
		return m2, cmd
	}
	return m, nil
}

func waitForData(ch <-chan struct{}) tea.Cmd {
	return func() tea.Msg {
		<-ch
		return dataMsg{}
	}
}

func tickClock(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(t time.Time) tea.Msg { return clockMsg(t) })
}

// tickNyan drives the little running cat in the header: ~7 frames per second.
func tickNyan() tea.Cmd {
	return tea.Tick(140*time.Millisecond, func(time.Time) tea.Msg { return nyanMsg{} })
}

type nyanMsg struct{}

func (m *Model) refresh() {
	m.procs, m.sys = m.mon.Snapshot()
	now := time.Now()
	m.anoms = m.det.Update(m.procs, m.sys, now)
	m.anomIndex = make(map[int][]anomaly.Anomaly, len(m.anoms))
	for _, a := range m.anoms {
		m.anomIndex[a.PID] = append(m.anomIndex[a.PID], a)
	}
	m.events = m.journal.Events()
	if err := m.mon.LastError(); err != nil {
		m.fatalErr = err
	}
	// The LEADERS lists re-sort on the same settle timer as the process
	// tree, so rows do not reshuffle on every 250 ms tick.
	if m.leaderAt.IsZero() || m.sortSettle <= 0 || now.Sub(m.leaderAt) >= m.sortSettle {
		m.leaderCPU = topByCPU(m.procs)
		m.leaderMem = topByMem(m.procs)
		m.leaderAt = now
	}
	m.recompute()
}

func (m *Model) recompute() {
	list := make([]proc.Snapshot, 0, len(m.procs))
	for _, s := range m.procs {
		if m.isTransparentName(s.Name) {
			continue
		}
		if m.matches(s) {
			list = append(list, s)
		}
	}

	sig := fmt.Sprintf("%d|%v|%d|%q|%v|%v", m.sortKey, m.sortDesc, m.filter, m.search,
		m.treeMode, m.userFirst)
	now := time.Now()
	sigChanged := sig != m.lastSig
	if sigChanged {

		m.smooth = nil
	}
	due := m.sortSettle <= 0 || m.lastSort.IsZero() || now.Sub(m.lastSort) >= m.sortSettle

	tree := m.treeViewActive()
	if tree {
		m.treeIdx = m.buildTreeIndex(list)
	} else {
		m.treeIdx = nil
	}

	frozen := tree && !sigChanged && m.anyBranchExpanded()
	resort := sigChanged || (due && !frozen)

	if tree {
		if resort {
			m.sortTree(list, m.treeIdx)
		} else {
			applyOrder(list, m.rootOrder)
		}
	} else if resort {
		m.sortList(list)
	} else {
		applyOrder(list, m.rootOrder)
	}
	if resort {
		m.lastSig = sig
		m.lastSort = now
		m.rootOrder = pidOrder(list)
	}
	m.visible = list
	m.buildRows()

	if m.cursorMoved {
		if m.selectedPID <= 0 || !m.selectPID(m.selectedPID) {
			m.clampCursor()
			m.rememberSelection()
		}
	} else if m.selectedPID > 0 || hasNonZeroCPU(m.visible) {
		// Default state (the user has not moved the cursor yet): stay on
		// the top row of the sorted list. The first snapshots have no CPU
		// data (everything reads 0%), the sort is degenerate and row 0 is
		// whatever the kernel listed first — usually init — so pinning it
		// would drag the whole view to the bottom of the list.
		m.cursor = 0
		m.rememberSelection()
	}
	m.clampScroll()

	m.refreshGroups()

	m.refreshHung()
}

func (m *Model) partitionByOwner(list []proc.Snapshot) {
	if !m.userFirst || len(list) < 2 {
		return
	}
	mine := make([]proc.Snapshot, 0, len(list))
	other := make([]proc.Snapshot, 0, len(list)/2)
	for _, s := range list {
		if s.UID == m.ownUID {
			mine = append(mine, s)
		} else {
			other = append(other, s)
		}
	}
	if len(mine) == 0 || len(other) == 0 {
		return
	}
	copy(list, mine)
	copy(list[len(mine):], other)
}

func (m *Model) ownerSplit() (mine, other int) {
	for i := range m.rows {
		if m.rows[i].depth != 0 {
			continue
		}
		if m.rows[i].snap.UID == m.ownUID {
			mine++
		} else {
			other++
		}
	}
	return mine, other
}

func pidOrder(list []proc.Snapshot) []int {
	order := make([]int, len(list))
	for i, s := range list {
		order[i] = s.PID
	}
	return order
}

func applyOrder(list []proc.Snapshot, order []int) {
	if len(order) == 0 {
		return
	}
	pos := make(map[int]int, len(order))
	for i, pid := range order {
		if _, ok := pos[pid]; !ok {
			pos[pid] = i
		}
	}
	sort.SliceStable(list, func(i, j int) bool {
		pi, oki := pos[list[i].PID]
		pj, okj := pos[list[j].PID]
		switch {
		case oki && okj:
			return pi < pj
		case oki:
			return true
		case okj:
			return false
		}
		return list[i].PID < list[j].PID
	})
}

func (m *Model) moveHelp(delta int) {
	m.helpScroll += delta
	if m.helpScroll < 0 {
		m.helpScroll = 0
	}
}

func (m *Model) handleHelpKey(msg tea.KeyMsg) (tea.Cmd, bool) {
	switch msg.String() {
	case "up", "k", "л":
		m.moveHelp(-1)
	case "down", "j", "о", " ":
		m.moveHelp(1)
	case "pgup", "ctrl+u":
		m.moveHelp(-m.helpRows())
	case "pgdown", "ctrl+d":
		m.moveHelp(m.helpRows())
	case "home", "g", "п":
		m.helpScroll = 0
	case "end", "G", "П":
		m.moveHelp(m.helpTotal)
	case "ctrl+home":
		m.helpScroll = 0
	case "ctrl+end":
		m.moveHelp(m.helpTotal)
	default:
		return nil, false
	}
	return nil, true
}

func (m *Model) helpRows() int {
	n := m.bodyHeight - 4
	if n < 1 {
		n = 1
	}
	return n
}

func (m *Model) moveList(delta int) {
	switch m.pane {
	case paneLog:
		m.moveLog(delta)
	case paneGroups:
		m.moveGroupCursor(delta)
	default:
		m.moveCursor(delta)
	}
}

func (m *Model) logEvents() []actions.Event {
	if m.logFilter == logAll {
		return m.events
	}
	out := make([]actions.Event, 0, len(m.events))
	for _, e := range m.events {
		if m.logFilter.allows(e) {
			out = append(out, e)
		}
	}
	return out
}

func (m *Model) moveLog(delta int) {
	evts := m.logEvents()
	if len(evts) == 0 {
		m.logCursor = 0
		m.logScroll = 0
		return
	}
	m.logCursor += delta
	m.clampLog()
}

func (m *Model) clampLog() {
	evts := m.logEvents()
	if m.logCursor >= len(evts) {
		m.logCursor = len(evts) - 1
	}
	if m.logCursor < 0 {
		m.logCursor = 0
	}

	vis := m.logRows()
	if m.logCursor < m.logScroll {
		m.logScroll = m.logCursor
	}
	if m.logCursor >= m.logScroll+vis {
		m.logScroll = m.logCursor - vis + 1
	}
	maxScroll := len(evts) - vis
	if maxScroll < 0 {
		maxScroll = 0
	}
	if m.logScroll > maxScroll {
		m.logScroll = maxScroll
	}
	if m.logScroll < 0 {
		m.logScroll = 0
	}
}

func (m *Model) logRows() int {
	n := m.bodyHeight - 7
	if n < 1 {
		n = 1
	}
	return n
}

func (m *Model) selectedEvent() (actions.Event, bool) {
	evts := m.logEvents()
	i := len(evts) - 1 - m.logCursor
	if i < 0 || i >= len(evts) {
		return actions.Event{}, false
	}
	return evts[i], true
}

type logFilter int

const (
	logAll logFilter = iota
	logNotable
	logErrors
	logActions
)

func (f logFilter) title() string {
	switch f {
	case logNotable:
		return "warnings and errors only"
	case logErrors:
		return "errors only"
	case logActions:
		return "actions only"
	}
	return "all events"
}

func (f logFilter) next() logFilter { return logFilter((int(f) + 1) % 4) }

func (f logFilter) allows(e actions.Event) bool {
	switch f {
	case logNotable:
		return e.Level == actions.LevelWarn || e.Level == actions.LevelError
	case logErrors:
		return e.Level == actions.LevelError
	case logActions:
		return e.Level == actions.LevelAction
	}
	return true
}

func (m *Model) rememberSelection() {
	if s, ok := m.selected(); ok {
		m.selectedPID = s.PID
		m.selectedStart = s.StartTime
		return
	}
	m.selectedPID = 0
	m.selectedStart = time.Time{}
}

func (m *Model) selectRow(i int) {
	m.cursorMoved = true
	if len(m.rows) == 0 {
		m.cursor = 0
		m.selectedPID = 0
		m.selectedStart = time.Time{}
		m.clampScroll()
		return
	}
	if i < 0 {
		i = 0
	}
	if i >= len(m.rows) {
		i = len(m.rows) - 1
	}
	m.cursor = i
	m.rememberSelection()
	m.clampScroll()
}

func hasNonZeroCPU(list []proc.Snapshot) bool {
	for _, s := range list {
		if s.CPUPercent != 0 {
			return true
		}
	}
	return false
}

// isTransparentName reports whether the process is a session wrapper hidden
// from the tree (see config ui.transparent_names).
func (m *Model) isTransparentName(name string) bool {
	if len(m.transparentNames) == 0 || name == "" {
		return false
	}
	lower := strings.ToLower(name)
	for _, pat := range m.transparentNames {
		if pat != "" && strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

func (m *Model) matches(s proc.Snapshot) bool {
	switch m.filter {
	case filterAnomalous:
		if _, ok := m.anomIndex[s.PID]; !ok {
			return false
		}
	case filterMine:
		if s.UID != m.ownUID {
			return false
		}
	case filterActive:
		if s.State != proc.StateRunning && s.State != proc.StateDiskSleep {
			return false
		}
	}
	if m.search != "" {
		if isAllDigits(m.search) {

			if strconv.Itoa(s.PID) == m.search ||
				containsNumberToken(s.Name, m.search) ||
				containsNumberToken(s.Cmdline, m.search) {
				return true
			}
			return false
		}
		needle := strings.ToLower(m.search)
		if !strings.Contains(strings.ToLower(s.Name), needle) &&
			!strings.Contains(strings.ToLower(s.Cmdline), needle) &&
			!strings.Contains(s.User, needle) {
			return false
		}
	}
	return true
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func containsNumberToken(haystack, digits string) bool {
	for i := 0; i < len(haystack); {
		j := strings.Index(haystack[i:], digits)
		if j < 0 {
			return false
		}
		start := i + j
		end := start + len(digits)
		beforeOK := start == 0 || !isDigitByte(haystack[start-1])
		afterOK := end == len(haystack) || !isDigitByte(haystack[end])
		if beforeOK && afterOK {
			return true
		}
		i = start + 1
	}
	return false
}

func isDigitByte(b byte) bool { return b >= '0' && b <= '9' }

func (m *Model) sortList(list []proc.Snapshot) {
	m.updateSmoothing(list)
	smoothed := m.cfg.UI.SmoothSort && m.sortIsVolatile()
	less := func(a, b proc.Snapshot) bool {
		if smoothed {

			va, vb := m.smoothValue(a), m.smoothValue(b)
			if va != vb {
				return va < vb
			}
			return a.PID < b.PID
		}
		switch m.sortKey {
		case sortCPU:
			return a.CPUPercent < b.CPUPercent
		case sortTotal:
			return m.totalScore(a) < m.totalScore(b)
		case sortMem:
			return a.RSSKiB < b.RSSKiB
		case sortDelta:
			return a.RSSDeltaKiB < b.RSSDeltaKiB
		case sortIO:
			return a.IORate() < b.IORate()
		case sortFD:
			if a.FDCount != b.FDCount {
				return a.FDCount < b.FDCount
			}
			return a.FDPercent < b.FDPercent
		case sortPID:
			return a.PID < b.PID
		case sortName:
			return strings.ToLower(a.Name) < strings.ToLower(b.Name)
		case sortUser:
			if a.User != b.User {
				return a.User < b.User
			}
			return a.PID < b.PID
		case sortAge:
			return a.Age < b.Age
		case sortNice:
			return a.Nice < b.Nice
		case sortState:
			return a.State < b.State
		}
		return a.PID < b.PID
	}
	sort.SliceStable(list, func(i, j int) bool {
		if m.sortDesc {
			return less(list[j], list[i])
		}
		return less(list[i], list[j])
	})
	m.partitionByOwner(list)
}

const smoothAlpha = 0.3

func (m *Model) sortIsVolatile() bool {
	switch m.sortKey {
	case sortCPU, sortTotal, sortIO, sortDelta:
		return true
	}
	return false
}

// totalScore — combined consumption: CPU% plus twice the share of RAM,
// so a memory hog ranks next to a CPU burner, not below it. For tree roots
// the values are the subtree sums (the sort proxy replaces both fields).
func (m *Model) totalScore(s proc.Snapshot) float64 {
	mem := 0.0
	if m.sys.MemTotalKiB > 0 {
		mem = float64(s.RSSKiB) / float64(m.sys.MemTotalKiB) * 100
	}
	return s.CPUPercent + 2*mem
}

func (m *Model) sortMetric(s proc.Snapshot) float64 {
	switch m.sortKey {
	case sortCPU:
		return s.CPUPercent
	case sortTotal:
		return m.totalScore(s)
	case sortIO:
		return s.IORate()
	case sortDelta:
		return s.RSSDeltaKiB
	}
	return 0
}

func (m *Model) updateSmoothing(list []proc.Snapshot) {
	if !m.cfg.UI.SmoothSort || !m.sortIsVolatile() {
		return
	}
	if m.smooth == nil {
		m.smooth = make(map[int]float64, len(list))
	}
	alive := make(map[int]bool, len(list))
	for _, s := range list {
		alive[s.PID] = true
		v := m.sortMetric(s)
		if prev, ok := m.smooth[s.PID]; ok {
			m.smooth[s.PID] = prev + smoothAlpha*(v-prev)
			continue
		}
		m.smooth[s.PID] = v
	}

	for pid := range m.smooth {
		if !alive[pid] {
			delete(m.smooth, pid)
		}
	}
}

func (m *Model) smoothValue(s proc.Snapshot) float64 {
	if v, ok := m.smooth[s.PID]; ok {
		return v
	}
	return m.sortMetric(s)
}

func (m *Model) anyBranchExpanded() bool {
	if m.treeIdx == nil {
		return false
	}
	for pid, open := range m.expanded {
		if open && len(m.treeIdx.kids[pid]) > 0 {
			return true
		}
	}
	return false
}

func (m *Model) selected() (proc.Snapshot, bool) {
	if r, ok := m.rowAt(m.cursor); ok {
		return r.snap, true
	}
	return proc.Snapshot{}, false
}

func (m *Model) focused() (proc.Snapshot, bool) {
	pid := 0
	switch m.pane {
	case paneHung:
		if it, ok := m.hungSelected(); ok {
			pid = it.PID
		}
	case paneSecurity:
		f, ok := m.secSelected()
		if !ok {
			return proc.Snapshot{}, false
		}
		if f.PID <= 0 {
			m.setStatus("this finding has no process: it is a file or a configuration", true, 5*time.Second)
			return proc.Snapshot{}, false
		}
		pid = f.PID
	}
	if pid > 0 {
		for _, p := range m.procs {
			if p.PID == pid {
				return p, true
			}
		}
		m.setStatus(fmt.Sprintf("process %d is no longer in the list", pid), true, 4*time.Second)
		return proc.Snapshot{}, false
	}
	return m.selected()
}

func (m *Model) moveCursor(delta int) {
	m.cursorMoved = true
	if len(m.visible) == 0 {
		m.cursor = 0
		m.scroll = 0
		m.selectedPID = 0
		m.selectedStart = time.Time{}
		return
	}
	m.selectRow(m.cursor + delta)
}

func (m *Model) rowsVisible() int {
	n := m.bodyHeight - 5
	if n < 1 {
		n = 1
	}
	return n
}

func (m *Model) clampScroll() {
	vis := m.rowsVisible()
	if m.cursor < m.scroll {
		m.scroll = m.cursor
	}
	if m.cursor >= m.scroll+vis {
		m.scroll = m.cursor - vis + 1
	}
	if m.scroll < 0 {
		m.scroll = 0
	}
	if max := len(m.rows) - vis; max >= 0 && m.scroll > max {
		m.scroll = max
	}
	m.clampLog()
}

func (m *Model) setStatus(text string, isErr bool, dur time.Duration) {
	m.status = text
	m.statusIsErr = isErr
	m.statusUntil = time.Now().Add(dur)
}

func (m *Model) activeStatus() string {
	if m.status == "" || time.Now().After(m.statusUntil) {
		return ""
	}
	return m.status
}

func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {

	if msg.Type == tea.KeyRunes && len(msg.Runes) > 1 && !m.searching {
		var cmds []tea.Cmd
		mm := m
		for _, r := range msg.Runes {
			next, cmd := mm.handleKey(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
			mm = next.(*Model)
			cmds = append(cmds, cmd)
		}
		return mm, tea.Batch(cmds...)
	}

	if m.searching {
		switch msg.Type {
		case tea.KeyEsc:
			m.searching = false
			m.search = ""
			m.recompute()
			return m, nil
		case tea.KeyEnter:
			m.searching = false
			m.setStatus(fmt.Sprintf("search %q: %d found", m.search, len(m.visible)), false, 5*time.Second)
			return m, nil
		case tea.KeyBackspace:
			r := []rune(m.search)
			if len(r) > 0 {
				m.search = string(r[:len(r)-1])
			}
			m.recompute()
			return m, nil
		case tea.KeyCtrlU:
			m.search = ""
			m.recompute()
			return m, nil
		case tea.KeyRunes:
			m.search += string(msg.Runes)
			m.recompute()
			return m, nil
		}
		return m, nil
	}

	if m.showHelp {
		if cmd, handled := m.handleHelpKey(msg); handled {
			return m, cmd
		}
	}

	if m.groupKill != nil {
		return m.handleGroupKillKey(msg)
	}

	inputActive := m.searching || m.launchInput || m.sysInput || m.srvInput
	if m.pane != paneTerminal && !inputActive && !m.showHelp {
		if msg.Type == tea.KeyRunes && len(msg.Runes) == 1 {
			if latin, ok := cyrLayout[string(msg.Runes)]; ok {
				msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(latin)}
			}
		}
	}

	if m.pane == paneSecurity {
		if cmd, handled := m.handleSecKey(msg); handled {
			return m, cmd
		}
	}

	if m.pane == paneHung {
		if cmd, handled := m.handleHungKey(msg); handled {
			return m, cmd
		}
	}

	if m.pane == paneSystem {
		if cmd, handled := m.handleSysKey(msg); handled {
			return m, cmd
		}
	}

	if m.pane == paneTerminal {
		if cmd, handled := m.handleTermKey(msg); handled {
			return m, cmd
		}
	}

	if m.pane == paneLaunch {
		if cmd, handled := m.handleLaunchKey(msg); handled {
			return m, cmd
		}
	}

	if m.pane == paneServers {
		if cmd, handled := m.handleSrvKey(msg); handled {
			return m, cmd
		}
	}

	if m.pane == paneAI {
		if cmd, handled := m.handleAIKey(msg); handled {
			return m, cmd
		}
	}

	if m.pane == paneGroups {
		if cmd, handled := m.handleGroupsKey(msg); handled {
			return m, cmd
		}
	}

	if m.confirm != nil {
		return m.handleConfirmKey(msg)
	}

	switch msg.Type {
	case tea.KeyInsert:

		m.setPane(paneServers)
		return m, nil
	case tea.KeyCtrlC:
		return m.quit()

	case tea.KeyEsc:
		switch {
		case m.showHelp:
			m.showHelp = false
		case m.search != "":
			m.search = ""
			m.recompute()
			m.setStatus("search reset", false, 3*time.Second)
		case m.filter != filterAll:
			m.filter = filterAll
			m.recompute()
			m.setStatus("filter reset", false, 3*time.Second)
		default:
			m.setStatus("Esc closes help, then search, then filter", false, 4*time.Second)
		}
		return m, nil

	case tea.KeyTab:
		m.switchPane(+1)
		return m, m.aiEnsureProbed()

	case tea.KeyShiftTab:
		m.switchPane(-1)
		return m, m.aiEnsureProbed()

	case tea.KeyUp:
		m.moveList(-1)
		return m, nil
	case tea.KeyDown:
		m.moveList(1)
		return m, nil
	case tea.KeyLeft:
		switch m.pane {
		case paneLog:
			m.logScroll = maxInt(0, m.logScroll-1)
		case paneProcesses:
			m.collapseOrParent()
		}
		return m, nil
	case tea.KeyRight:
		switch m.pane {
		case paneLog:
			m.logScroll++
			m.clampScroll()
		case paneProcesses:
			m.expandRow()
		}
		return m, nil
	case tea.KeyPgUp, tea.KeyCtrlU:
		m.moveList(-m.rowsVisible())
		return m, nil
	case tea.KeyPgDown, tea.KeyCtrlD:
		m.moveList(m.rowsVisible())
		return m, nil
	case tea.KeyHome:
		if m.pane == paneLog {
			m.logCursor = 0
			m.logScroll = 0
			return m, nil
		}
		m.cursorMoved = true
		m.selectRow(0)
		return m, nil
	case tea.KeyEnd:
		if m.pane == paneLog {
			m.logCursor = len(m.logEvents()) - 1
			m.clampLog()
			return m, nil
		}
		m.cursorMoved = true
		m.selectRow(len(m.rows) - 1)
		return m, nil

	case tea.KeyEnter:

		if m.pane == paneProcesses {
			if r, ok := m.rowAt(m.cursor); ok {
				if r.hasKids {
					m.toggleRow()
				} else {
					m.setStatus(r.snap.DisplayName()+": "+clip(r.snap.Cmdline, 120), false, 8*time.Second)
				}
			}
		}
		return m, nil

	case tea.KeyF7:

		return m, m.reniceCmd(+m.act.ReniceStep())
	case tea.KeyF8:

		return m, m.reniceCmd(-m.act.ReniceStep())
	case tea.KeyF9:
		return m.openConfirm(), nil

	case tea.KeyRunes:

		for _, r := range msg.Runes {
			if m.searching {
				m.search += string(r)
				m.recompute()
				continue
			}
			_, cmd := m.handleRune(string(r))
			if cmd != nil || m.quitting {
				return m, cmd
			}
		}
		return m, nil
	}
	return m, nil
}

var cyrLayout = map[string]string{
	"й": "q", "ц": "w", "у": "e", "к": "r", "е": "t", "н": "y", "г": "u", "ш": "i", "щ": "o", "з": "p",
	"ф": "a", "ы": "s", "в": "d", "а": "f", "п": "g", "р": "h", "о": "j", "л": "k", "д": "l",
	"я": "z", "ч": "x", "с": "c", "м": "v", "и": "b", "т": "n", "ь": "m",
	"Й": "Q", "Ц": "W", "У": "E", "К": "R", "Е": "T", "Н": "Y", "Г": "U", "Ш": "I", "Щ": "O", "З": "P",
	"Ф": "A", "Ы": "S", "В": "D", "А": "F", "П": "G", "Р": "H", "О": "J", "Л": "K", "Д": "L",
	"Я": "Z", "Ч": "X", "С": "C", "М": "V", "И": "B", "Т": "N", "Ь": "M",
	".": "/", ",": "?",
}

func normalizeRune(s string) string {
	if v, ok := cyrLayout[s]; ok {
		return v
	}
	return s
}

func (m *Model) handleRune(s string) (tea.Model, tea.Cmd) {
	switch normalizeRune(s) {
	case "q":
		return m.quit()
	case "j":
		m.moveList(1)
		return m, nil
	case "k":
		m.moveList(-1)
		return m, nil
	case "g":
		if m.pane == paneLog {
			m.logCursor = 0
			m.logScroll = 0
			return m, nil
		}
		m.selectRow(0)
		return m, nil
	case "L":
		m.logFilter = m.logFilter.next()
		m.logCursor = 0
		m.logScroll = 0
		m.setStatus("log: "+m.logFilter.title(), false, 4*time.Second)
		return m, nil
	case "G":
		m.selectRow(len(m.rows) - 1)
		return m, nil
	case "T":

		m.treeMode = !m.treeMode
		if m.treeMode {
			m.setStatus("process tree: Enter — expand a branch, ←/→ — collapse or go to parent", false, 6*time.Second)
		} else {
			m.setStatus("flat list: all processes in one table", false, 6*time.Second)
		}
		m.selectedPID = 0
		m.cursor = 0
		m.scroll = 0
		m.recompute()
		return m, nil
	case "u", "U":

		m.userFirst = !m.userFirst
		m.cfg.UI.UserFirst = m.userFirst
		if m.userFirst {
			m.setStatus("own processes above system ones", false, 4*time.Second)
		} else {
			m.setStatus("global sort: owner is not taken into account", false, 4*time.Second)
		}
		m.recompute()
		return m, nil
	case "a":

		if m.pane == paneLog {
			m.setStatus("nothing to explain in the log: select a process on the Processes tab",
				true, 6*time.Second)
			return m, nil
		}
		return m, m.aiExplainSelected()
	case "e":
		if !m.treeMode {
			m.setStatus("branch expansion works in tree mode (T)", false, 4*time.Second)
			return m, nil
		}
		m.setAllExpanded(true)
		m.setStatus("all branches expanded", false, 3*time.Second)
		return m, nil
	case "E":
		if !m.treeMode {
			m.setStatus("branch collapsing works in tree mode (T)", false, 4*time.Second)
			return m, nil
		}
		m.setAllExpanded(false)
		m.setStatus("all branches collapsed", false, 3*time.Second)
		return m, nil
	case "s":
		m.sortKey = m.sortKey.next()
		m.recompute()
		m.setStatus("sort: "+m.sortKey.title(), false, 4*time.Second)
		return m, nil
	case "S":
		m.sortKey = m.sortKey.prev()
		m.recompute()
		m.setStatus("sort: "+m.sortKey.title(), false, 4*time.Second)
		return m, nil
	case "d":
		m.sortDesc = !m.sortDesc
		m.recompute()
		order := "ascending"
		if m.sortDesc {
			order = "descending"
		}
		m.setStatus("order: "+order, false, 4*time.Second)
		return m, nil
	case "f":
		m.filter = m.filter.next()

		m.selectedPID = 0
		m.selectedStart = time.Time{}
		m.cursor = 0
		m.scroll = 0
		m.recompute()
		m.setStatus(fmt.Sprintf("filter: %s (%d visible)", m.filter.title(), len(m.visible)), false, 5*time.Second)
		return m, nil
	case "c":
		m.showCmdline = !m.showCmdline
		if m.showCmdline {
			m.setStatus("showing full command line", false, 4*time.Second)
		} else {
			m.setStatus("showing process name", false, 4*time.Second)
		}
		return m, nil
	case "r":
		m.mon.Poll()
		m.setStatus("manual /proc snapshot requested", false, 3*time.Second)
		return m, nil
	case "/":

		m.search = ""
		m.searching = true
		m.recompute()
		return m, nil
	case "x":
		if m.search != "" {
			m.search = ""
			m.recompute()
			m.setStatus("search cleared", false, 3*time.Second)
		}
		return m, nil
	case "1", "2", "3", "4", "5", "6", "7", "8", "9", "0":
		if p, ok := paneByDigit(normalizeRune(s)); ok {
			m.setPane(p)
		}
		return m, m.aiEnsureProbed()
	case "?", "h":
		m.showHelp = !m.showHelp
		if m.showHelp {
			m.helpScroll = 0
		}
		return m, nil
	}
	return m, nil
}

func (m *Model) handleMouse(msg tea.MouseMsg) (tea.Model, tea.Cmd) {
	if msg.Action != tea.MouseActionPress {
		return m, nil
	}
	switch msg.Button {
	case tea.MouseButtonWheelUp:
		m.moveList(-3)
	case tea.MouseButtonWheelDown:
		m.moveList(3)
	case tea.MouseButtonLeft:
		if m.pane == paneProcesses && m.tableTop > 0 {
			row := msg.Y - m.tableTop
			if row >= 0 {
				idx := m.scroll + row
				if idx < len(m.rows) {
					m.selectRow(idx)
				}
			}
		}
	}
	return m, nil
}

func (m *Model) quit() (tea.Model, tea.Cmd) {
	if m.confirm != nil && m.confirm.running {
		m.setStatus("Smart Kill in progress: quitting is blocked until it finishes", true, 4*time.Second)
		return m, nil
	}
	m.termStop()
	m.srvCloseAll()
	m.quitting = true

	return m, tea.Quit
}

func (m *Model) openConfirm() *Model {
	s, ok := m.focused()
	if !ok {
		m.setStatus("no process selected", true, 4*time.Second)
		return m
	}
	if s.PID <= 1 {
		m.setStatus(fmt.Sprintf("PID %d is a system process, it cannot be killed from the TUI", s.PID), true, 6*time.Second)
		return m
	}
	if s.PID == os.Getpid() {
		m.setStatus("cannot kill Deadeye itself — press q to quit", true, 6*time.Second)
		return m
	}
	if s.Kernel {
		m.setStatus("kernel threads cannot be killed with a signal", true, 6*time.Second)
		return m
	}
	if s.IsZombie() {
		m.setStatus(fmt.Sprintf("PID %d already exited (zombie) — signals are useless, the parent will reap it", s.PID), true, 8*time.Second)
		return m
	}
	tree := m.treeOf(s.PID)
	var treeRSS int64
	for _, pid := range tree {
		treeRSS += m.rssOf(pid)
	}
	parentPID, parentName := 0, ""
	if s.PPID > 1 {
		parentPID = s.PPID
		parentName = m.nameOf(s.PPID)
	}

	m.confirm = &confirmState{
		pid:        s.PID,
		name:       s.Name,
		user:       s.User,
		start:      s.StartTime,
		coredump:   m.act.Config().CoreDump,
		scope:      actions.ScopeProcess,
		tree:       tree,
		treeRSS:    treeRSS + s.RSSKiB,
		parentPID:  parentPID,
		parentName: parentName,
	}
	return m
}

func (m *Model) treeOf(pid int) []int {
	kids := make(map[int][]int, len(m.procs))
	for _, s := range m.procs {
		kids[s.PPID] = append(kids[s.PPID], s.PID)
	}
	for _, list := range kids {
		sort.Slice(list, func(i, j int) bool { return list[i] < list[j] })
	}
	seen := map[int]bool{pid: true}
	var out []int
	var rec func(p, depth int)
	rec = func(p, depth int) {
		if depth > 64 {
			return
		}
		for _, c := range kids[p] {
			if seen[c] {
				continue
			}
			seen[c] = true
			rec(c, depth+1)
			out = append(out, c)
		}
	}
	rec(pid, 0)
	return out
}

func (m *Model) rssOf(pid int) int64 {
	for _, s := range m.procs {
		if s.PID == pid {
			return s.RSSKiB
		}
	}
	return 0
}

func (m *Model) nameOf(pid int) string {
	for _, s := range m.procs {
		if s.PID == pid {
			return s.Name
		}
	}
	return "?"
}

func (m *Model) handleConfirmKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	c := m.confirm
	if c == nil {
		return m, nil
	}

	if c.running {

		if msg.Type == tea.KeyCtrlC || (msg.Type == tea.KeyRunes && normalizeRune(string(msg.Runes)) == "q") {
			m.setStatus("Smart Kill in progress — wait for it to finish (quitting is blocked)", true, 4*time.Second)
		}
		return m, nil
	}

	switch msg.Type {
	case tea.KeyEsc:
		m.confirm = nil
		m.setStatus("Smart Kill cancelled", false, 3*time.Second)
		return m, nil
	case tea.KeyEnter:
		return m, m.startKillCmd()
	case tea.KeyCtrlC:
		m.confirm = nil
		return m.quit()
	case tea.KeyRunes:
		switch normalizeRune(string(msg.Runes)) {
		case "y":
			return m, m.startKillCmd()
		case "n", "q":
			m.confirm = nil
			m.setStatus("Smart Kill cancelled", false, 3*time.Second)
			return m, nil
		case "t", "е":
			if len(c.tree) == 0 {
				m.setStatus("this process has no children — there is nothing to kill as a tree", false, 4*time.Second)
				return m, nil
			}
			if c.scope == actions.ScopeProcess {
				c.scope = actions.ScopeTree
				m.setStatus(fmt.Sprintf("scope: whole tree — %d processes, total RSS %s",
					len(c.tree)+1, human.FromKiB(float64(c.treeRSS))), false, 5*time.Second)
			} else {
				c.scope = actions.ScopeProcess
				m.setStatus("scope: this process only", false, 4*time.Second)
			}
			return m, nil
		case "c":
			c.coredump = !c.coredump
			if c.coredump {
				m.setStatus("core dump on: SIGABRT will be sent before SIGKILL", false, 4*time.Second)
			} else {
				m.setStatus("core dump off: SIGTERM → SIGKILL", false, 4*time.Second)
			}
			return m, nil
		}
	}
	return m, nil
}

func (m *Model) startKillCmd() tea.Cmd {
	c := m.confirm
	if c == nil {
		return nil
	}
	c.running = true
	c.started = time.Now()
	c.stage = "SIGTERM"
	c.detail = "asking the process to terminate gracefully"

	pid, name, core := c.pid, c.name, c.coredump
	opts := m.act.DefaultKillOptions()
	opts.CoreDump = core

	opts.ExpectStart = c.start
	opts.Scope = c.scope
	if c.scope == actions.ScopeTree {

		opts.Tree = append([]int(nil), c.tree...)
	}
	p := m.program

	m.journal.Actionf("kill", pid, name, "Smart Kill started manually from the TUI (core dump: %v)", core)

	return func() tea.Msg {
		report, err := m.act.SmartKill(context.Background(), pid, opts, func(st actions.StageRecord) {
			if p != nil {
				p.Send(killStageMsg(st))
			}
		})
		return killDoneMsg{report: report, err: err}
	}
}

func (m *Model) reniceCmd(delta int) tea.Cmd {
	s, ok := m.focused()
	if !ok {
		m.setStatus("no process selected", true, 4*time.Second)
		return nil
	}
	if s.PID <= 0 {
		m.setStatus("invalid PID", true, 4*time.Second)
		return nil
	}
	pid, name, start := s.PID, s.Name, s.StartTime
	return func() tea.Msg {
		old, updated, err := m.act.ReniceChecked(pid, delta, start)
		return reniceMsg{pid: pid, name: name, oldNice: old, newNice: updated, err: err}
	}
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
