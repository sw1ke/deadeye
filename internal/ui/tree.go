package ui

import (
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"deadeye/internal/proc"
)

const indentStep = 3

const maxIndentDepth = 5

const maxTreeDepth = 64

type row struct {
	snap    proc.Snapshot
	depth   int
	prefix  string
	kids    int
	subtree int
	hasKids bool
	open    bool
	anoms   int
	sev     float64
	group   int
}

func (r row) isRoot() bool { return r.depth == 0 }

func (r row) label() string {
	name := r.snap.DisplayName()
	if r.subtree > 0 {
		name += " (" + strconv.Itoa(r.subtree) + ")"
	}
	return name
}

type treeAgg struct {
	cpu   float64
	rss   int64
	drss  float64
	thr   int64
	fd    int
	read  float64
	write float64
	anoms int
	sev   float64
	count int
}

type treeIndex struct {
	snap    map[int]proc.Snapshot
	kids    map[int][]int
	rootSet map[int]bool
	isChild map[int]bool
	aggs    map[int]*treeAgg

	transparent map[int]bool

	reachable map[int]bool
}

func (m *Model) treeViewActive() bool {
	return m.treeMode && m.search == "" && m.filter == filterAll && len(m.procs) > 0
}

func (m *Model) buildTreeIndex(list []proc.Snapshot) *treeIndex {
	idx := &treeIndex{
		snap:        make(map[int]proc.Snapshot, len(list)),
		kids:        make(map[int][]int, len(list)),
		rootSet:     make(map[int]bool, len(list)/2+1),
		isChild:     make(map[int]bool, len(list)),
		aggs:        make(map[int]*treeAgg, len(list)),
		reachable:   make(map[int]bool, len(list)),
		transparent: make(map[int]bool, 1),
	}
	for _, s := range list {
		if _, dup := idx.snap[s.PID]; !dup {
			idx.snap[s.PID] = s
		}
	}

	idx.transparent = transparentParents(idx.snap)

	for _, s := range list {
		// A process nests under its parent only when the parent is shown
		// and belongs to the same user. Across a user boundary (e.g. the
		// display manager owning the login session) the process starts its
		// own branch, so user applications do not disappear inside a
		// root-owned "sddm (57)" knot.
		if s.PPID > 0 && s.PPID != s.PID && !idx.transparent[s.PPID] {
			if parent, ok := idx.snap[s.PPID]; ok && parent.UID == s.UID {
				idx.kids[s.PPID] = append(idx.kids[s.PPID], s.PID)
				idx.isChild[s.PID] = true
				continue
			}
		}
		idx.rootSet[s.PID] = true
	}
	for pid := range idx.kids {

		sort.Ints(idx.kids[pid])
	}

	busy := make(map[int]bool, len(list))
	var calc func(pid, depth int) *treeAgg
	calc = func(pid, depth int) *treeAgg {
		s := idx.snap[pid]
		a := &treeAgg{
			cpu:   s.CPUPercent,
			rss:   s.RSSKiB,
			drss:  s.RSSDeltaKiB,
			thr:   s.Threads,
			fd:    -1,
			read:  s.ReadRate,
			write: s.WriteRate,
			anoms: len(m.anomIndex[pid]),
			sev:   m.maxSeverity(pid),
		}
		if s.FDCount >= 0 {
			a.fd = s.FDCount
		}
		if depth >= maxTreeDepth || busy[pid] {
			return a
		}
		busy[pid] = true
		defer delete(busy, pid)
		for _, c := range idx.kids[pid] {
			if c == pid {
				continue
			}
			sub := calc(c, depth+1)
			a.cpu += sub.cpu
			a.rss += sub.rss
			a.drss += sub.drss
			a.thr += sub.thr
			a.read += sub.read
			a.write += sub.write
			a.anoms += sub.anoms
			if sub.sev > a.sev {
				a.sev = sub.sev
			}
			a.count += sub.count + 1
			switch {
			case sub.fd >= 0 && a.fd >= 0:
				a.fd += sub.fd
			case sub.fd >= 0:
				a.fd = sub.fd
			}
		}
		idx.aggs[pid] = a
		return a
	}

	var mark func(pid, depth int)
	mark = func(pid, depth int) {
		if idx.reachable[pid] || depth > maxTreeDepth {
			return
		}
		idx.reachable[pid] = true
		for _, c := range idx.kids[pid] {
			mark(c, depth+1)
		}
	}
	for pid := range idx.rootSet {
		mark(pid, 0)
	}

	for pid := range idx.rootSet {
		calc(pid, 0)
	}

	for _, s := range list {
		if _, ok := idx.aggs[s.PID]; !ok {
			calc(s.PID, 0)
		}
	}
	return idx
}

func transparentParents(snap map[int]proc.Snapshot) map[int]bool {
	out := make(map[int]bool, 1)
	if s, ok := snap[1]; ok && (s.PPID <= 1 || s.PPID == 0) {
		out[1] = true
	}
	return out
}

func (m *Model) sortTree(list []proc.Snapshot, idx *treeIndex) {
	proxy := make([]proc.Snapshot, len(list))
	copy(proxy, list)
	for i := range proxy {
		if a, ok := idx.aggs[proxy[i].PID]; ok {
			proxy[i].CPUPercent = a.cpu
			proxy[i].RSSKiB = a.rss
			proxy[i].RSSDeltaKiB = a.drss
			proxy[i].Threads = a.thr
			proxy[i].FDCount = a.fd
			proxy[i].ReadRate = a.read
			proxy[i].WriteRate = a.write
		}
	}
	m.sortList(proxy)
	pos := make(map[int]int, len(proxy))
	for i, s := range proxy {
		pos[s.PID] = i
	}
	sort.SliceStable(list, func(i, j int) bool { return pos[list[i].PID] < pos[list[j].PID] })
}

func (m *Model) buildRows() {
	if m.treeIdx == nil || !m.treeViewActive() {
		rows := make([]row, 0, len(m.visible))
		for i, s := range m.visible {
			rows = append(rows, row{snap: s, group: i})
		}
		m.rows = rows
		m.treeDepth = 0
		return
	}
	idx := m.treeIdx

	rows := make([]row, 0, len(m.visible)+8)
	seen := make(map[int]bool, len(m.visible))
	maxDepth := 0

	var walk func(pid int, guide string, depth int, last bool, group int)
	walk = func(pid int, guide string, depth int, last bool, group int) {
		s, ok := idx.snap[pid]
		if !ok || seen[pid] || depth > maxTreeDepth || len(rows) > 4*len(m.visible)+16 {
			return
		}
		seen[pid] = true

		list := idx.kids[pid]
		open := len(list) > 0 && m.expanded[pid]

		var prefix string
		switch {
		case depth == 0 && len(list) == 0:
			prefix = strings.Repeat(" ", indentStep)
		case depth == 0 && open:
			prefix = "▾  "
		case depth == 0:
			prefix = "▸  "
		case last:
			prefix = guide + "└─ "
		default:
			prefix = guide + "├─ "
		}

		r := row{
			snap:    s,
			depth:   depth,
			prefix:  prefix,
			kids:    len(list),
			hasKids: len(list) > 0,
			open:    open,
			group:   group,
		}
		if a, ok := idx.aggs[pid]; ok {
			r.subtree = a.count
			r.anoms = a.anoms
			r.sev = a.sev
			if len(list) > 0 && !open {

				r.snap.CPUPercent = a.cpu
				r.snap.RSSKiB = a.rss
				r.snap.RSSDeltaKiB = a.drss
				r.snap.Threads = a.thr
				r.snap.FDCount = a.fd
				r.snap.ReadRate = a.read
				r.snap.WriteRate = a.write
			}
		}
		if depth > maxDepth {
			maxDepth = depth
		}
		rows = append(rows, r)

		if !open {
			return
		}
		childGuide := guide
		switch {
		case depth == 0:
			childGuide = ""
		case last:
			childGuide = guide + strings.Repeat(" ", indentStep)
		default:
			childGuide = guide + "│  "
		}
		for j, c := range list {
			walk(c, childGuide, depth+1, j == len(list)-1, group)
		}
	}

	group := 0
	for _, s := range m.visible {
		if !idx.rootSet[s.PID] || seen[s.PID] {
			continue
		}
		walk(s.PID, "", 0, true, group)
		group++
	}

	for _, s := range m.visible {
		if seen[s.PID] || idx.reachable[s.PID] {
			continue
		}
		walk(s.PID, "", 0, true, group)
		group++
	}

	m.rows = rows
	m.treeDepth = maxDepth
}

func (m *Model) indentWidth() int {
	if m.treeIdx == nil {
		return 0
	}
	depth := m.treeDepth
	if depth > maxIndentDepth {
		depth = maxIndentDepth
	}
	return indentStep * (depth + 1)
}

func (m *Model) rowAt(i int) (row, bool) {
	if i < 0 || i >= len(m.rows) {
		return row{}, false
	}
	return m.rows[i], true
}

func (m *Model) indexOfRow(pid int) int {
	for i := range m.rows {
		if m.rows[i].snap.PID == pid {
			return i
		}
	}
	return -1
}

func (m *Model) selectPID(pid int) bool {
	if m.indexOfRow(pid) < 0 {
		m.ensureAncestors(pid)
		m.buildRows()
		m.clampCursor()
	}
	i := m.indexOfRow(pid)
	if i < 0 {
		return false
	}
	m.selectRow(i)
	return true
}

func (m *Model) ensureAncestors(pid int) {
	if m.treeIdx == nil || m.expanded == nil {
		return
	}
	cur, ok := m.treeIdx.snap[pid]
	for i := 0; ok && i < maxTreeDepth; i++ {
		parent, ok2 := m.treeIdx.snap[cur.PPID]
		if !ok2 || parent.PID == cur.PID {
			return
		}
		m.expanded[parent.PID] = true
		cur = parent
		ok = cur.PPID > 0
	}
}

func (m *Model) toggleRow() {
	r, ok := m.rowAt(m.cursor)
	if !ok || !r.hasKids {
		return
	}
	if m.expanded == nil {
		m.expanded = make(map[int]bool)
	}
	m.expanded[r.snap.PID] = !m.expanded[r.snap.PID]
	m.keepCursorOn(r.snap.PID)
	m.reselectVisible()
}

func (m *Model) expandRow() {
	r, ok := m.rowAt(m.cursor)
	if !ok || !r.hasKids || r.open {
		return
	}
	if m.expanded == nil {
		m.expanded = make(map[int]bool)
	}
	m.expanded[r.snap.PID] = true
	m.keepCursorOn(r.snap.PID)
}

func (m *Model) collapseOrParent() {
	r, ok := m.rowAt(m.cursor)
	if !ok {
		return
	}
	if r.hasKids && r.open {
		if m.expanded != nil {
			m.expanded[r.snap.PID] = false
		}
		m.keepCursorOn(r.snap.PID)
		m.reselectVisible()
		return
	}
	if r.depth == 0 {
		return
	}
	if i := m.indexOfRow(r.snap.PPID); i >= 0 {
		m.selectRow(i)
	}
}

func (m *Model) setAllExpanded(open bool) {
	if m.expanded == nil {
		m.expanded = make(map[int]bool)
	}
	pid := 0
	if r, ok := m.rowAt(m.cursor); ok {
		pid = r.snap.PID
	}
	for i := range m.visible {
		m.expanded[m.visible[i].PID] = open
	}
	m.buildRows()
	if pid > 0 {
		if i := m.indexOfRow(pid); i >= 0 {
			m.cursor = i
		}
	}
	m.clampCursor()
	m.rememberSelection()
	m.reselectVisible()
}

func (m *Model) reselectVisible() {
	if m.treeIdx == nil || m.selectedPID == 0 {
		return
	}
	if m.indexOfRow(m.selectedPID) >= 0 {
		return
	}
	pid := m.selectedPID
	for i := 0; i < maxTreeDepth; i++ {
		snap, ok := m.treeIdx.snap[pid]
		if !ok || snap.PPID <= 0 || snap.PPID == pid {
			return
		}
		pid = snap.PPID
		if j := m.indexOfRow(pid); j >= 0 {
			m.selectRow(j)
			return
		}
	}
}

func (m *Model) keepCursorOn(pid int) {
	m.buildRows()
	if i := m.indexOfRow(pid); i >= 0 {
		m.cursor = i
	}
	m.clampCursor()
	m.rememberSelection()
	m.clampScroll()
}

func (m *Model) clampCursor() {
	if m.cursor >= len(m.rows) {
		m.cursor = len(m.rows) - 1
	}
	if m.cursor < 0 {
		m.cursor = 0
	}
}

func (m *Model) visibleCount() int { return len(m.rows) }

func (m *Model) groupCount() int {
	n := 0
	for i := range m.rows {
		if m.rows[i].depth == 0 {
			n++
		}
	}
	return n
}

func (m *Model) maxSeverity(pid int) float64 {
	var max float64
	for _, a := range m.anomIndex[pid] {
		if a.Severity > max {
			max = a.Severity
		}
	}
	return max
}

func (m *Model) styleForRow(r row) lipgloss.Style {
	if r.anoms > 0 || r.sev > 0 {
		return rowStyleFor(r.snap, r.sev, true)
	}
	return rowStyleFor(r.snap, 0, false)
}
