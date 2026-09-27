package actions

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"deadeye/internal/proc"
)

type Level string

const (
	LevelInfo   Level = "INFO"
	LevelAction Level = "ACTION"
	LevelWarn   Level = "WARN"
	LevelError  Level = "ERROR"
)

type Event struct {
	Time    time.Time
	Level   Level
	Kind    string
	PID     int
	Name    string
	Message string
}

func (e Event) String() string {
	msg := strings.ReplaceAll(e.Message, "\n", " ")
	if e.PID > 0 {
		return fmt.Sprintf("%s [%-6s] kind=%s pid=%d name=%q %s",
			e.Time.Format(time.RFC3339), e.Level, e.Kind, e.PID, e.Name, msg)
	}
	return fmt.Sprintf("%s [%-6s] kind=%s %s", e.Time.Format(time.RFC3339), e.Level, e.Kind, msg)
}

type Log struct {
	mu       sync.Mutex
	events   []Event
	cap      int
	minLevel Level

	fileMu   sync.Mutex
	file     *os.File
	path     string
	written  int64
	maxBytes int64
}

func NewLog(maxEvents int) *Log {
	if maxEvents < 10 {
		maxEvents = 10
	}
	if maxEvents > 100000 {
		maxEvents = 100000
	}
	return &Log{cap: maxEvents, events: make([]Event, 0, 64), minLevel: LevelInfo}
}

func (l *Log) SetMinLevel(min Level) {
	l.mu.Lock()
	defer l.mu.Unlock()
	switch min {
	case LevelInfo, LevelAction, LevelWarn, LevelError:
		l.minLevel = min
	default:
		l.minLevel = LevelInfo
	}
}

func (l *Log) MinLevel() Level {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.minLevel
}

func levelRank(l Level) int {
	switch l {
	case LevelError:
		return 3
	case LevelWarn:
		return 2
	case LevelAction:
		return 1
	default:
		return 0
	}
}

func (l *Log) Push(level Level, kind string, pid int, name, format string, args ...any) Event {
	e := Event{
		Time:    time.Now(),
		Level:   level,
		Kind:    kind,
		PID:     pid,
		Name:    name,
		Message: fmt.Sprintf(format, args...),
	}

	l.mu.Lock()
	if levelRank(level) < levelRank(l.minLevel) {
		l.mu.Unlock()
		return e
	}
	l.events = append(l.events, e)
	if len(l.events) > l.cap {
		drop := len(l.events) - l.cap
		l.events = l.events[drop:]
	}
	l.mu.Unlock()

	l.writeToFile(e)
	return e
}

func (l *Log) Infof(kind string, pid int, name, format string, args ...any) Event {
	return l.Push(LevelInfo, kind, pid, name, format, args...)
}

func (l *Log) Actionf(kind string, pid int, name, format string, args ...any) Event {
	return l.Push(LevelAction, kind, pid, name, format, args...)
}

func (l *Log) Warnf(kind string, pid int, name, format string, args ...any) Event {
	return l.Push(LevelWarn, kind, pid, name, format, args...)
}

func (l *Log) Errorf(kind string, pid int, name, format string, args ...any) Event {
	return l.Push(LevelError, kind, pid, name, format, args...)
}

func (l *Log) Events() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]Event, len(l.events))
	copy(out, l.events)
	return out
}

func (l *Log) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.events)
}

func (l *Log) AttachFile(path string, maxBytes int64) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open log %s: %w", path, err)
	}
	st, err := f.Stat()
	size := int64(0)
	if err == nil {
		size = st.Size()
	}
	l.fileMu.Lock()
	if l.file != nil {
		_ = l.file.Close()
	}
	l.file = f
	l.path = path
	l.written = size
	l.maxBytes = maxBytes
	l.fileMu.Unlock()
	return nil
}

func (l *Log) writeToFile(e Event) {
	l.fileMu.Lock()
	defer l.fileMu.Unlock()
	if l.file == nil {
		return
	}
	line := e.String() + "\n"
	if l.maxBytes > 0 && l.written+int64(len(line)) > l.maxBytes {
		l.rotateLocked()
	}
	if _, err := l.file.WriteString(line); err != nil {
		return
	}
	l.written += int64(len(line))
}

func (l *Log) rotateLocked() {
	backup := l.path + ".1"
	_ = l.file.Close()
	_ = os.Rename(l.path, backup)
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		l.file = nil
		return
	}
	l.file = f
	l.written = 0
}

func (l *Log) Path() string {
	l.fileMu.Lock()
	defer l.fileMu.Unlock()
	return l.path
}

func (l *Log) Close() error {
	l.fileMu.Lock()
	defer l.fileMu.Unlock()
	if l.file == nil {
		return nil
	}
	err := l.file.Sync()
	if cerr := l.file.Close(); err == nil {
		err = cerr
	}
	l.file = nil
	return err
}

type Config struct {
	ReniceStep      int
	GracefulTimeout time.Duration
	CoreDump        bool
	CoreWait        time.Duration
	FinalWait       time.Duration
}

func DefaultConfig() Config {
	return Config{
		ReniceStep:      5,
		GracefulTimeout: 5 * time.Second,
		CoreDump:        true,
		CoreWait:        2 * time.Second,
		FinalWait:       2 * time.Second,
	}
}

func (c *Config) normalize() {
	if c.ReniceStep < 1 {
		c.ReniceStep = 1
	}
	if c.ReniceStep > 19 {
		c.ReniceStep = 19
	}
	if c.GracefulTimeout <= 0 {
		c.GracefulTimeout = 5 * time.Second
	}
	if c.CoreWait <= 0 {
		c.CoreWait = 2 * time.Second
	}
	if c.FinalWait <= 0 {
		c.FinalWait = 2 * time.Second
	}
}

type StageRecord struct {
	Time   time.Time
	Stage  string
	Detail string
}

type KillReport struct {
	PID      int
	Name     string
	Stages   []StageRecord
	Success  bool
	Duration time.Duration
	Err      error

	Targets      int
	ParentPID    int
	ParentName   string
	ParentAlive  bool
	RestartedPID int
	Note         string
}

func (r KillReport) Summary() string {
	stages := make([]string, 0, len(r.Stages))
	for _, s := range r.Stages {
		stages = append(stages, s.Stage)
	}
	res := "success"
	if !r.Success {
		res = "failed"
	}
	target := fmt.Sprintf("PID %d (%s)", r.PID, r.Name)
	if r.Targets > 1 {
		target = fmt.Sprintf("PID %d (%s) and a tree of %d processes", r.PID, r.Name, r.Targets)
	}
	return fmt.Sprintf("%s: %s in %s, stages: %s",
		target, res, r.Duration.Round(time.Millisecond), strings.Join(stages, " → "))
}

type Manager struct {
	cfg Config
	log *Log

	mu       sync.Mutex
	notifyFn func(text string, isErr bool)
}

const RestartWatch = 3 * time.Second

func (m *Manager) SetNotify(fn func(text string, isErr bool)) {
	m.mu.Lock()
	m.notifyFn = fn
	m.mu.Unlock()
}

func (m *Manager) notify() func(string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.notifyFn
}

func NewManager(cfg Config, log *Log) *Manager {
	cfg.normalize()
	return &Manager{cfg: cfg, log: log}
}

func (m *Manager) Config() Config { return m.cfg }

func (m *Manager) ReniceStep() int { return m.cfg.ReniceStep }

func checkTarget(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("invalid PID %d", pid)
	}
	if pid == 1 {
		return errors.New("PID 1 (init) is protected: Deadeye never touches the system manager")
	}
	if pid == os.Getpid() {
		return errors.New("denied: this is Deadeye's own PID")
	}
	return nil
}

func sameProcess(pid int, actual, expect time.Time) error {
	if expect.IsZero() || actual.IsZero() {
		return nil
	}
	if d := actual.Sub(expect); d < -time.Second || d > time.Second {
		return fmt.Errorf("PID %d now belongs to a different process (started %s instead of %s) — action cancelled",
			pid, actual.Format("02.01.2006 15:04:05"), expect.Format("02.01.2006 15:04:05"))
	}
	return nil
}

func (m *Manager) SameProcess(pid int, expectStart time.Time) error {
	if expectStart.IsZero() {
		return nil
	}
	s, err := proc.Read(pid)
	if err != nil {
		return fmt.Errorf("process %d is unavailable: %w", pid, err)
	}
	return sameProcess(pid, s.StartTime, expectStart)
}

func (m *Manager) ReniceChecked(pid, delta int, expectStart time.Time) (oldNice, newNice int, err error) {
	if err := m.SameProcess(pid, expectStart); err != nil {
		m.log.Errorf("renice", pid, procName(pid), "%v", err)
		return 0, 0, err
	}
	return m.Renice(pid, delta)
}

func procName(pid int) string {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (m *Manager) Renice(pid int, delta int) (oldNice, newNice int, err error) {

	if snap, rerr := proc.Read(pid); rerr == nil && snap.IsRealtime() {
		err = fmt.Errorf("process runs under %s (real-time priority %d): nice does not affect it, chrt(1) and root are needed",
			snap.SchedName(), snap.RTPriority)
		m.log.Errorf("renice", pid, procName(pid), "%v", err)
		return 0, 0, err
	}

	cur, err := proc.ReadNice(pid)
	if err != nil {
		m.log.Errorf("renice", pid, procName(pid), "failed to read current nice: %v", err)
		return 0, 0, err
	}
	return m.SetNice(pid, cur+delta)
}

func (m *Manager) SetNice(pid int, nice int) (oldNice, newNice int, err error) {
	if err := checkTarget(pid); err != nil {
		m.log.Errorf("renice", pid, "", "%v", err)
		return 0, 0, err
	}
	if nice < -20 {
		nice = -20
	}
	if nice > 19 {
		nice = 19
	}
	old, err := proc.ReadNice(pid)
	if err != nil {
		m.log.Errorf("renice", pid, "", "failed to read current nice: %v", err)
		return 0, 0, err
	}

	if err := syscall.Setpriority(syscall.PRIO_PROCESS, pid, nice); err != nil {
		msg := fmt.Sprintf("setpriority(%d, %d) failed: %v", pid, nice, err)
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) {
			msg += " — root or the CAP_SYS_NICE capability is required"
		}
		m.log.Errorf("renice", pid, procName(pid), "%s", msg)
		return old, old, errors.New(msg)
	}

	actual, verr := proc.ReadNice(pid)
	if verr == nil && actual != nice {
		msg := fmt.Sprintf("nice changed partially: asked %d, kernel kept %d (RLIMIT_NICE limit)", nice, actual)
		m.log.Warnf("renice", pid, procName(pid), "%s", msg)
		return old, actual, errors.New(msg)
	}

	m.log.Actionf("renice", pid, procName(pid), "priority changed: nice %d → %d", old, nice)
	return old, nice, nil
}

func (m *Manager) SendSignal(pid int, sig syscall.Signal, note string) error {
	if err := checkTarget(pid); err != nil {
		m.log.Errorf("signal", pid, "", "%v", err)
		return err
	}
	if err := syscall.Kill(pid, sig); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return fmt.Errorf("process %d no longer exists", pid)
		}
		if errors.Is(err, syscall.EPERM) {
			return fmt.Errorf("no permission to signal process %d (root needed)", pid)
		}
		return fmt.Errorf("kill(%d, %v): %w", pid, sig, err)
	}
	if note == "" {
		note = signalName(sig)
	}
	m.log.Actionf("signal", pid, procName(pid), "signal %s sent", note)
	return nil
}

func (m *Manager) SmartKill(ctx context.Context, pid int, opts KillOptions, onStage func(StageRecord)) (KillReport, error) {
	start := time.Now()
	rep := KillReport{PID: pid}

	if err := checkTarget(pid); err != nil {
		rep.Err = err
		m.log.Errorf("kill", pid, "", "%v", err)
		return rep, rep.Err
	}
	var victim proc.Snapshot
	if s, err := proc.Read(pid); err == nil {
		rep.Name = s.Name
		victim = s
	}
	if rep.Name == "" {
		rep.Name = "?"
	}

	stage := func(name, detail string) {
		rec := StageRecord{Time: time.Now(), Stage: name, Detail: detail}
		rep.Stages = append(rep.Stages, rec)
		if onStage != nil {
			onStage(rec)
		}
	}

	if err := sameProcess(pid, victim.StartTime, opts.ExpectStart); err != nil {
		rep.Err = err
		stage("check", err.Error())
		rep.Duration = time.Since(start)
		m.log.Errorf("kill", pid, rep.Name, "%v", err)
		return rep, rep.Err
	}

	if !proc.Exists(pid) {
		stage("check", "process no longer exists")
		rep.Success = true
		rep.Duration = time.Since(start)
		m.log.Infof("kill", pid, rep.Name, "process exited before any action was taken")
		return rep, nil
	}
	if victim.State == proc.StateZombie {

		stage("check", "process already finished (zombie) — the parent will reap it")
		rep.Success = true
		rep.Duration = time.Since(start)
		m.log.Infof("kill", pid, rep.Name, "zombie: nothing to kill, waiting for the parent to reap it")
		return rep, nil
	}

	targets := []int{pid}
	if opts.Scope == ScopeTree {
		tree := opts.Tree
		if len(tree) == 0 {
			tree = proc.Descendants(pid)
		}
		targets = make([]int, 0, len(tree)+1)
		for _, t := range tree {
			if t == pid {
				continue
			}
			if err := checkTarget(t); err != nil {

				stage("skip", fmt.Sprintf("PID %d untouched: %v", t, err))
				continue
			}
			if !proc.Exists(t) {
				continue
			}
			targets = append(targets, t)
		}
		targets = append(targets, pid)
	}
	isTree := len(targets) > 1
	rep.Targets = len(targets)
	if isTree {
		stage("target", fmt.Sprintf("tree of %d processes: PID %d (%s) and its descendants", len(targets), pid, rep.Name))
		m.log.Actionf("kill", pid, rep.Name, "Smart Kill: %s, %d processes total", opts.Scope.Title(), len(targets))
	}

	knownSiblings := map[int]bool{}
	if !isTree && victim.PPID > 1 {
		for _, c := range proc.Children(victim.PPID) {
			knownSiblings[c] = true
		}
	}

	graceful := opts.Graceful
	if graceful <= 0 {
		graceful = m.cfg.GracefulTimeout
	}
	coreWait := opts.CoreWait
	if coreWait <= 0 {
		coreWait = m.cfg.CoreWait
	}
	finalWait := opts.FinalWait
	if finalWait <= 0 {
		finalWait = m.cfg.FinalWait
	}

	finish := func(detailSingle, detailTree string) (KillReport, error) {
		rep.Success = true
		rep.Duration = time.Since(start)
		if isTree {
			stage("finished", detailTree)
			m.log.Actionf("kill", pid, rep.Name, "%s in %s", detailTree, rep.Duration.Round(time.Millisecond))
		} else {
			stage("finished", detailSingle)
			m.log.Actionf("kill", pid, rep.Name, "finished in %s", rep.Duration.Round(time.Millisecond))
		}
		m.aftermath(&rep, victim, opts, knownSiblings)
		return rep, nil
	}

	sent, sigErr := signalAll(targets, syscall.SIGTERM)
	if sent == 0 && sigErr == nil {
		rep.Success = true
		rep.Duration = time.Since(start)
		stage("finished", "targets vanished before the signal was delivered")
		m.log.Infof("kill", pid, rep.Name, "processes exited on their own while the signal was being prepared")
		return rep, nil
	}
	if sent == 0 {
		rep.Err = fmt.Errorf("SIGTERM: %w", translateKillErr(sigErr, pid))
		stage("SIGTERM", rep.Err.Error())
		rep.Duration = time.Since(start)
		m.log.Errorf("kill", pid, rep.Name, "%v", rep.Err)
		return rep, rep.Err
	}
	if isTree {
		stage("SIGTERM", fmt.Sprintf("sent to %d processes, waiting up to %s", sent, graceful))
		m.log.Actionf("kill", pid, rep.Name, "Smart Kill: SIGTERM sent to %d tree processes, waiting up to %s", sent, graceful)
	} else {
		stage("SIGTERM", fmt.Sprintf("sent, waiting up to %s", graceful))
		m.log.Actionf("kill", pid, rep.Name, "Smart Kill: SIGTERM sent, waiting up to %s", graceful)
	}
	if waitAllGone(ctx, targets, graceful) {
		return finish("process exited gracefully on SIGTERM",
			fmt.Sprintf("all %d processes exited on SIGTERM", len(targets)))
	}

	if opts.CoreDump {
		alive := survivors(targets)
		note := "SIGABRT (no dump: RLIMIT_CORE = 0; enable with `ulimit -c unlimited`)"
		if len(alive) > 0 && proc.CoreDumpEnabled(alive[0]) {
			note = "SIGABRT (RLIMIT_CORE > 0 — a core dump will be written)"
		}
		if isTree {
			note = fmt.Sprintf("SIGABRT for the remaining %d (dump only written if RLIMIT_CORE > 0)", len(alive))
		}
		abortSent, abortErr := signalAll(alive, syscall.SIGABRT)
		if abortSent == 0 && abortErr != nil {
			stage("SIGABRT", fmt.Sprintf("error: %v", translateKillErr(abortErr, pid)))
			m.log.Warnf("kill", pid, rep.Name, "SIGABRT not delivered: %v", abortErr)
		} else {
			stage("SIGABRT", note)
			m.log.Actionf("kill", pid, rep.Name, "Smart Kill: SIGABRT sent for a core dump, waiting up to %s", coreWait)
		}
		if waitAllGone(ctx, targets, coreWait) {
			return finish("process exited on SIGABRT",
				fmt.Sprintf("all %d processes exited on SIGABRT", len(targets)))
		}
	}

	sent, sigErr = signalAll(survivors(targets), syscall.SIGKILL)
	if sent == 0 && sigErr != nil {
		rep.Err = fmt.Errorf("SIGKILL: %w", translateKillErr(sigErr, pid))
		stage("SIGKILL", rep.Err.Error())
		rep.Duration = time.Since(start)
		m.log.Errorf("kill", pid, rep.Name, "%v", rep.Err)
		return rep, rep.Err
	}
	if isTree {
		stage("SIGKILL", fmt.Sprintf("sent to %d remaining, waiting up to %s", sent, finalWait))
	} else {
		stage("SIGKILL", fmt.Sprintf("sent, waiting up to %s", finalWait))
	}
	m.log.Actionf("kill", pid, rep.Name, "Smart Kill: SIGKILL sent")

	if waitAllGone(ctx, targets, finalWait) {
		return finish("process killed",
			fmt.Sprintf("tree of %d processes killed", len(targets)))
	}

	left := survivors(targets)
	rep.Duration = time.Since(start)
	if isTree {
		rep.Err = fmt.Errorf("after SIGKILL, %d of %d are still alive: %s — probably stuck in uninterruptible sleep (D) on I/O",
			len(left), len(targets), formatPIDs(left))
	} else {
		rep.Err = fmt.Errorf("process %d did not disappear even after SIGKILL: probably stuck in uninterruptible sleep (D) on I/O", pid)
	}
	stage("failed", rep.Err.Error())
	m.log.Errorf("kill", pid, rep.Name, "%v", rep.Err)
	return rep, rep.Err
}

func signalAll(targets []int, sig syscall.Signal) (int, error) {
	var sent int
	var lastErr error
	for _, pid := range targets {
		if !proc.Exists(pid) {
			continue
		}
		if err := syscall.Kill(pid, sig); err != nil {
			lastErr = err
			continue
		}
		sent++
	}
	return sent, lastErr
}

func survivors(targets []int) []int {
	out := make([]int, 0, len(targets))
	for _, pid := range targets {
		if !processGone(pid) {
			out = append(out, pid)
		}
	}
	return out
}

func waitAllGone(ctx context.Context, targets []int, timeout time.Duration) bool {
	if len(targets) == 1 {
		return waitGone(ctx, targets[0], timeout)
	}
	deadline := time.Now().Add(timeout)
	for {
		if len(survivors(targets)) == 0 {
			return true
		}
		wait := time.Until(deadline)
		if wait <= 0 {
			return false
		}
		if wait > 100*time.Millisecond {
			wait = 100 * time.Millisecond
		}
		select {
		case <-ctx.Done():
			return false
		case <-time.After(wait):
		}
	}
}

func formatPIDs(pids []int) string {
	parts := make([]string, 0, len(pids))
	for _, pid := range pids {
		parts = append(parts, fmt.Sprintf("%d (%s)", pid, procName(pid)))
	}
	return strings.Join(parts, ", ")
}

func (m *Manager) aftermath(rep *KillReport, victim proc.Snapshot, opts KillOptions, knownSiblings map[int]bool) {
	if victim.PPID <= 1 || !proc.Exists(victim.PPID) {
		return
	}
	rep.ParentPID = victim.PPID
	rep.ParentName = procName(victim.PPID)
	rep.ParentAlive = true
	rep.Note = fmt.Sprintf("parent PID %d (%s) is still alive — kill it or the whole tree",
		rep.ParentPID, rep.ParentName)
	m.log.Warnf("kill", rep.PID, rep.Name, "%s", rep.Note)

	if opts.Scope == ScopeTree {
		return
	}
	go m.watchRestart(rep.PID, rep.Name, victim.PPID, knownSiblings)
}

func (m *Manager) watchRestart(deadPID int, name string, ppid int, known map[int]bool) {
	deadline := time.Now().Add(RestartWatch)
	for time.Now().Before(deadline) {
		time.Sleep(150 * time.Millisecond)
		if !proc.Exists(ppid) {
			return
		}
		for _, c := range proc.Children(ppid) {
			if c == deadPID || known[c] || !proc.Exists(c) {
				continue
			}
			if procName(c) != name {
				continue
			}
			msg := fmt.Sprintf("PID %d (%s) was already restarted by parent PID %d (%s) as PID %d — kill the parent",
				deadPID, name, ppid, procName(ppid), c)
			m.log.Warnf("kill", deadPID, name, "%s", msg)
			if fn := m.notify(); fn != nil {
				fn(msg, true)
			}
			return
		}
	}
}

type KillScope int

const (
	ScopeProcess KillScope = iota

	ScopeTree
)

func (sc KillScope) Title() string {
	if sc == ScopeTree {
		return "entire process tree"
	}
	return "this process only"
}

type KillOptions struct {
	Graceful  time.Duration
	CoreDump  bool
	CoreWait  time.Duration
	FinalWait time.Duration

	Scope KillScope

	Tree []int

	ExpectStart time.Time
}

func (m *Manager) DefaultKillOptions() KillOptions {
	return KillOptions{
		Graceful:  m.cfg.GracefulTimeout,
		CoreDump:  m.cfg.CoreDump,
		CoreWait:  m.cfg.CoreWait,
		FinalWait: m.cfg.FinalWait,
	}
}

func processGone(pid int) bool {
	if !proc.Exists(pid) {
		return true
	}
	if s, err := proc.Read(pid); err == nil && s.State == proc.StateZombie {
		return true
	}
	return false
}

func waitGone(ctx context.Context, pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
	for {
		if processGone(pid) {
			return true
		}
		if time.Now().After(deadline) {
			return processGone(pid)
		}
		select {
		case <-ctx.Done():
			return processGone(pid)
		case <-t.C:
		}
	}
}

func translateKillErr(err error, pid int) error {
	switch {
	case errors.Is(err, syscall.ESRCH):
		return fmt.Errorf("process %d no longer exists", pid)
	case errors.Is(err, syscall.EPERM):
		return fmt.Errorf("no permission to signal process %d (root needed)", pid)
	default:
		return err
	}
}

func signalName(sig syscall.Signal) string {
	switch sig {
	case syscall.SIGHUP:
		return "SIGHUP"
	case syscall.SIGINT:
		return "SIGINT"
	case syscall.SIGTERM:
		return "SIGTERM"
	case syscall.SIGABRT:
		return "SIGABRT"
	case syscall.SIGKILL:
		return "SIGKILL"
	case syscall.SIGSTOP:
		return "SIGSTOP"
	case syscall.SIGCONT:
		return "SIGCONT"
	default:
		return fmt.Sprintf("signal %d", int(sig))
	}
}
