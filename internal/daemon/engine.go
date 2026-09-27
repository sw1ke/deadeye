package daemon

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"deadeye/internal/actions"
	"deadeye/internal/anomaly"
	"deadeye/internal/config"
	"deadeye/internal/human"
	"deadeye/internal/monitor"
	"deadeye/internal/proc"
	"deadeye/internal/sysinfo"
)

type anomalyKey struct {
	kind anomaly.Kind
	pid  int
}

type Engine struct {
	cfg *config.Config
	mon *monitor.Monitor
	det *anomaly.Detector
	act *actions.Manager
	log *actions.Log

	ownUID int

	mu          sync.Mutex
	ruleHits    map[string]int
	ruleLast    map[string]time.Time
	reported    map[anomalyKey]time.Time
	autoReniced map[anomalyKey]bool
	killing     map[int]time.Time

	wg sync.WaitGroup

	reportEvery  time.Duration
	summaryEvery time.Duration
	lastSummary  time.Time
}

func NewEngine(cfg *config.Config, mon *monitor.Monitor, det *anomaly.Detector, act *actions.Manager, log *actions.Log) *Engine {
	return &Engine{
		cfg:          cfg,
		mon:          mon,
		det:          det,
		act:          act,
		log:          log,
		ownUID:       os.Getuid(),
		ruleHits:     make(map[string]int),
		ruleLast:     make(map[string]time.Time),
		reported:     make(map[anomalyKey]time.Time),
		autoReniced:  make(map[anomalyKey]bool),
		killing:      make(map[int]time.Time),
		reportEvery:  5 * time.Minute,
		summaryEvery: time.Minute,
	}
}

func (e *Engine) Run(ctx context.Context) error {
	updates, unsub := e.mon.Subscribe()
	defer unsub()

	e.log.Infof("system", 0, "", "daemon mode started: %s", e.cfg.Summary())
	if len(e.cfg.Rules) > 0 {
		e.log.Infof("system", 0, "", "loaded %d reaction rules", len(e.cfg.Rules))
	}
	if e.cfg.Daemon.AutoKillAfterSec > 0 {
		kinds := strings.Join(e.cfg.Daemon.AutoKillKinds, ", ")
		if kinds == "" {
			kinds = "(list is empty — nothing will be killed)"
		}
		e.log.Warnf("system", 0, "", "enabled automatic termination after %d s; kinds: %s",
			e.cfg.Daemon.AutoKillAfterSec, kinds)
	}
	if e.cfg.Daemon.AutoRenice {
		e.log.Infof("system", 0, "", "enabled automatic priority lowering by +%d",
			e.cfg.Daemon.AutoReniceDelta)
	}

	for {
		select {
		case <-ctx.Done():
			e.shutdown()
			return nil
		case <-updates:
			e.processOnce(time.Now())
		}
	}
}

func (e *Engine) Wait() { e.wg.Wait() }

func (e *Engine) shutdown() {
	e.wg.Wait()
	e.log.Infof("system", 0, "", "daemon mode stopped")
}

func (e *Engine) processOnce(now time.Time) {
	procs, sys := e.mon.Snapshot()
	anoms := e.det.Update(procs, sys, now)

	byPID := make(map[int]proc.Snapshot, len(procs))
	for _, s := range procs {
		byPID[s.PID] = s
	}

	for _, a := range anoms {
		e.reportAnomaly(a, now)
	}
	e.forgetRecovered(anoms)

	suppressed := make(map[anomalyKey]bool, len(anoms))
	handled := make(map[anomalyKey]bool, len(anoms))

	for i := range anoms {
		a := anoms[i]
		key := anomalyKey{kind: a.Kind, pid: a.PID}

		s, ok := byPID[a.PID]
		if !ok {
			continue
		}
		if !e.allowedFor(s) {
			continue
		}

		for ri := range e.cfg.Rules {
			r := &e.cfg.Rules[ri]
			if !r.Matches(s, a) {
				continue
			}
			switch r.ActionName() {
			case "ignore":
				suppressed[key] = true
				if e.ruleAllowed(r, a, now, time.Minute) {
					e.markRule(r, a, now)
					e.log.Infof("rule", s.PID, s.Name, "rule %q: anomaly %s ignored",
						r.DisplayName(), a.Kind.Title())
				}
			case "log":
				if e.ruleAllowed(r, a, now, time.Minute) {
					e.markRule(r, a, now)
					e.log.Infof("rule", s.PID, s.Name, "rule %q: %s", r.DisplayName(), a.Detail)
				}
			case "renice":
				if e.ruleAllowed(r, a, now, 30*time.Second) {
					e.markRule(r, a, now)
					delta := r.NiceDelta
					if delta == 0 {
						delta = e.cfg.Daemon.AutoReniceDelta
					}
					e.doRenice(s, delta, fmt.Sprintf("rule %q", r.DisplayName()))
				}
			case "kill":
				if e.ruleAllowed(r, a, now, 30*time.Second) {
					e.markRule(r, a, now)
					scope := actions.ScopeProcess
					if r.KillTree {
						scope = actions.ScopeTree
					}
					e.killAsync(s, fmt.Sprintf("rule %q", r.DisplayName()), scope)
				}
			}
			handled[key] = true
			break
		}
	}

	e.applyAutoActions(anoms, byPID, suppressed, handled, now)
	e.maybeSummary(sys, procs, anoms, now)
}

func (e *Engine) allowedFor(s proc.Snapshot) bool {
	if !e.cfg.Daemon.OwnProcessesOnly {
		return true
	}
	return s.UID == e.ownUID
}

func (e *Engine) ruleAllowed(r *config.Rule, a anomaly.Anomaly, now time.Time, minCooldown time.Duration) bool {
	key := fmt.Sprintf("%s#%d#%s", r.DisplayName(), a.PID, a.Kind)

	e.mu.Lock()
	defer e.mu.Unlock()

	if r.MaxTimes > 0 && e.ruleHits[key] >= r.MaxTimes {
		return false
	}
	cooldown := r.Cooldown()
	if cooldown < minCooldown {
		cooldown = minCooldown
	}
	if last, ok := e.ruleLast[key]; ok && now.Sub(last) < cooldown {
		return false
	}
	return true
}

func (e *Engine) markRule(r *config.Rule, a anomaly.Anomaly, now time.Time) {
	key := fmt.Sprintf("%s#%d#%s", r.DisplayName(), a.PID, a.Kind)
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ruleHits[key]++
	e.ruleLast[key] = now
}

func (e *Engine) reportAnomaly(a anomaly.Anomaly, now time.Time) {
	k := anomalyKey{kind: a.Kind, pid: a.PID}

	e.mu.Lock()
	last, seen := e.reported[k]
	if seen && now.Sub(last) < e.reportEvery {
		e.mu.Unlock()
		return
	}
	e.reported[k] = now
	e.mu.Unlock()

	if !seen {
		e.log.Warnf("anomaly", a.PID, a.Name, "detected: %s — %s", a.Kind.Title(), a.Detail)
		return
	}
	e.log.Warnf("anomaly", a.PID, a.Name, "persisting for %s: %s — %s",
		human.Duration(now.Sub(a.Since)), a.Kind.Title(), a.Detail)
}

func (e *Engine) forgetRecovered(anoms []anomaly.Anomaly) {
	live := make(map[anomalyKey]bool, len(anoms))
	for _, a := range anoms {
		live[anomalyKey{kind: a.Kind, pid: a.PID}] = true
	}

	e.mu.Lock()
	var recovered []anomalyKey
	for k := range e.reported {
		if live[k] {
			continue
		}
		recovered = append(recovered, k)
		delete(e.reported, k)
		delete(e.autoReniced, k)
	}
	e.mu.Unlock()

	for _, k := range recovered {
		e.log.Infof("anomaly", k.pid, "", "recovery: %s is no longer observed", k.kind.Title())
	}
}

func (e *Engine) applyAutoActions(anoms []anomaly.Anomaly, byPID map[int]proc.Snapshot,
	suppressed, handled map[anomalyKey]bool, now time.Time) {

	killKinds := e.cfg.KillKindsSet()

	for _, a := range anoms {
		key := anomalyKey{kind: a.Kind, pid: a.PID}
		if suppressed[key] {
			continue
		}
		s, ok := byPID[a.PID]
		if !ok {
			continue
		}
		if !e.allowedFor(s) {
			continue
		}

		if e.cfg.Daemon.AutoRenice && !handled[key] {
			e.mu.Lock()
			done := e.autoReniced[key]
			if !done {
				e.autoReniced[key] = true
			}
			e.mu.Unlock()
			if !done {
				e.doRenice(s, e.cfg.Daemon.AutoReniceDelta, "auto_renice")
			}
		}

		if e.cfg.Daemon.AutoKillAfterSec > 0 && killKinds[a.Kind] {
			limit := time.Duration(e.cfg.Daemon.AutoKillAfterSec) * time.Second
			if dur := a.Duration(now); dur >= limit {
				e.killAsync(s, fmt.Sprintf("auto_kill_after_sec=%d (%s lasting %s)",
					e.cfg.Daemon.AutoKillAfterSec, a.Kind.Title(), human.Duration(dur)), actions.ScopeProcess)
			}
		}
	}
}

func (e *Engine) doRenice(s proc.Snapshot, delta int, reason string) {
	old, updated, err := e.act.ReniceChecked(s.PID, delta, s.StartTime)
	if err != nil {

		return
	}
	e.log.Actionf("rule", s.PID, s.Name, "%s: priority lowered, nice %d → %d", reason, old, updated)
}

func (e *Engine) killAsync(s proc.Snapshot, reason string, scope actions.KillScope) {
	pid, name := s.PID, s.Name
	e.mu.Lock()
	if _, busy := e.killing[pid]; busy {
		e.mu.Unlock()
		return
	}
	e.killing[pid] = time.Now()
	e.mu.Unlock()

	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		defer func() {
			e.mu.Lock()
			delete(e.killing, pid)
			e.mu.Unlock()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()

		if scope == actions.ScopeTree {
			e.log.Actionf("kill", pid, name, "automatic Smart Kill: %s (whole tree)", reason)
		} else {
			e.log.Actionf("kill", pid, name, "automatic Smart Kill: %s", reason)
		}
		opts := e.act.DefaultKillOptions()
		opts.Scope = scope
		opts.ExpectStart = s.StartTime
		report, err := e.act.SmartKill(ctx, pid, opts, func(st actions.StageRecord) {
			e.log.Infof("kill", pid, name, "stage %s: %s", st.Stage, st.Detail)
		})
		if err != nil {
			e.log.Errorf("kill", pid, name, "automatic termination failed: %v", err)
			return
		}
		e.log.Actionf("kill", pid, name, "%s", report.Summary())
		if report.Note != "" {
			e.log.Warnf("kill", pid, name, "%s", report.Note)
		}
	}()
}

func (e *Engine) maybeSummary(sys sysinfo.Stats, procs []proc.Snapshot, anoms []anomaly.Anomaly, now time.Time) {
	if e.summaryEvery <= 0 {
		return
	}
	if !e.lastSummary.IsZero() && now.Sub(e.lastSummary) < e.summaryEvery {
		return
	}
	e.lastSummary = now

	e.log.Infof("system", 0, "",
		"summary: CPU %s (%d cores), memory %s of %s (%s), swap %s, load %.2f/%.2f/%.2f, %d processes, %d anomalies",
		human.Percent(sys.CPUPercent), sys.NumCPU,
		human.FromKiB(float64(sys.MemUsedKiB())), human.FromKiB(float64(sys.MemTotalKiB)),
		human.Percent(sys.MemPercent()), human.FromKiB(float64(sys.SwapUsedKiB())),
		sys.Load1, sys.Load5, sys.Load15, len(procs), len(anoms))
}
