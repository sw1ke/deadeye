package hung

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"deadeye/internal/anomaly"
	"deadeye/internal/human"
	"deadeye/internal/proc"
)

type Verdict string

const (
	VerdictIOBlock  Verdict = "waiting for I/O"
	VerdictCPUBurn  Verdict = "burning CPU for nothing"
	VerdictZombie   Verdict = "zombie"
	VerdictStopped  Verdict = "stopped by a signal"
	VerdictRealtime Verdict = "real-time"
	VerdictSlow     Verdict = "slow, but working"
)

type Rules struct {
	IOBlockSec     int     `toml:"io_block_sec" json:"io_block_sec"`
	CPUBurnSec     int     `toml:"cpu_burn_sec" json:"cpu_burn_sec"`
	ZombieSec      int     `toml:"zombie_sec" json:"zombie_sec"`
	StoppedSec     int     `toml:"stopped_sec" json:"stopped_sec"`
	CPUBurnPercent float64 `toml:"cpu_burn_percent" json:"cpu_burn_percent"`
}

func DefaultRules() Rules {
	return Rules{
		IOBlockSec:     10,
		CPUBurnSec:     30,
		ZombieSec:      60,
		StoppedSec:     120,
		CPUBurnPercent: 90,
	}
}

func (r *Rules) Normalize() { r.normalize() }

func (r *Rules) normalize() {
	d := DefaultRules()
	if r.IOBlockSec <= 0 {
		r.IOBlockSec = d.IOBlockSec
	}
	if r.CPUBurnSec <= 0 {
		r.CPUBurnSec = d.CPUBurnSec
	}
	if r.ZombieSec <= 0 {
		r.ZombieSec = d.ZombieSec
	}
	if r.StoppedSec <= 0 {
		r.StoppedSec = d.StoppedSec
	}
	if r.CPUBurnPercent <= 0 {
		r.CPUBurnPercent = d.CPUBurnPercent
	}
}

type Item struct {
	PID       int
	PPID      int
	Name      string
	User      string
	State     string
	Wchan     string
	Since     time.Duration
	CPU       float64
	RSSKiB    int64
	Threads   int64
	Policy    int
	RTPrio    int
	Verdict   Verdict
	Evidence  []string
	Severity  float64
	Action    string
	StartTime time.Time
	Protected bool
	Why       string
}

func (it Item) Title() string {
	if n := it.Name; n != "" {
		return n
	}
	return fmt.Sprintf("PID %d", it.PID)
}

type Tracker struct {
	rules Rules
	since map[int]mark
}

type mark struct {
	state string
	at    time.Time
}

func NewTracker(rules Rules) *Tracker {
	rules.normalize()
	return &Tracker{rules: rules, since: make(map[int]mark, 64)}
}

func (t *Tracker) Rules() Rules { return t.rules }

func (t *Tracker) Update(procs []proc.Snapshot, anoms []anomaly.Anomaly, now time.Time) []Item {
	byPID := make(map[int]anomaly.Anomaly, len(anoms))
	for _, a := range anoms {
		if _, ok := byPID[a.PID]; !ok {
			byPID[a.PID] = a
		}
	}

	alive := make(map[int]bool, len(procs))
	out := make([]Item, 0, 8)
	for _, s := range procs {
		alive[s.PID] = true
		prev, seen := t.since[s.PID]
		if !seen || prev.state != s.State {
			t.since[s.PID] = mark{state: s.State, at: now}
			continue
		}
		dur := now.Sub(prev.at)
		if it, ok := t.classify(s, dur, byPID[s.PID]); ok {
			out = append(out, it)
		}
	}

	for pid := range t.since {
		if !alive[pid] {
			delete(t.since, pid)
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		return out[i].Since > out[j].Since
	})
	return out
}

func (t *Tracker) classify(s proc.Snapshot, dur time.Duration, a anomaly.Anomaly) (Item, bool) {
	it := Item{
		PID: s.PID, PPID: s.PPID, Name: s.DisplayName(), User: s.User,
		State: s.State, Wchan: s.Wchan, Since: dur, CPU: s.CPUPercent,
		RSSKiB: s.RSSKiB, Threads: s.Threads, Policy: s.Policy, RTPrio: s.RTPriority,
		StartTime: s.StartTime,
	}

	switch {
	case s.Kernel || s.PID == 2 || s.PPID == 2:

		return it, false

	case s.State == proc.StateZombie:
		if dur < time.Duration(t.rules.ZombieSec)*time.Second {
			return it, false
		}
		it.Verdict = VerdictZombie
		it.Evidence = append(it.Evidence,
			fmt.Sprintf("state Z for %s", human.Duration(dur)),
			"the process exited but its parent never collected the status")
		it.Action = fmt.Sprintf("kill parent PID %d — the zombie itself cannot be killed", s.PPID)
		it.Severity = 0.45

	case s.State == proc.StateDiskSleep:
		if dur < time.Duration(t.rules.IOBlockSec)*time.Second {
			return it, false
		}
		it.Verdict = VerdictIOBlock
		ev := fmt.Sprintf("uninterruptible kernel sleep (D) for %s", human.Duration(dur))
		if it.Wchan != "" && it.Wchan != "0" {
			ev += ", waiting in " + it.Wchan
		}
		it.Evidence = append(it.Evidence, ev)
		if !s.IOAccessible {
			it.Evidence = append(it.Evidence,
				"cannot read /proc/[pid]/io: without root not everything is visible")
		}
		it.Action = "wait for the device; SIGKILL in D state will not work, " +
			"until the kernel releases the process"
		it.Severity = severityForDuration(dur, time.Duration(t.rules.IOBlockSec)*time.Second, 0.55, 0.95)

	case s.State == proc.StateStopped || s.State == proc.StateTraced:
		if dur < time.Duration(t.rules.StoppedSec)*time.Second {
			return it, false
		}
		it.Verdict = VerdictStopped
		it.Evidence = append(it.Evidence,
			fmt.Sprintf("stopped (state %s) for %s", s.State, human.Duration(dur)),
			"usually a forgotten Ctrl+Z or a debugger pause")
		it.Action = "resume: kill -CONT " + fmt.Sprint(s.PID) + ", or kill it"
		it.Severity = 0.4

	case a.Kind == anomaly.KindHung:
		it.Verdict = VerdictCPUBurn
		it.Evidence = append(it.Evidence,
			fmt.Sprintf("CPU %.1f%% with almost no I/O", s.CPUPercent),
			a.Detail)
		it.Action = "make a core dump (SIGABRT) and kill, or lower the priority"
		it.Severity = 0.8 + 0.2*a.Severity

	case (s.Policy == 1 || s.Policy == 2) && s.CPUPercent >= t.rules.CPUBurnPercent:

		it.Verdict = VerdictRealtime
		it.Evidence = append(it.Evidence,
			fmt.Sprintf("policy %s, priority %d, CPU %.1f%% for %s",
				policyName(s.Policy), s.RTPriority, s.CPUPercent, human.Duration(dur)),
			"crowds out normal processes: everything around it lags, not it")
		it.Action = "cannot drop SCHED_FIFO/RR without root; restarting the app usually helps"
		it.Severity = 0.85

	case s.CPUPercent >= t.rules.CPUBurnPercent && dur >= time.Duration(t.rules.CPUBurnSec)*time.Second:

		it.Verdict = VerdictSlow
		it.Evidence = append(it.Evidence,
			fmt.Sprintf("CPU %.1f%% continuously for %s", s.CPUPercent, human.Duration(dur)))
		it.Action = "check whether this process is useful; lower its priority (F7) if not"
		it.Severity = 0.3
		if dur >= 5*time.Duration(t.rules.CPUBurnSec)*time.Second {
			it.Severity = 0.6
		}

	default:
		return it, false
	}

	if s.PID == 1 {
		it.Protected, it.Why = true, "init: the system cannot live without it"
	}
	return it, true
}

func severityForDuration(dur, base time.Duration, lo, hi float64) float64 {
	if dur <= base {
		return lo
	}
	k := float64(dur) / float64(base*10)
	if k > 1 {
		k = 1
	}
	return lo + (hi-lo)*k
}

func policyName(p int) string {
	switch p {
	case 1:
		return "SCHED_FIFO"
	case 2:
		return "SCHED_RR"
	}
	return fmt.Sprintf("policy %d", p)
}

func ReadWchan(pid int) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/wchan", pid))
	if err != nil {
		return ""
	}
	s := strings.TrimSpace(string(b))
	if s == "" || s == "0" {
		return ""
	}
	return s
}

func Summarize(items []Item) string {
	if len(items) == 0 {
		return "no stuck processes"
	}
	counts := map[Verdict]int{}
	for _, it := range items {
		counts[it.Verdict]++
	}
	order := []Verdict{VerdictCPUBurn, VerdictIOBlock, VerdictZombie, VerdictStopped,
		VerdictRealtime, VerdictSlow}
	parts := make([]string, 0, len(counts))
	for _, v := range order {
		if n := counts[v]; n > 0 {
			parts = append(parts, fmt.Sprintf("%s — %d", v, n))
		}
	}
	return fmt.Sprintf("%s: %s", human.Pluralf(len(items), "stuck process",
		"stuck processes", "stuck processes"), strings.Join(parts, ", "))
}
