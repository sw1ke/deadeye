package anomaly

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"

	"deadeye/internal/human"
	"deadeye/internal/proc"
	"deadeye/internal/sysinfo"
)

type Kind string

const (
	KindHung    Kind = "hung"
	KindLeak    Kind = "memleak"
	KindFD      Kind = "fdleak"
	KindZombie  Kind = "zombie"
	KindIOStorm Kind = "iostorm"
)

func AllKinds() []Kind {
	return []Kind{KindHung, KindLeak, KindFD, KindZombie, KindIOStorm}
}

func (k Kind) Title() string {
	switch k {
	case KindHung:
		return "Hung"
	case KindLeak:
		return "Memory leak"
	case KindFD:
		return "FD leak"
	case KindZombie:
		return "Zombie"
	case KindIOStorm:
		return "I/O storm"
	default:
		return string(k)
	}
}

func (k Kind) Short() string {
	switch k {
	case KindHung:
		return "HUNG"
	case KindLeak:
		return "LEAK"
	case KindFD:
		return "FD"
	case KindZombie:
		return "ZOMB"
	case KindIOStorm:
		return "I/O"
	default:
		return strings.ToUpper(string(k))
	}
}

func ParseKind(s string) (Kind, bool) {
	k := Kind(strings.ToLower(strings.TrimSpace(s)))
	switch k {
	case KindHung, KindLeak, KindFD, KindZombie, KindIOStorm:
		return k, true
	case "any", "all", "*":
		return "", true
	}
	return "", false
}

type Anomaly struct {
	Kind     Kind
	PID      int
	Name     string
	Cmdline  string
	User     string
	Value    float64
	Severity float64
	Detail   string
	Since    time.Time
	LastSeen time.Time
}

func (a Anomaly) Duration(now time.Time) time.Duration {
	if a.Since.IsZero() {
		return 0
	}
	d := now.Sub(a.Since)
	if d < 0 {
		return 0
	}
	return d
}

func (a Anomaly) String() string {
	return fmt.Sprintf("%s pid=%d name=%q: %s", a.Kind.Title(), a.PID, a.Name, a.Detail)
}

type Rules struct {
	HungCPUPercent       float64
	HungSeconds          float64
	HungMaxIOBytesPerSec float64

	LeakWindow            int
	LeakMinSlopeKiBPerSec float64
	LeakMaxDropRatio      float64
	LeakMinRSSKiB         float64
	LeakMinR2             float64

	FDWarnRatio     float64
	ZombieSeconds   float64
	IOStormMBPerSec float64
}

func DefaultRules() Rules {
	return Rules{
		HungCPUPercent:       95,
		HungSeconds:          30,
		HungMaxIOBytesPerSec: 4 * human.KiB,

		LeakWindow:            60,
		LeakMinSlopeKiBPerSec: 512,
		LeakMaxDropRatio:      0.05,
		LeakMinRSSKiB:         64 * human.KiB,
		LeakMinR2:             0.80,

		FDWarnRatio:     0.80,
		ZombieSeconds:   60,
		IOStormMBPerSec: 200,
	}
}

func (r *Rules) normalize() {
	if r.HungCPUPercent <= 0 {
		r.HungCPUPercent = 95
	}
	if r.HungSeconds <= 0 {
		r.HungSeconds = 30
	}
	if r.HungMaxIOBytesPerSec < 0 {
		r.HungMaxIOBytesPerSec = 0
	}
	if r.LeakWindow < 3 {
		r.LeakWindow = 3
	}
	if r.LeakWindow > 100000 {
		r.LeakWindow = 100000
	}
	if r.LeakMinSlopeKiBPerSec <= 0 {
		r.LeakMinSlopeKiBPerSec = 512
	}
	if r.LeakMaxDropRatio <= 0 {
		r.LeakMaxDropRatio = 0.05
	}
	if r.LeakMaxDropRatio > 1 {
		r.LeakMaxDropRatio = 1
	}
	if r.LeakMinRSSKiB < 0 {
		r.LeakMinRSSKiB = 0
	}
	if r.LeakMinR2 <= 0 || r.LeakMinR2 > 1 {
		r.LeakMinR2 = 0.80
	}
	if r.FDWarnRatio <= 0 || r.FDWarnRatio > 1 {
		r.FDWarnRatio = 0.80
	}
	if r.ZombieSeconds <= 0 {
		r.ZombieSeconds = 60
	}
	if r.IOStormMBPerSec < 0 {
		r.IOStormMBPerSec = 0
	}
}

type procState struct {
	hotSince    time.Time
	zombieSince time.Time
	ioSince     time.Time
}

type rssSeries struct {
	t   []time.Time
	v   []float64
	cap int
}

func (s *rssSeries) push(t time.Time, v float64) {
	s.t = append(s.t, t)
	s.v = append(s.v, v)
	if len(s.t) > s.cap {
		drop := len(s.t) - s.cap
		s.t = s.t[drop:]
		s.v = s.v[drop:]
	}
}

type activeKey struct {
	kind Kind
	pid  int
}

type Detector struct {
	rules   Rules
	holdoff time.Duration

	mu     sync.Mutex
	states map[int]*procState
	series map[int]*rssSeries
	active map[activeKey]*Anomaly
}

func NewDetector(rules Rules, interval time.Duration) *Detector {
	rules.normalize()
	holdoff := 5 * time.Second
	if interval > 0 {
		if h := 3 * interval; h > holdoff {
			holdoff = h
		}
	}
	return &Detector{
		rules:   rules,
		holdoff: holdoff,
		states:  make(map[int]*procState),
		series:  make(map[int]*rssSeries),
		active:  make(map[activeKey]*Anomaly),
	}
}

func (d *Detector) Rules() Rules { return d.rules }

func (d *Detector) Update(procs []proc.Snapshot, sys sysinfo.Stats, now time.Time) []Anomaly {
	d.mu.Lock()
	defer d.mu.Unlock()

	seen := make(map[int]struct{}, len(procs))
	for i := range procs {
		s := procs[i]
		seen[s.PID] = struct{}{}

		st := d.states[s.PID]
		if st == nil {
			st = &procState{}
			d.states[s.PID] = st
		}
		d.pushRSS(s.PID, now, float64(s.RSSKiB))

		if a, ok := d.checkHung(s, st, now); ok {
			d.raise(a, now)
		}

		if a, ok := d.checkLeak(s, sys, now); ok {
			d.raise(a, now)
		}

		if a, ok := d.checkFD(s); ok {
			d.raise(a, now)
		}

		if a, ok := d.checkZombie(s, st, now); ok {
			d.raise(a, now)
		}

		if a, ok := d.checkIOStorm(s, st, now); ok {
			d.raise(a, now)
		}
	}

	for pid := range d.states {
		if _, ok := seen[pid]; !ok {
			delete(d.states, pid)
			delete(d.series, pid)
		}
	}

	for k, a := range d.active {
		if now.Sub(a.LastSeen) > d.holdoff {
			delete(d.active, k)
		}
	}

	return d.sortedActiveLocked()
}

func (d *Detector) Active() []Anomaly {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sortedActiveLocked()
}

func (d *Detector) Count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.active)
}

func (d *Detector) sortedActiveLocked() []Anomaly {
	out := make([]Anomaly, 0, len(d.active))
	for _, a := range d.active {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		if out[i].Since != out[j].Since {
			return out[i].Since.Before(out[j].Since)
		}
		return out[i].PID < out[j].PID
	})
	return out
}

func (d *Detector) raise(a Anomaly, now time.Time) {
	k := activeKey{kind: a.Kind, pid: a.PID}
	if prev, ok := d.active[k]; ok {
		a.Since = prev.Since
	} else {
		a.Since = now
	}
	a.LastSeen = now
	d.active[k] = &a
}

func (d *Detector) pushRSS(pid int, now time.Time, kib float64) {
	s := d.series[pid]
	if s == nil {
		s = &rssSeries{cap: d.rules.LeakWindow}
		d.series[pid] = s
	}
	s.push(now, kib)
}

func (d *Detector) checkHung(s proc.Snapshot, st *procState, now time.Time) (Anomaly, bool) {
	r := d.rules
	if s.Kernel || s.IsZombie() {
		st.hotSince = time.Time{}
		return Anomaly{}, false
	}

	if !s.IOAccessible {
		st.hotSince = time.Time{}
		return Anomaly{}, false
	}
	hot := s.CPUPercent >= r.HungCPUPercent
	quiet := (s.ReadRate + s.WriteRate) <= r.HungMaxIOBytesPerSec
	if !hot || !quiet {

		st.hotSince = time.Time{}
		return Anomaly{}, false
	}
	if st.hotSince.IsZero() {
		st.hotSince = now
		return Anomaly{}, false
	}
	elapsed := now.Sub(st.hotSince)
	if elapsed.Seconds() < r.HungSeconds {
		return Anomaly{}, false
	}
	sev := math.Min(1, 0.45+elapsed.Seconds()/(4*r.HungSeconds))
	return Anomaly{
		Kind:     KindHung,
		PID:      s.PID,
		Name:     s.Name,
		Cmdline:  s.Cmdline,
		User:     s.User,
		Value:    s.CPUPercent,
		Severity: sev,
		Detail: fmt.Sprintf("CPU %s with no block I/O for %s (threshold %s); I/O %s, threads %d, state %s",
			human.Percent(s.CPUPercent), human.Duration(elapsed),
			human.Duration(time.Duration(r.HungSeconds*float64(time.Second))),
			human.Rate(s.ReadRate+s.WriteRate), s.Threads, s.StateName),
	}, true
}

func (d *Detector) checkLeak(s proc.Snapshot, sys sysinfo.Stats, now time.Time) (Anomaly, bool) {
	r := d.rules
	ser := d.series[s.PID]
	if ser == nil || len(ser.v) < r.LeakWindow || len(ser.v) < 3 {
		return Anomaly{}, false
	}
	if float64(s.RSSKiB) < r.LeakMinRSSKiB {
		return Anomaly{}, false
	}

	xs := make([]float64, len(ser.t))
	base := ser.t[0]
	for i, t := range ser.t {
		xs[i] = t.Sub(base).Seconds()
	}
	slope, _, r2 := linregress(xs, ser.v)
	if slope < r.LeakMinSlopeKiBPerSec || r2 < r.LeakMinR2 {
		return Anomaly{}, false
	}

	if drop := maxRelativeDrop(ser.v); drop > r.LeakMaxDropRatio {
		return Anomaly{}, false
	}

	sev := math.Min(1, 0.35+0.65*math.Min(1, slope/(10*r.LeakMinSlopeKiBPerSec)))
	if sys.MemPercent() > 85 {
		sev = math.Min(1, sev+0.2)
	}

	cur := ser.v[len(ser.v)-1]
	eta := ""
	if slope > 0 && cur > 0 {
		doubling := time.Duration(cur/slope) * time.Second
		eta = fmt.Sprintf("; RSS doubles in ~%s", human.Duration(doubling))
	}
	windowDur := ser.t[len(ser.t)-1].Sub(base)

	return Anomaly{
		Kind:     KindLeak,
		PID:      s.PID,
		Name:     s.Name,
		Cmdline:  s.Cmdline,
		User:     s.User,
		Value:    slope,
		Severity: sev,
		Detail: fmt.Sprintf("RSS grows linearly: +%s/s (R²=%.2f, window %d snaps / %s), now %s%s",
			human.FromKiB(slope), r2, len(ser.v), human.Duration(windowDur),
			human.FromKiB(cur), eta),
	}, true
}

func (d *Detector) checkFD(s proc.Snapshot) (Anomaly, bool) {
	r := d.rules
	if !s.FDAccessible || s.FDCount < 0 || s.FDLimit == 0 {
		return Anomaly{}, false
	}
	ratio := float64(s.FDCount) / float64(s.FDLimit)
	if ratio < r.FDWarnRatio {
		return Anomaly{}, false
	}
	return Anomaly{
		Kind:     KindFD,
		PID:      s.PID,
		Name:     s.Name,
		Cmdline:  s.Cmdline,
		User:     s.User,
		Value:    ratio,
		Severity: math.Min(1, ratio),
		Detail: fmt.Sprintf("%d of %d fds open (%s of the limit)",
			s.FDCount, s.FDLimit, human.Percent(ratio*100)),
	}, true
}

func (d *Detector) checkZombie(s proc.Snapshot, st *procState, now time.Time) (Anomaly, bool) {
	r := d.rules
	if s.State != proc.StateZombie {
		st.zombieSince = time.Time{}
		return Anomaly{}, false
	}
	if st.zombieSince.IsZero() {
		st.zombieSince = now
		return Anomaly{}, false
	}
	elapsed := now.Sub(st.zombieSince)
	if elapsed.Seconds() < r.ZombieSeconds {
		return Anomaly{}, false
	}
	return Anomaly{
		Kind:     KindZombie,
		PID:      s.PID,
		Name:     s.Name,
		Cmdline:  s.Cmdline,
		User:     s.User,
		Value:    elapsed.Seconds(),
		Severity: 0.35,
		Detail: fmt.Sprintf("zombie for %s already; parent PID %d does not reap the exit status",
			human.Duration(elapsed), s.PPID),
	}, true
}

func (d *Detector) checkIOStorm(s proc.Snapshot, st *procState, now time.Time) (Anomaly, bool) {
	r := d.rules
	if !s.IOAccessible || r.IOStormMBPerSec <= 0 {
		st.ioSince = time.Time{}
		return Anomaly{}, false
	}
	rate := s.ReadRate + s.WriteRate
	threshold := r.IOStormMBPerSec * float64(human.MiB)
	if rate < threshold {
		st.ioSince = time.Time{}
		return Anomaly{}, false
	}
	if st.ioSince.IsZero() {
		st.ioSince = now
		return Anomaly{}, false
	}
	elapsed := now.Sub(st.ioSince)
	if elapsed < 10*time.Second {
		return Anomaly{}, false
	}
	return Anomaly{
		Kind:     KindIOStorm,
		PID:      s.PID,
		Name:     s.Name,
		Cmdline:  s.Cmdline,
		User:     s.User,
		Value:    rate,
		Severity: math.Min(1, rate/(threshold*4)),
		Detail: fmt.Sprintf("block I/O %s (read %s, write %s) for %s",
			human.Rate(rate), human.Rate(s.ReadRate), human.Rate(s.WriteRate),
			human.Duration(elapsed)),
	}, true
}

func linregress(xs, ys []float64) (slope, intercept, r2 float64) {
	n := len(xs)
	if n < 2 || n != len(ys) {
		return 0, 0, 0
	}
	var sx, sy, sxy, sxx, syy float64
	for i := 0; i < n; i++ {
		sx += xs[i]
		sy += ys[i]
		sxy += xs[i] * ys[i]
		sxx += xs[i] * xs[i]
		syy += ys[i] * ys[i]
	}
	fn := float64(n)
	denom := fn*sxx - sx*sx
	if denom == 0 {
		return 0, sy / fn, 0
	}
	slope = (fn*sxy - sx*sy) / denom
	intercept = (sy - slope*sx) / fn

	dY := fn*syy - sy*sy
	if dY <= 0 || denom <= 0 {
		return slope, intercept, 0
	}
	r := (fn*sxy - sx*sy) / math.Sqrt(denom*dY)
	return slope, intercept, r * r
}

func maxRelativeDrop(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	peak := v[0]
	drop := 0.0
	for _, x := range v {
		if x > peak {
			peak = x
			continue
		}
		if peak > 0 {
			if d := (peak - x) / peak; d > drop {
				drop = d
			}
		}
	}
	return drop
}

func Trend(values []float64, interval time.Duration) (slope, r2 float64) {
	if len(values) < 3 || interval <= 0 {
		return 0, 0
	}
	secs := interval.Seconds()
	xs := make([]float64, len(values))
	for i := range values {
		xs[i] = float64(i) * secs
	}
	slope, _, r2 = linregress(xs, values)
	return slope, r2
}

func MaxRelativeDrop(values []float64) float64 { return maxRelativeDrop(values) }

func (d *Detector) Holdoff() time.Duration { return d.holdoff }

func Summary(r Rules) string {
	return fmt.Sprintf("hung: CPU ≥ %.0f%% with I/O ≤ %s/s for over %.0f s; "+
		"leak: RSS slope ≥ %.0f KiB/s with R² ≥ %.2f, window %d snaps, drop from peak ≤ %.0f%%, minimum %.0f MiB; "+
		"fds: ≥ %.0f%% of the limit; zombie: > %.0f s; I/O storm: ≥ %.0f MiB/s",
		r.HungCPUPercent, human.Bytes(r.HungMaxIOBytesPerSec), r.HungSeconds,
		r.LeakMinSlopeKiBPerSec, r.LeakMinR2, r.LeakWindow, r.LeakMaxDropRatio*100,
		r.LeakMinRSSKiB/1024, r.FDWarnRatio*100, r.ZombieSeconds, r.IOStormMBPerSec)
}
