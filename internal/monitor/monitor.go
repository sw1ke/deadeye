package monitor

import (
	"context"
	"sync"
	"time"

	"deadeye/internal/proc"
	"deadeye/internal/sysinfo"
)

type Options struct {
	Interval      time.Duration
	History       int
	Workers       int
	IncludeKernel bool

	DeepEvery int

	UIDFilter int
}

func DefaultOptions() Options {
	return Options{

		Interval:      250 * time.Millisecond,
		History:       240,
		Workers:       8,
		IncludeKernel: false,
		DeepEvery:     8,
		UIDFilter:     -1,
	}
}

func (o *Options) normalize() {
	if o.Interval < 100*time.Millisecond {
		o.Interval = 100 * time.Millisecond
	}
	if o.Interval > time.Minute {
		o.Interval = time.Minute
	}
	if o.History < 8 {
		o.History = 8
	}
	if o.History > 8192 {
		o.History = 8192
	}
	if o.Workers < 1 {
		o.Workers = 1
	}
	if o.Workers > 128 {
		o.Workers = 128
	}
	if o.DeepEvery < 1 {
		o.DeepEvery = 1
	}
}

type Monitor struct {
	opts      Options
	clkTck    int64
	sysReader *sysinfo.Reader

	mu     sync.RWMutex
	procs  []proc.Snapshot
	sys    sysinfo.Stats
	prev   map[int]proc.Snapshot
	prevAt time.Time

	prevDeep   map[int]proc.Snapshot
	prevDeepAt time.Time
	tick       uint64
	cpuHist    *ring
	memHist    *ring
	rssHist    map[int]*ring
	samples    uint64
	lastErr    error
	startedAt  time.Time

	pollCh chan struct{}

	subMu sync.Mutex
	subs  map[chan struct{}]struct{}
}

func New(opts Options) *Monitor {
	opts.normalize()
	return &Monitor{
		opts:      opts,
		clkTck:    proc.ClkTck(),
		sysReader: sysinfo.NewReader(),
		prev:      make(map[int]proc.Snapshot),
		cpuHist:   newRing(opts.History),
		memHist:   newRing(opts.History),
		rssHist:   make(map[int]*ring),
		pollCh:    make(chan struct{}, 1),
		subs:      make(map[chan struct{}]struct{}),
	}
}

func (m *Monitor) Options() Options { return m.opts }

func (m *Monitor) StartedAt() time.Time { return m.startedAt }

func (m *Monitor) Run(ctx context.Context) {
	m.startedAt = time.Now()
	m.sample()

	t := time.NewTicker(m.opts.Interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.sample()
		case <-m.pollCh:
			m.sample()
		}
	}
}

func (m *Monitor) Poll() {
	select {
	case m.pollCh <- struct{}{}:
	default:
	}
}

func (m *Monitor) Subscribe() (<-chan struct{}, func()) {
	ch := make(chan struct{}, 1)
	m.subMu.Lock()
	m.subs[ch] = struct{}{}
	m.subMu.Unlock()

	unsub := func() {
		m.subMu.Lock()
		if _, ok := m.subs[ch]; ok {
			delete(m.subs, ch)
		}
		m.subMu.Unlock()
	}
	return ch, unsub
}

func (m *Monitor) notify() {
	m.subMu.Lock()
	defer m.subMu.Unlock()
	for ch := range m.subs {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

func (m *Monitor) Snapshot() ([]proc.Snapshot, sysinfo.Stats) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]proc.Snapshot, len(m.procs))
	copy(out, m.procs)
	return out, m.sys
}

func (m *Monitor) SysHistory() (cpu, mem []float64) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cpuHist.values(), m.memHist.values()
}

func (m *Monitor) RSSHistory(pid int) []float64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	r, ok := m.rssHist[pid]
	if !ok {
		return nil
	}
	return r.values()
}

func (m *Monitor) Samples() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.samples
}

func (m *Monitor) LastError() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastErr
}

func (m *Monitor) sample() {
	now := time.Now()
	m.tick++

	deep := m.tick%uint64(m.opts.DeepEvery) == 1 || m.opts.DeepEvery <= 1

	sys, sysErr := m.sysReader.Read()

	pids, listErr := proc.ListPIDs()
	if listErr != nil {
		m.setErr(listErr)
		return
	}

	results := make([]proc.Snapshot, len(pids))
	filled := make([]bool, len(pids))
	idxCh := make(chan int)

	var wg sync.WaitGroup
	for w := 0; w < m.opts.Workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range idxCh {

				var s proc.Snapshot
				var err error
				if deep || !m.knownPID(pids[i]) {
					s, err = proc.Read(pids[i])
				} else {
					s, err = proc.ReadFast(pids[i])
				}
				if err != nil {
					continue
				}
				results[i] = s
				filled[i] = true
			}
		}()
	}
	for i := range pids {
		idxCh <- i
	}
	close(idxCh)
	wg.Wait()

	m.mu.Lock()
	defer m.mu.Unlock()

	dt := 0.0
	if !m.prevAt.IsZero() {
		dt = now.Sub(m.prevAt).Seconds()
	}

	procs := make([]proc.Snapshot, 0, len(pids))
	for i := range pids {
		if !filled[i] {
			continue
		}
		s := results[i]

		prev, seen := m.prev[s.PID]
		if seen && !deep {

			s = carrySlowFields(s, prev)
		}

		if !m.opts.IncludeKernel && s.Kernel {
			continue
		}
		if m.opts.UIDFilter >= 0 && s.UID != m.opts.UIDFilter {
			continue
		}

		if seen {
			if dt > 0 {

				prevTicks := prev.Utime + prev.Stime
				curTicks := s.Utime + s.Stime
				if curTicks >= prevTicks {
					ticks := float64(curTicks - prevTicks)
					s.CPUPercent = (ticks / float64(m.clkTck)) / dt * 100
				}
				s.RSSDeltaKiB = float64(s.RSSKiB - prev.RSSKiB)
			}
		}

		if deep {
			dtDeep := 0.0
			if !m.prevDeepAt.IsZero() {
				dtDeep = now.Sub(m.prevDeepAt).Seconds()
			}
			if prev, seen := m.prevDeep[s.PID]; seen && dtDeep > 0 {
				if s.ReadBytes >= prev.ReadBytes {
					s.ReadRate = float64(s.ReadBytes-prev.ReadBytes) / dtDeep
				}
				if s.WriteBytes >= prev.WriteBytes {
					s.WriteRate = float64(s.WriteBytes-prev.WriteBytes) / dtDeep
				}
			} else if prev, seen := m.prev[s.PID]; seen {
				s.ReadRate, s.WriteRate = prev.ReadRate, prev.WriteRate
			}
		} else if seen {
			s.ReadRate, s.WriteRate = prev.ReadRate, prev.WriteRate
		}
		s.Age = now.Sub(s.StartTime)
		if s.Age < 0 {
			s.Age = 0
		}

		procs = append(procs, s)
	}

	m.cpuHist.push(sys.CPUPercent)
	m.memHist.push(sys.MemPercent())

	live := make(map[int]struct{}, len(procs))
	for _, s := range procs {
		live[s.PID] = struct{}{}
		r, ok := m.rssHist[s.PID]
		if !ok {
			r = newRing(m.opts.History)
			m.rssHist[s.PID] = r
		}
		r.push(float64(s.RSSKiB))
	}
	for pid := range m.rssHist {
		if _, ok := live[pid]; !ok {
			delete(m.rssHist, pid)
		}
	}

	nextPrev := make(map[int]proc.Snapshot, len(procs))
	for _, s := range procs {
		nextPrev[s.PID] = s
	}
	m.prev = nextPrev
	m.prevAt = now
	if deep {
		m.prevDeep = nextPrev
		m.prevDeepAt = now
	}
	m.procs = procs
	m.sys = sys
	m.samples++
	m.lastErr = sysErr

	m.notify()
}

func (m *Monitor) knownPID(pid int) bool {
	m.mu.RLock()
	_, ok := m.prev[pid]
	m.mu.RUnlock()
	return ok
}

func carrySlowFields(s, prev proc.Snapshot) proc.Snapshot {
	s.User, s.UID = prev.User, prev.UID
	s.Cmdline, s.Argv0 = prev.Cmdline, prev.Argv0
	s.Name = firstNonEmpty(s.Name, prev.Name)
	s.VmSizeKiB, s.SwapKiB = prev.VmSizeKiB, prev.SwapKiB
	s.VSizeBytes = prev.VSizeBytes
	s.FDCount, s.FDLimit = prev.FDCount, prev.FDLimit
	s.FDAccessible, s.FDPercent = prev.FDAccessible, prev.FDPercent
	s.RChar, s.WChar = prev.RChar, prev.WChar
	s.ReadBytes, s.WriteBytes = prev.ReadBytes, prev.WriteBytes
	s.SyscallRead, s.SyscallWrite = prev.SyscallRead, prev.SyscallWrite
	s.IOAccessible = prev.IOAccessible
	s.Kernel = prev.Kernel
	s.Wchan = prev.Wchan
	s.Threads = firstNonZero(s.Threads, prev.Threads)
	s.StateName = firstNonEmpty(s.StateName, prev.StateName)

	if s.StartTime.IsZero() {
		s.StartTime = prev.StartTime
	}
	return s
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func firstNonZero(a, b int64) int64 {
	if a != 0 {
		return a
	}
	return b
}

func (m *Monitor) setErr(err error) {
	m.mu.Lock()
	m.lastErr = err
	m.mu.Unlock()
}
