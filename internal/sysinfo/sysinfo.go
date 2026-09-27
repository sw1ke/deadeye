package sysinfo

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Stats struct {
	CPUPercent float64
	PerCore    []float64
	NumCPU     int

	MemTotalKiB     uint64
	MemAvailableKiB uint64
	MemFreeKiB      uint64
	BuffersKiB      uint64
	CachedKiB       uint64
	ShmemKiB        uint64
	DirtyKiB        uint64
	SwapTotalKiB    uint64
	SwapFreeKiB     uint64

	Load1        float64
	Load5        float64
	Load15       float64
	ProcsRunning int
	ProcsBlocked int
	ProcsTotal   int

	Uptime time.Duration

	CtxtTotal  uint64
	ForksTotal uint64
	IRQTotal   uint64

	CollectedAt time.Time
	First       bool
}

func (s Stats) MemUsedKiB() uint64 {
	if s.MemTotalKiB == 0 {
		return 0
	}
	if s.MemAvailableKiB > 0 && s.MemTotalKiB >= s.MemAvailableKiB {
		return s.MemTotalKiB - s.MemAvailableKiB
	}
	var used uint64
	if s.MemTotalKiB > s.MemFreeKiB+s.BuffersKiB+s.CachedKiB {
		used = s.MemTotalKiB - s.MemFreeKiB - s.BuffersKiB - s.CachedKiB
	}
	return used
}

func (s Stats) MemPercent() float64 {
	if s.MemTotalKiB == 0 {
		return 0
	}
	return float64(s.MemUsedKiB()) / float64(s.MemTotalKiB) * 100
}

func (s Stats) SwapUsedKiB() uint64 {
	if s.SwapTotalKiB <= s.SwapFreeKiB {
		return 0
	}
	return s.SwapTotalKiB - s.SwapFreeKiB
}

func (s Stats) SwapPercent() float64 {
	if s.SwapTotalKiB == 0 {
		return 0
	}
	return float64(s.SwapUsedKiB()) / float64(s.SwapTotalKiB) * 100
}

func (s Stats) LoadPerCore() float64 {
	if s.NumCPU == 0 {
		return s.Load1
	}
	return s.Load1 / float64(s.NumCPU)
}

type cpuTimes struct {
	user    uint64
	nice    uint64
	system  uint64
	idle    uint64
	iowait  uint64
	irq     uint64
	softirq uint64
	steal   uint64
}

func (c cpuTimes) total() uint64 {
	return c.user + c.nice + c.system + c.idle + c.iowait + c.irq + c.softirq + c.steal
}

func (c cpuTimes) busy() uint64 {
	t := c.total()
	idle := c.idle + c.iowait
	if t <= idle {
		return 0
	}
	return t - idle
}

func percentDelta(prev, cur cpuTimes) float64 {
	if cur.total() <= prev.total() {
		return 0
	}
	total := float64(cur.total() - prev.total())
	var busy float64
	if cur.busy() > prev.busy() {
		busy = float64(cur.busy() - prev.busy())
	}
	pct := busy / total * 100
	if pct < 0 {
		return 0
	}
	if pct > 100 {
		return 100
	}
	return pct
}

type Reader struct {
	prevTotal cpuTimes
	prevCores []cpuTimes
	first     bool
}

func NewReader() *Reader {
	return &Reader{first: true}
}

func (r *Reader) Read() (Stats, error) {
	var st Stats
	st.CollectedAt = time.Now()
	st.First = r.first

	if err := r.readStat(&st); err != nil {
		return st, err
	}

	memErr := readMeminfo(&st)
	loadErr := readLoadavg(&st)
	upErr := readUptime(&st)
	if memErr != nil && loadErr != nil && upErr != nil {
		return st, fmt.Errorf("procfs unavailable: %w", memErr)
	}

	r.first = false
	return st, nil
}

func (r *Reader) readStat(st *Stats) error {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return fmt.Errorf("open /proc/stat: %w", err)
	}
	defer f.Close()

	var total cpuTimes
	var cores []cpuTimes

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.HasPrefix(line, "cpu"):
			fields := strings.Fields(line)
			if len(fields) < 5 {
				continue
			}
			ct, err := parseCPUFields(fields[1:])
			if err != nil {
				continue
			}
			if fields[0] == "cpu" {
				total = ct
			} else {
				cores = append(cores, ct)
			}
		case strings.HasPrefix(line, "ctxt "):
			st.CtxtTotal = secondField(line)
		case strings.HasPrefix(line, "processes "):
			st.ForksTotal = secondField(line)
		case strings.HasPrefix(line, "intr "):
			st.IRQTotal = secondField(line)
		case strings.HasPrefix(line, "procs_running "):
			st.ProcsRunning = int(secondField(line))
		case strings.HasPrefix(line, "procs_blocked "):
			st.ProcsBlocked = int(secondField(line))
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read /proc/stat: %w", err)
	}
	if len(cores) == 0 && total.total() == 0 {
		return fmt.Errorf("/proc/stat: no cpu lines found")
	}

	st.NumCPU = len(cores)
	st.PerCore = make([]float64, len(cores))
	for i, c := range cores {
		if i < len(r.prevCores) {
			st.PerCore[i] = percentDelta(r.prevCores[i], c)
		}
	}

	st.CPUPercent = percentDelta(r.prevTotal, total)

	r.prevTotal = total
	r.prevCores = cores
	return nil
}

func parseCPUFields(f []string) (cpuTimes, error) {
	var v [8]uint64
	for i := 0; i < len(v) && i < len(f); i++ {
		n, err := strconv.ParseUint(f[i], 10, 64)
		if err != nil {
			return cpuTimes{}, fmt.Errorf("field %d (%q): %w", i, f[i], err)
		}
		v[i] = n
	}
	return cpuTimes{
		user: v[0], nice: v[1], system: v[2], idle: v[3],
		iowait: v[4], irq: v[5], softirq: v[6], steal: v[7],
	}, nil
}

func secondField(line string) uint64 {
	f := strings.Fields(line)
	if len(f) < 2 {
		return 0
	}
	n, err := strconv.ParseUint(f[1], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func readMeminfo(st *Stats) error {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return fmt.Errorf("open /proc/meminfo: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		valStr := strings.TrimSpace(line[idx+1:])
		valStr = strings.TrimSuffix(valStr, "kB")
		v, err := strconv.ParseUint(strings.TrimSpace(valStr), 10, 64)
		if err != nil {
			continue
		}
		switch key {
		case "MemTotal":
			st.MemTotalKiB = v
		case "MemAvailable":
			st.MemAvailableKiB = v
		case "MemFree":
			st.MemFreeKiB = v
		case "Buffers":
			st.BuffersKiB = v
		case "Cached":
			st.CachedKiB = v
		case "Shmem":
			st.ShmemKiB = v
		case "Dirty":
			st.DirtyKiB = v
		case "SwapTotal":
			st.SwapTotalKiB = v
		case "SwapFree":
			st.SwapFreeKiB = v
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("read /proc/meminfo: %w", err)
	}
	if st.MemTotalKiB == 0 {
		return fmt.Errorf("/proc/meminfo: MemTotal not found")
	}

	if st.MemAvailableKiB == 0 {
		st.MemAvailableKiB = st.MemFreeKiB + st.BuffersKiB + st.CachedKiB
	}
	return nil
}

func readLoadavg(st *Stats) error {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return fmt.Errorf("open /proc/loadavg: %w", err)
	}
	f := strings.Fields(string(b))
	if len(f) < 4 {
		return fmt.Errorf("/proc/loadavg: unexpected format %q", strings.TrimSpace(string(b)))
	}
	if v, err := strconv.ParseFloat(f[0], 64); err == nil {
		st.Load1 = v
	}
	if v, err := strconv.ParseFloat(f[1], 64); err == nil {
		st.Load5 = v
	}
	if v, err := strconv.ParseFloat(f[2], 64); err == nil {
		st.Load15 = v
	}
	if parts := strings.SplitN(f[3], "/", 2); len(parts) == 2 {
		st.ProcsRunning = atoiOr(parts[0], st.ProcsRunning)
		if n, err := strconv.Atoi(parts[1]); err == nil {
			st.ProcsTotal = n
		}
	}
	return nil
}

func atoiOr(s string, fallback int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return fallback
}

func readUptime(st *Stats) error {
	b, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return fmt.Errorf("open /proc/uptime: %w", err)
	}
	f := strings.Fields(string(b))
	if len(f) == 0 {
		return fmt.Errorf("/proc/uptime is empty")
	}
	sec, err := strconv.ParseFloat(f[0], 64)
	if err != nil {
		return fmt.Errorf("/proc/uptime: %w", err)
	}
	st.Uptime = time.Duration(sec * float64(time.Second))
	return nil
}
