package proc

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	StateRunning   = "R"
	StateSleeping  = "S"
	StateDiskSleep = "D"
	StateZombie    = "Z"
	StateStopped   = "T"
	StateTraced    = "t"
	StateIdle      = "I"
	StateDead      = "X"
	StateWakekill  = "W"
	StateParked    = "P"
)

var ErrVanished = errors.New("process vanished")

type Snapshot struct {
	PID  int
	Name string

	Cmdline string
	Kernel  bool

	noCmdline bool

	State     string
	StateName string
	PPID      int
	PGID      int
	SID       int

	Policy     int
	RTPriority int

	Argv0 string

	UID  int
	User string

	Priority int
	Nice     int
	Threads  int64

	RSSKiB     int64
	RSSPages   int64
	VmSizeKiB  int64
	SwapKiB    int64
	VSizeBytes uint64

	Wchan        string
	FDCount      int
	FDLimit      uint64
	FDAccessible bool
	FDPercent    float64

	RChar        uint64
	WChar        uint64
	ReadBytes    uint64
	WriteBytes   uint64
	SyscallRead  uint64
	SyscallWrite uint64
	IOAccessible bool

	Utime      uint64
	Stime      uint64
	StartTicks uint64
	StartTime  time.Time
	Age        time.Duration

	CPUPercent  float64
	ReadRate    float64
	WriteRate   float64
	RSSDeltaKiB float64
}

func (s Snapshot) TotalCPUPercent() float64 { return s.CPUPercent }

func (s Snapshot) IORate() float64 { return s.ReadRate + s.WriteRate }

func (s Snapshot) IsZombie() bool { return s.State == StateZombie }

var (
	clkOnce sync.Once
	clkTck  int64
)

func ClkTck() int64 {
	clkOnce.Do(func() {
		clkTck = 100
		out, err := runGetconf()
		if err != nil {
			return
		}
		if n, err := strconv.ParseInt(strings.TrimSpace(out), 10, 64); err == nil && n > 0 {
			clkTck = n
		}
	})
	return clkTck
}

func runGetconf() (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "getconf", "CLK_TCK").Output()
	if err != nil {
		return "", fmt.Errorf("getconf CLK_TCK: %w", err)
	}
	return string(out), nil
}

func PageSize() int64 { return int64(os.Getpagesize()) }

var (
	bootOnce sync.Once
	bootAt   time.Time
)

func BootTime() time.Time {
	bootOnce.Do(func() {
		b, err := os.ReadFile("/proc/stat")
		if err != nil {
			bootAt = time.Now()
			return
		}
		for _, line := range strings.Split(string(b), "\n") {
			if !strings.HasPrefix(line, "btime ") {
				continue
			}
			f := strings.Fields(line)
			if len(f) == 2 {
				if sec, err := strconv.ParseInt(f[1], 10, 64); err == nil && sec > 0 {
					bootAt = time.Unix(sec, 0)
				}
			}
			break
		}
		if bootAt.IsZero() {
			bootAt = time.Now()
		}
	})
	return bootAt
}

func ListPIDs() ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("read /proc: %w", err)
	}
	pids := make([]int, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		pids = append(pids, pid)
	}
	sort.Ints(pids)
	return pids, nil
}

func Read(pid int) (Snapshot, error) { return read(pid, true) }

func ReadFast(pid int) (Snapshot, error) { return read(pid, false) }

func read(pid int, deep bool) (Snapshot, error) {
	base := "/proc/" + strconv.Itoa(pid)
	var s Snapshot
	s.PID = pid
	s.FDCount = -1

	if err := s.readStat(base); err != nil {
		return s, err
	}
	if !deep {
		s.FDCount = -1
		s.readStatm(base)

		s.Kernel = s.PPID == 2 || s.PID == 2
		s.StartTime = BootTime().Add(time.Duration(s.StartTicks) * time.Second / time.Duration(ClkTck()))
		s.StateName = StateName(s.State)
		return s, nil
	}
	s.readStatus(base)
	s.readCmdline(base)
	s.readIO(base)
	s.readFDs(base)
	s.readLimits(base)
	s.readWchan(base)

	s.Kernel = s.noCmdline && s.State != StateZombie && (s.PID == 2 || s.PPID == 2)
	if s.State == StateZombie && !s.noCmdline {
		s.Cmdline = "[" + s.Name + "]"
		s.noCmdline = true
	}

	if s.RSSKiB == 0 && s.RSSPages > 0 {
		s.RSSKiB = s.RSSPages * PageSize() / 1024
	}
	if s.VmSizeKiB == 0 && s.VSizeBytes > 0 {
		s.VmSizeKiB = int64(s.VSizeBytes / 1024)
	}
	s.StateName = StateName(s.State)
	s.User = Username(s.UID)
	if s.StartTicks > 0 {
		s.StartTime = BootTime().Add(time.Duration(s.StartTicks) * time.Second / time.Duration(ClkTck()))
		s.Age = time.Since(s.StartTime)
		if s.Age < 0 {
			s.Age = 0
		}
	}
	if s.FDAccessible && s.FDLimit > 0 && s.FDCount >= 0 {
		s.FDPercent = float64(s.FDCount) / float64(s.FDLimit) * 100
	}
	return s, nil
}

func (s *Snapshot) readStat(base string) error {
	b, err := os.ReadFile(base + "/stat")
	if err != nil {
		if isGone(err) {
			return fmt.Errorf("%w: %v", ErrVanished, err)
		}
		return fmt.Errorf("stat: %w", err)
	}
	return applyStat(s, string(b))
}

func applyStat(s *Snapshot, str string) error {
	open := strings.IndexByte(str, '(')
	closing := strings.LastIndexByte(str, ')')
	if open < 0 || closing <= open {
		return fmt.Errorf("stat: unexpected format %q", truncate(str, 60))
	}
	s.Name = str[open+1 : closing]

	f := strings.Fields(str[closing+1:])
	if len(f) < 22 {
		return fmt.Errorf("stat: too few fields (%d)", len(f))
	}

	s.State = f[0]
	s.PPID = atoiField(f[1])
	s.PGID = atoiField(f[2])
	s.SID = atoiField(f[3])
	s.Utime = atouField(f[11])
	s.Stime = atouField(f[12])
	s.Priority = atoiField(f[15])
	s.Nice = atoiField(f[16])
	s.Threads = int64(atouField(f[17]))
	s.StartTicks = atouField(f[19])
	s.VSizeBytes = atouField(f[20])
	s.RSSPages = int64(atouField(f[21]))

	if len(f) >= 39 {
		s.RTPriority = atoiField(f[37])
		s.Policy = atoiField(f[38])
	}
	return nil
}

const (
	SchedOther    = 0
	SchedFIFO     = 1
	SchedRR       = 2
	SchedBatch    = 3
	SchedIdle     = 5
	SchedDeadline = 6
)

func (s Snapshot) SchedName() string {
	switch s.Policy {
	case SchedFIFO:
		return "SCHED_FIFO"
	case SchedRR:
		return "SCHED_RR"
	case SchedBatch:
		return "SCHED_BATCH"
	case SchedIdle:
		return "SCHED_IDLE"
	case SchedDeadline:
		return "SCHED_DEADLINE"
	case SchedOther:
		return "SCHED_OTHER"
	}
	return "unknown (" + strconv.Itoa(s.Policy) + ")"
}

func (s Snapshot) IsRealtime() bool {
	return s.Policy == SchedFIFO || s.Policy == SchedRR || s.Policy == SchedDeadline
}

func (s Snapshot) NiceLabel() string {
	switch s.Policy {
	case SchedFIFO:
		return "F" + strconv.Itoa(s.RTPriority)
	case SchedRR:
		return "R" + strconv.Itoa(s.RTPriority)
	case SchedDeadline:
		return "DL"
	case SchedIdle:
		return "I" + strconv.Itoa(s.Nice)
	case SchedBatch:
		return "B" + strconv.Itoa(s.Nice)
	}
	return strconv.Itoa(s.Nice)
}

func (s *Snapshot) readStatus(base string) {
	f, err := os.Open(base + "/status")
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		key := line[:idx]
		val := strings.TrimSpace(line[idx+1:])
		switch key {
		case "VmRSS":
			s.RSSKiB = kibField(val)
		case "VmSize":
			s.VmSizeKiB = kibField(val)
		case "VmSwap":
			s.SwapKiB = kibField(val)
		case "Threads":
			if n, err := strconv.ParseInt(val, 10, 64); err == nil {
				s.Threads = n
			}
		case "Uid":
			if parts := strings.Fields(val); len(parts) > 0 {
				if n, err := strconv.Atoi(parts[0]); err == nil {
					s.UID = n
				}
			}
		}
	}
}

func (s *Snapshot) readStatm(base string) {
	b, err := os.ReadFile(base + "/statm")
	if err != nil {
		return
	}
	f := strings.Fields(string(b))
	if len(f) < 2 {
		return
	}
	pages, err := strconv.ParseInt(f[1], 10, 64)
	if err != nil {
		return
	}
	s.RSSPages = pages
	s.RSSKiB = pages * PageSize() / 1024
}

func (s *Snapshot) readCmdline(base string) {
	b, err := os.ReadFile(base + "/cmdline")
	if err != nil || len(b) == 0 {
		s.Cmdline = "[" + s.Name + "]"
		s.noCmdline = true
		return
	}
	s.noCmdline = false
	parts := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
	cleaned := make([]string, 0, len(parts))
	for _, p := range parts {
		cleaned = append(cleaned, sanitize(p))
	}
	s.Cmdline = strings.Join(cleaned, " ")
	if len(cleaned) > 0 {
		s.Argv0 = cleaned[0]
	}
}

const commLimit = 15

func (s Snapshot) DisplayName() string {
	if len([]rune(s.Name)) < commLimit || s.Argv0 == "" {
		return s.Name
	}

	base := s.Argv0
	if i := strings.IndexByte(base, ' '); i > 0 {
		base = base[:i]
	}
	if i := strings.LastIndexByte(base, '/'); i >= 0 && i < len(base)-1 {
		base = base[i+1:]
	}
	base = strings.TrimSpace(base)
	if base == "" || base == s.Name {
		return s.Name
	}
	return base
}

func (s *Snapshot) readIO(base string) {
	b, err := os.ReadFile(base + "/io")
	if err != nil {
		s.IOAccessible = false
		return
	}
	s.IOAccessible = true
	for _, line := range strings.Split(string(b), "\n") {
		idx := strings.IndexByte(line, ':')
		if idx <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := atouField(strings.TrimSpace(line[idx+1:]))
		switch key {
		case "rchar":
			s.RChar = val
		case "wchar":
			s.WChar = val
		case "syscr":
			s.SyscallRead = val
		case "syscw":
			s.SyscallWrite = val
		case "read_bytes":
			s.ReadBytes = val
		case "write_bytes":
			s.WriteBytes = val
		}
	}
}

func (s *Snapshot) readWchan(base string) {
	b, err := os.ReadFile(base + "/wchan")
	if err != nil {
		return
	}
	v := strings.TrimSpace(string(b))
	if v == "0" {
		return
	}
	s.Wchan = v
}

func (s *Snapshot) readFDs(base string) {
	entries, err := os.ReadDir(base + "/fd")
	if err != nil {
		s.FDCount = -1
		s.FDAccessible = false
		return
	}
	s.FDCount = len(entries)
	s.FDAccessible = true
}

func (s *Snapshot) readLimits(base string) {
	f, err := os.Open(base + "/limits")
	if err != nil {
		return
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "Max open files") {
			continue
		}
		fields := strings.Fields(line)

		if len(fields) >= 4 {
			if n, err := strconv.ParseUint(fields[3], 10, 64); err == nil {
				s.FDLimit = n
			}
		}
		return
	}
}

func parentMap() map[int]int {
	pids, err := ListPIDs()
	if err != nil {
		return nil
	}
	out := make(map[int]int, len(pids))
	for _, pid := range pids {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			continue
		}
		var s Snapshot
		if applyStat(&s, string(data)) != nil {
			continue
		}
		out[pid] = s.PPID
	}
	return out
}

func Children(ppid int) []int {
	parents := parentMap()
	var kids []int
	for pid, par := range parents {
		if par == ppid {
			kids = append(kids, pid)
		}
	}
	sort.Ints(kids)
	return kids
}

func Descendants(pid int) []int {
	parents := parentMap()
	kids := make(map[int][]int, len(parents))
	for p, par := range parents {
		kids[par] = append(kids[par], p)
	}
	for _, list := range kids {
		sort.Ints(list)
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

func Exists(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	if err == nil {
		return true
	}
	return errors.Is(err, syscall.EPERM)
}

func ReadNice(pid int) (int, error) {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		if isGone(err) {
			return 0, fmt.Errorf("%w: %v", ErrVanished, err)
		}
		return 0, fmt.Errorf("stat: %w", err)
	}
	str := string(b)
	closing := strings.LastIndexByte(str, ')')
	if closing < 0 || closing+2 > len(str) {
		return 0, fmt.Errorf("stat: unexpected format")
	}
	f := strings.Fields(str[closing+2:])
	if len(f) < 17 {
		return 0, fmt.Errorf("stat: too few fields (%d)", len(f))
	}
	return atoiField(f[16]), nil
}

func CoreDumpEnabled(pid int) bool {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/limits")
	if err != nil {
		return false
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "Max core file size") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 5 {
			return false
		}
		if strings.EqualFold(fields[4], "unlimited") {
			return true
		}
		n, err := strconv.ParseUint(fields[4], 10, 64)
		return err == nil && n > 0
	}
	return false
}

func StateName(state string) string {
	switch state {
	case StateRunning:
		return "running"
	case StateSleeping:
		return "sleeping"
	case StateDiskSleep:
		return "disk sleep"
	case StateZombie:
		return "zombie"
	case StateStopped:
		return "stopped"
	case StateTraced:
		return "traced"
	case StateIdle:
		return "idle"
	case StateDead, StateWakekill, StateParked:
		return "service"
	default:
		return "unknown"
	}
}

var (
	userMu    sync.Mutex
	userCache = make(map[int]string)
)

func Username(uid int) string {
	userMu.Lock()
	defer userMu.Unlock()
	if n, ok := userCache[uid]; ok {
		return n
	}
	name := "#" + strconv.Itoa(uid)
	if u, err := user.LookupId(strconv.Itoa(uid)); err == nil && u.Username != "" {
		name = u.Username
	}
	userCache[uid] = name
	return name
}

func isGone(err error) bool {
	return errors.Is(err, os.ErrNotExist) ||
		errors.Is(err, syscall.ESRCH) ||
		errors.Is(err, syscall.ENOENT)
}

func atoiField(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func atouField(s string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimSpace(s), 10, 64)
	return n
}

func kibField(s string) int64 {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0
	}
	n, err := strconv.ParseInt(f[0], 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func sanitize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\n', r == '\r', r == '\t':
			b.WriteRune(' ')
		case r < 0x20 || r == 0x7f:
			b.WriteRune('?')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}
