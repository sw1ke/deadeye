package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"deadeye/internal/actions"
	"deadeye/internal/anomaly"
	"deadeye/internal/config"
	"deadeye/internal/daemon"
	"deadeye/internal/human"
	"deadeye/internal/monitor"
	"deadeye/internal/proc"
	"deadeye/internal/system"
	"deadeye/internal/ui"
)

const (
	appName = "deadeye"
	version = "1.0.0"
)

func main() { os.Exit(realMain()) }

func realMain() (code int) {
	defer func() {
		restoreTerminal()
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "%s: crash: %v\n%s\n", appName, r, debug.Stack())
			code = 2
		}
	}()

	if err := run(os.Args[1:]); err != nil {
		restoreTerminal()
		fmt.Fprintf(os.Stderr, "%s: %v\n", appName, err)
		return 1
	}
	return 0
}

func restoreTerminal() {
	if !isTerminal(os.Stdout) {
		return
	}

	_, _ = os.Stdout.WriteString("\x1b[?1049l\x1b[?1048l\x1b[?25h" +
		"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1006l\x1b[0m")
}

func isTerminal(f *os.File) bool {
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}

type cliFlags struct {
	daemon      bool
	foreground  bool
	once        bool
	config      string
	interval    time.Duration
	history     int
	workers     int
	log         string
	pidFile     string
	uid         int
	top         int
	initConfig  string
	printConfig bool
	version     bool
	flat        bool

	systemHelper      bool
	systemHelperStart bool
	helperUID         int
	helperSocket      string

	set map[string]bool
}

func parseArgs(args []string) (*cliFlags, error) {
	fs := flag.NewFlagSet(appName, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var f cliFlags
	fs.BoolVar(&f.daemon, "daemon", false, "background mode: no TUI, detach into the background and apply config rules")
	fs.BoolVar(&f.foreground, "foreground", false, "like --daemon but stay in the foreground; log goes to stdout")
	fs.BoolVar(&f.once, "once", false, "take one system snapshot, print it to stdout and exit")
	fs.StringVar(&f.config, "config", "", "path to config (TOML or JSON)")
	fs.DurationVar(&f.interval, "interval", 0, "metric collection interval: 200ms, 1s, 5s (overrides general.interval_ms)")
	fs.IntVar(&f.history, "history", 0, "history depth for trends and charts, in snapshots")
	fs.IntVar(&f.workers, "workers", 0, "how many goroutines read /proc in parallel")
	fs.StringVar(&f.log, "log", "", "action log file")
	fs.StringVar(&f.pidFile, "pid-file", "", "file for the background process PID")
	fs.IntVar(&f.uid, "uid", -1, "monitor only processes of this UID (-1 = all)")
	fs.IntVar(&f.top, "top", 20, "how many processes to print in --once mode")
	fs.StringVar(&f.initConfig, "init-config", "", "create a config file with a detailed example and exit")
	fs.BoolVar(&f.printConfig, "print-config", false, "print the effective config as TOML and exit")
	fs.BoolVar(&f.version, "version", false, "show version and exit")
	fs.BoolVar(&f.flat, "flat", false, "flat process list instead of a tree (overrides ui.tree_view)")
	fs.BoolVar(&f.systemHelper, "system-helper", false, "privileged helper for the System tab (internal)")
	fs.BoolVar(&f.systemHelperStart, "system-helper-start", false, "start the helper and exit (internal, under pkexec)")
	fs.IntVar(&f.helperUID, "system-helper-uid", -1, "uid of the client allowed to connect (internal)")
	fs.StringVar(&f.helperSocket, "system-helper-socket", "", "path to the helper socket (internal)")

	fs.Usage = func() { printUsage(fs) }

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return &f, nil
		}
		return &f, err
	}

	f.set = make(map[string]bool)
	fs.Visit(func(fl *flag.Flag) { f.set[fl.Name] = true })
	return &f, nil
}

func run(args []string) error {
	f, err := parseArgs(args)
	if err != nil {
		return err
	}

	if flagHelpRequested(args) {
		return nil
	}

	if f.systemHelperStart {

		if f.helperUID <= 0 || f.helperSocket == "" {
			return fmt.Errorf("--system-helper-start requires --system-helper-uid and --system-helper-socket")
		}
		return system.RunHelperStart(f.helperUID, f.helperSocket)
	}

	if f.systemHelper {

		if f.helperUID <= 0 || f.helperSocket == "" {
			return fmt.Errorf("--system-helper requires --system-helper-uid and --system-helper-socket")
		}
		return system.RunHelper(f.helperUID, f.helperSocket)
	}

	if f.version {
		fmt.Printf("%s %s (Go %s, %s/%s)\n", appName, version, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		fmt.Printf("CLK_TCK=%d, page size=%d B, /proc available=%v\n",
			proc.ClkTck(), proc.PageSize(), procAccessOK())
		fmt.Printf("default heuristics: %s\n", anomaly.Summary(anomaly.DefaultRules()))
		return nil
	}

	if f.initConfig != "" {
		if err := config.WriteExample(f.initConfig); err != nil {
			return err
		}
		fmt.Printf("example configuration created: %s\n", f.initConfig)
		fmt.Printf("check: %s --config %s --foreground\n", appName, f.initConfig)
		return nil
	}

	cfg, cfgPath, err := loadConfig(f.config)
	if err != nil {
		return err
	}

	if strings.TrimSpace(cfg.Daemon.LogFile) == "" {
		cfg.Daemon.LogFile = daemon.DefaultLogPath()
	}

	if f.printConfig {
		fmt.Fprintf(os.Stderr, "# effective Deadeye configuration (%s), TOML format\n", sourceLabel(cfgPath))
		return cfg.EncodeTOML(os.Stdout)
	}

	if f.set["interval"] {
		if f.interval < 100*time.Millisecond {
			return errors.New("--interval below 100 ms: polling /proc itself will become a noticeable load")
		}
		cfg.General.IntervalMs = int(f.interval.Milliseconds())
	}
	if f.set["history"] {
		cfg.General.History = f.history
	}
	if f.set["workers"] {
		cfg.General.Workers = f.workers
	}
	if f.set["uid"] {
		cfg.General.UIDFilter = f.uid
	}
	if f.set["log"] {
		cfg.Daemon.LogFile = f.log
	}
	if f.set["pid-file"] {
		cfg.Daemon.PIDFile = f.pidFile
	}
	if f.set["flat"] {
		cfg.UI.TreeView = !f.flat
	}

	if f.daemon && f.foreground {
		return errors.New("--daemon and --foreground are mutually exclusive: pick one mode")
	}
	if f.once && (f.daemon || f.foreground) {
		return errors.New("--once is incompatible with --daemon/--foreground")
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration (%s): %w", sourceLabel(cfgPath), err)
	}

	headless := f.daemon || f.foreground

	if f.daemon && !daemon.IsChild() {
		logFile := cfg.Daemon.LogFile
		if dir := filepath.Dir(logFile); dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("failed to create the log directory %s: %w", dir, err)
			}
		}

		if cfg.Daemon.PIDFile != "" {
			oldPID, err := daemon.ReadPIDFile(cfg.Daemon.PIDFile)
			if err == nil && oldPID > 0 && oldPID != os.Getpid() {
				if proc.Exists(oldPID) {
					name := "?"
					if s, rerr := proc.Read(oldPID); rerr == nil {
						name = s.Name
					}
					return fmt.Errorf("daemon already running: PID %d (%s) from %s — stop it (kill %d) or remove the pid file",
						oldPID, name, cfg.Daemon.PIDFile, oldPID)
				}
				fmt.Printf("pid file %s points to a nonexistent process %d — starting anyway\n",
					cfg.Daemon.PIDFile, oldPID)
			}
		}

		childPID, err := daemon.Daemonize(logFile)
		if err != nil {
			return fmt.Errorf("failed to detach into the background: %w", err)
		}
		fmt.Printf("Deadeye %s started in the background\n", version)
		fmt.Printf("  process PID : %d\n", childPID)
		fmt.Printf("  log         : %s\n", logFile)
		fmt.Printf("  config      : %s\n", sourceLabel(cfgPath))
		fmt.Printf("  parameters  : %s\n", cfg.Summary())
		if cfg.Daemon.PIDFile != "" {
			fmt.Printf("  pid file    : %s\n", cfg.Daemon.PIDFile)
		}
		fmt.Printf("  stop        : kill %d  (SIGTERM — graceful shutdown)\n", childPID)
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()

	mon := monitor.New(cfg.MonitorOptions())
	det := anomaly.NewDetector(cfg.DetectorRules(), cfg.MonitorOptions().Interval)
	journal := actions.NewLog(maxInt(cfg.UI.MaxLogLines, 64))
	defer func() {
		if err := journal.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "%s: failed to close the log: %v\n", appName, err)
		}
	}()
	journal.SetMinLevel(cfg.LogLevel())

	if err := attachJournal(cfg, journal, headless, f.foreground, f.set["log"]); err != nil {
		return err
	}

	act := actions.NewManager(cfg.ActionsConfigValue(), journal)

	switch {
	case f.once:
		return printOnce(ctx, mon, det, f.top)
	case headless:
		return runHeadless(ctx, cfg, mon, det, act, journal)
	default:
		return runTUI(ctx, cfg, mon, det, act, journal)
	}
}

func flagHelpRequested(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" {
			return true
		}
	}
	return false
}

func loadConfig(path string) (*config.Config, string, error) {
	if strings.TrimSpace(path) != "" {
		cfg, err := config.Load(path)
		if err != nil {
			return nil, path, err
		}
		return cfg, path, nil
	}
	found := config.FindDefault()
	if found == "" {
		return config.Default(), "", nil
	}
	cfg, err := config.Load(found)
	if err != nil {
		return nil, found, err
	}
	return cfg, found, nil
}

func sourceLabel(path string) string {
	if strings.TrimSpace(path) == "" {
		return "defaults; no config files found: " + strings.Join(config.DefaultPaths(), ", ")
	}
	return path
}

func attachJournal(cfg *config.Config, journal *actions.Log, headless, foreground, logExplicit bool) error {
	switch {
	case foreground && !logExplicit:

		if err := journal.AttachFile("/dev/stdout", 0); err != nil {
			return fmt.Errorf("failed to direct the log to stdout: %w", err)
		}
		return nil

	case headless || logExplicit:
		path := cfg.Daemon.LogFile
		if strings.TrimSpace(path) == "" {
			return nil
		}
		if dir := filepath.Dir(path); dir != "" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return fmt.Errorf("failed to create the log directory %s: %w", dir, err)
			}
		}
		if err := journal.AttachFile(path, cfg.Daemon.MaxLogMB*1024*1024); err != nil {
			return err
		}
	}
	return nil
}

func runTUI(ctx context.Context, cfg *config.Config, mon *monitor.Monitor, det *anomaly.Detector,
	act *actions.Manager, journal *actions.Log) error {

	if !isTerminal(os.Stdout) {
		return errors.New("stdout is not a terminal: the TUI is unavailable. " +
			"Use --once for a one-off snapshot or --foreground/--daemon for background mode")
	}

	tuiCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go mon.Run(tuiCtx)

	journal.Infof("system", 0, "", "starting the TUI: %s", cfg.Summary())
	return ui.Run(cfg, mon, det, act, journal, version)
}

func runHeadless(ctx context.Context, cfg *config.Config, mon *monitor.Monitor, det *anomaly.Detector,
	act *actions.Manager, journal *actions.Log) error {

	if cfg.Daemon.PIDFile != "" {
		if err := daemon.WritePIDFile(cfg.Daemon.PIDFile, os.Getpid()); err != nil {
			journal.Errorf("system", 0, "", "failed to write pid file %s: %v", cfg.Daemon.PIDFile, err)
		} else {
			defer daemon.RemovePIDFile(cfg.Daemon.PIDFile)
		}
	}

	go mon.Run(ctx)

	engine := daemon.NewEngine(cfg, mon, det, act, journal)
	err := engine.Run(ctx)
	engine.Wait()
	return err
}

type ansi struct{ on bool }

func (a ansi) wrap(code, s string) string {
	if !a.on || s == "" {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (a ansi) bold(s string) string   { return a.wrap("1", s) }
func (a ansi) dim(s string) string    { return a.wrap("2", s) }
func (a ansi) red(s string) string    { return a.wrap("1;31", s) }
func (a ansi) yellow(s string) string { return a.wrap("33", s) }
func (a ansi) green(s string) string  { return a.wrap("32", s) }
func (a ansi) cyan(s string) string   { return a.wrap("36", s) }

func printOnce(ctx context.Context, mon *monitor.Monitor, det *anomaly.Detector, top int) error {
	if top <= 0 {
		top = 20
	}
	if !procAccessOK() {
		return errors.New("/proc is unavailable: there is nowhere else to collect metrics")
	}

	a := ansi{on: isTerminal(os.Stdout)}

	waitCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	updates, unsub := mon.Subscribe()
	defer unsub()

	go mon.Run(waitCtx)

	for mon.Samples() < 2 {
		select {
		case <-updates:
		case <-waitCtx.Done():
			if errors.Is(waitCtx.Err(), context.DeadlineExceeded) {
				return errors.New("failed to obtain two /proc snapshots within 30 s")
			}
			return waitCtx.Err()
		}
	}

	procs, sys := mon.Snapshot()
	now := time.Now()
	anoms := det.Update(procs, sys, now)

	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "localhost"
	}

	out := os.Stdout
	p := func(format string, args ...any) { fmt.Fprintf(out, format+"\n", args...) }

	p("%s %s — one-off system snapshot", a.bold("Deadeye"), a.dim(version))
	p("%s", a.dim(strings.Repeat("─", 78)))
	p("host      : %s   uptime: %s   CLK_TCK: %d   page: %d B",
		host, human.Duration(sys.Uptime), proc.ClkTck(), proc.PageSize())
	p("CPU       : %s (%d cores, load %.2f %.2f %.2f = %.2f per core)",
		a.bold(human.Percent(sys.CPUPercent)), sys.NumCPU,
		sys.Load1, sys.Load5, sys.Load15, sys.LoadPerCore())
	p("memory    : %s of %s used (%s), %s available, cache %s, dirty %s",
		human.FromKiB(float64(sys.MemUsedKiB())), human.FromKiB(float64(sys.MemTotalKiB)),
		human.Percent(sys.MemPercent()), human.FromKiB(float64(sys.MemAvailableKiB)),
		human.FromKiB(float64(sys.CachedKiB)), human.FromKiB(float64(sys.DirtyKiB)))
	p("swap      : %s of %s (%s)",
		human.FromKiB(float64(sys.SwapUsedKiB())), human.FromKiB(float64(sys.SwapTotalKiB)),
		human.Percent(sys.SwapPercent()))
	p("processes : %d total, %d running, %d blocked on I/O; snapshots %d, interval %s",
		len(procs), sys.ProcsRunning, sys.ProcsBlocked, mon.Samples(), mon.Options().Interval)

	states := make(map[string]int, 8)
	for _, s := range procs {
		states[s.State]++
	}

	byCPU := make([]proc.Snapshot, len(procs))
	copy(byCPU, procs)
	sort.Slice(byCPU, func(i, j int) bool { return byCPU[i].CPUPercent > byCPU[j].CPUPercent })

	anomByPID := make(map[int][]anomaly.Anomaly, len(anoms))
	for _, an := range anoms {
		anomByPID[an.PID] = append(anomByPID[an.PID], an)
	}

	p("\n%s (R %d · D %d · S %d · Z %d · T %d)", a.bold("TOP BY CPU"),
		states[proc.StateRunning], states[proc.StateDiskSleep], states[proc.StateSleeping],
		states[proc.StateZombie], states[proc.StateStopped])
	p("%s", a.cyan(fmt.Sprintf("%7s %-10s %-20s %2s %4s %7s %9s %9s %9s %6s %10s",
		"PID", "USER", "NAME", "ST", "NI", "CPU%", "RSS", "RD/s", "WR/s", "FD", "AGE")))

	limit := minInt(top, len(byCPU))
	for i := 0; i < limit; i++ {
		s := byCPU[i]
		fd := "—"
		if s.FDCount >= 0 {
			fd = strconv.Itoa(s.FDCount)
		}
		line := fmt.Sprintf("%7d %-10s %-20s %2s %4d %6.1f%% %9s %9s %9s %6s %10s",
			s.PID, human.Truncate(s.User, 10), human.Truncate(s.Name, 20),
			s.State, s.Nice, s.CPUPercent, human.FromKiB(float64(s.RSSKiB)),
			human.Rate(s.ReadRate), human.Rate(s.WriteRate), fd, human.Duration(s.Age))

		marks := make([]string, 0, 2)
		for _, an := range anomByPID[s.PID] {
			marks = append(marks, an.Kind.Short())
		}
		switch {
		case len(marks) > 0:
			line = a.red(line + "  " + strings.Join(marks, "+"))
		case s.State == proc.StateZombie || s.State == proc.StateDiskSleep:
			line = a.yellow(line)
		}
		p("%s", line)
	}

	p("\n%s %d", a.bold("ANOMALIES:"), len(anoms))
	if len(anoms) == 0 {
		p("  %s", a.green("none"))
		p("  %s", a.dim("thresholds: "+anomaly.Summary(det.Rules())))
		return nil
	}

	sorted := make([]anomaly.Anomaly, len(anoms))
	copy(sorted, anoms)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Severity > sorted[j].Severity })
	for _, an := range sorted {
		p("  %s PID %d %s (owner %s, lasting %s)",
			a.red("["+an.Kind.Title()+"]"), an.PID, an.Name, an.User,
			human.Duration(now.Sub(an.Since)))
		p("      %s", an.Detail)
	}
	return nil
}

func procAccessOK() bool {
	_, err := os.Stat("/proc/self/stat")
	return err == nil
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

func printUsage(fs *flag.FlagSet) {
	w := fs.Output()
	fmt.Fprintf(w, `Deadeye %s — terminal process watchdog for Linux

USAGE
  deadeye [flags]

MODES
  (no flags)     TUI: Processes / Load / AI / Groups / Log
  --once         one snapshot to stdout, then exit
  --foreground   config rules without the TUI, log to stdout
  --daemon       same, but detached (setsid, log to file)

FLAGS
`, version)
	fs.PrintDefaults()
	fmt.Fprintf(w, `
HOTKEYS
  Tab / Shift+Tab   tabs; 1…8, 9, 0 — jump to a tab
  ↑/↓, j/k          move; PgUp/PgDn, Home/End, g/G — scroll
  Enter             expand branch / confirm
  ←/→               collapse / expand branch
  T                 tree ⇄ flat list
  e/E               expand / collapse all
  u                 my processes first ⇄ global sort
  s/S, d            sort column, direction
  f                 filter: all → anomalous → mine → active (R/D)
  L                 filter: log level / security level
  /, x              search, reset
  c                 full command line instead of name
  r                 snapshot now (scan on Security, recompute on Hung)
  a                 ask the local model about the selection
  F7/F8             renice +/−
  F9                Smart Kill: SIGTERM → wait → SIGABRT (dump) → SIGKILL
  y/Enter           confirm kill; c — dump, t — tree scope, n/Esc — cancel
  ?                 this help
  q, Ctrl+C         quit

AI TAB (4)
  Ollama explains the process from /proc numbers (state, CPU, memory, fds,
  anomalies). Runs only when you press a — no background requests.
  Enter — question, r — re-check the model, Esc — close input.
  Without Ollama everything else works; install: ollama serve && ollama pull qwen2.5:1.5b

SECURITY TAB (6)
  Local checks, no network. Launches from /tmp, /dev/shm etc., deleted or
  replaced executables, miners and reverse shells, LD_PRELOAD, autostart,
  listening ports (3333, 4444, …). Findings sorted !!! → ·.
  r — scan, L — level filter, m — local ⇄ +DeepSeek, e — hash check,
  Enter — jump to the process, a — ask the model.
  With DeepSeek on, e sends only the SHA-256 of a suspicious file (never the
  contents): cache 30 days, 20 requests/day, min level 3.
  Without root some /proc data is unreadable — the tab says so instead of
  pretending all is clean.

SYSTEM TAB (7)
  One pkexec password per session, then a local socket. Sleep / reboot /
  poweroff, restart services (NetworkManager, bluetooth, cups, sshd, docker),
  rfkill, ufw, pacman -Syu, paccache. Allowlist only, no shell metacharacters,
  socket 0600. Enter — run, y/n — confirm, C — clear, r — re-check root.

TERMINAL TAB (8)
  A shell inside the TUI (pseudo-terminal). Esc/Ctrl+Q — detach, the shell
  keeps running. vim/less unsupported: use a real terminal.

LAUNCH TAB (0)
  Quick-launch apps and Hyprland autostart (~/.config/hypr). Enter — toggle a
  line, a — add a command, r — re-read the files.

HUNG TAB (2)
  Verdict + evidence + what to do per row:
    D  stuck in I/O (wchan shown; SIGKILL may not help)
    R  burning CPU (detector verdict)
    Z  zombie — reap the parent
    T  stopped — SIGCONT
  Kernel threads are skipped. Enter — show in Processes, c — SIGCONT,
  a — ask the model, r — recompute, F7–F9 as usual.

GROUPS TAB (5)
  Browsers, messengers, games, builds, VPN, … — totals per group.
  Enter — contents, F9/y — kill group (SIGTERM → wait → SIGKILL, leaves
  first), x/X — nice ±5, n/Esc — cancel. Services, terminals, VPN, the
  program itself, init and kernel threads are never killed; the start time is
  checked before every kill.

PROCESS TREE
  Collapsed row shows subtree sums. Children by PID, roots by sort column;
  my processes first (u toggles). PID 1 is a regular row, its children count
  as roots. Search / filter switch to the flat list. Russian layout is
  understood: keys map by position (short-i=q, o=j, el=k, yeru=s, ve=d,
  a=f, ka=r, es=c). NO_COLOR=1 kills colors.

DATA
  /proc/stat, /proc/meminfo, /proc/loadavg, /proc/uptime
  /proc/[pid]/stat, status, io, cmdline, limits, fd/

EXAMPLES
  deadeye --interval 500ms
  deadeye --once --top 10
  deadeye --init-config ~/.config/deadeye.toml
  deadeye --config ~/.config/deadeye.toml --daemon
  deadeye --foreground --uid 1000 --log /tmp/deadeye.log
  tail -f ~/.local/state/deadeye/daemon.log
  kill "$(cat ~/.local/state/deadeye/daemon.pid)"

CONFIG
  TOML or JSON (.json). Standard locations:
`)
	for _, path := range config.DefaultPaths() {
		fmt.Fprintf(w, "    %s\n", path)
	}
	fmt.Fprintf(w, `
  [[rule]] — what to do on an anomaly: ignore, log, renice, kill (trigger cap
  and cooldown). See the example file.
`)
}
