package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"deadeye/internal/actions"
	"deadeye/internal/ai"
	"deadeye/internal/anomaly"
	"deadeye/internal/human"
	"deadeye/internal/hung"
	"deadeye/internal/monitor"
	"deadeye/internal/proc"
	"deadeye/internal/security"
)

type Config struct {
	General General       `toml:"general" json:"general"`
	Anomaly AnomalyConfig `toml:"anomaly" json:"anomaly"`
	Actions ActionsConfig `toml:"actions" json:"actions"`
	Daemon  DaemonConfig  `toml:"daemon" json:"daemon"`
	UI      UIConfig      `toml:"ui" json:"ui"`

	AI ai.Config `toml:"ai" json:"ai"`

	Hung hung.Rules `toml:"hung" json:"hung"`

	Security security.Config `toml:"security" json:"security"`
	Rules    []Rule          `toml:"rule" json:"rules"`
}

type General struct {
	IntervalMs int `toml:"interval_ms" json:"interval_ms"`
	History    int `toml:"history" json:"history"`
	Workers    int `toml:"workers" json:"workers"`

	DeepEvery     int  `toml:"deep_every" json:"deep_every"`
	IncludeKernel bool `toml:"include_kernel_threads" json:"include_kernel_threads"`
	UIDFilter     int  `toml:"uid_filter" json:"uid_filter"`
}

type AnomalyConfig struct {
	HungCPUPercent       float64 `toml:"hung_cpu_percent" json:"hung_cpu_percent"`
	HungSeconds          float64 `toml:"hung_seconds" json:"hung_seconds"`
	HungMaxIOBytesPerSec float64 `toml:"hung_max_io_bytes_per_sec" json:"hung_max_io_bytes_per_sec"`

	LeakWindow            int     `toml:"leak_window" json:"leak_window"`
	LeakMinSlopeKiBPerSec float64 `toml:"leak_min_slope_kib_per_sec" json:"leak_min_slope_kib_per_sec"`
	LeakMaxDropRatio      float64 `toml:"leak_max_drop_ratio" json:"leak_max_drop_ratio"`
	LeakMinRSSKiB         float64 `toml:"leak_min_rss_kib" json:"leak_min_rss_kib"`
	LeakMinR2             float64 `toml:"leak_min_r2" json:"leak_min_r2"`

	FDWarnRatio     float64 `toml:"fd_warn_ratio" json:"fd_warn_ratio"`
	ZombieSeconds   float64 `toml:"zombie_seconds" json:"zombie_seconds"`
	IOStormMBPerSec float64 `toml:"io_storm_mb_per_sec" json:"io_storm_mb_per_sec"`
}

type ActionsConfig struct {
	ReniceStep        int  `toml:"renice_step" json:"renice_step"`
	GracefulTimeoutMs int  `toml:"graceful_timeout_ms" json:"graceful_timeout_ms"`
	CoreDump          bool `toml:"coredump" json:"coredump"`
	CoreWaitMs        int  `toml:"core_wait_ms" json:"core_wait_ms"`
	FinalWaitMs       int  `toml:"final_wait_ms" json:"final_wait_ms"`
}

type DaemonConfig struct {
	LogFile  string `toml:"log_file" json:"log_file"`
	LogLevel string `toml:"log_level" json:"log_level"`
	PIDFile  string `toml:"pid_file" json:"pid_file"`
	MaxLogMB int64  `toml:"max_log_mb" json:"max_log_mb"`

	AutoRenice       bool     `toml:"auto_renice" json:"auto_renice"`
	AutoReniceDelta  int      `toml:"auto_renice_delta" json:"auto_renice_delta"`
	AutoKillAfterSec int      `toml:"auto_kill_after_sec" json:"auto_kill_after_sec"`
	AutoKillKinds    []string `toml:"auto_kill_kinds" json:"auto_kill_kinds"`
	OwnProcessesOnly bool     `toml:"own_processes_only" json:"own_processes_only"`
}

type UIConfig struct {
	FPS          int    `toml:"fps" json:"fps"`
	SortColumn   string `toml:"sort_column" json:"sort_column"`
	SortDesc     bool   `toml:"sort_desc" json:"sort_desc"`
	ShowCmdline  bool   `toml:"show_cmdline" json:"show_cmdline"`
	MaxLogLines  int    `toml:"max_log_lines" json:"max_log_lines"`
	MouseSupport bool   `toml:"mouse_support" json:"mouse_support"`

	TreeView bool `toml:"tree_view" json:"tree_view"`

	UserFirst bool `toml:"user_first" json:"user_first"`

	SmoothSort bool `toml:"smooth_sort" json:"smooth_sort"`

	SortSettleMs int `toml:"sort_settle_ms" json:"sort_settle_ms"`

	// TransparentNames hides session wrappers from the process tree: these
	// processes are not shown, and their children are promoted to roots.
	// Without this the whole desktop nests inside "start-hyprland" or
	// "gnome-shell" and the tree degenerates into one branch.
	TransparentNames []string `toml:"transparent_names" json:"transparent_names"`
}

type Rule struct {
	Name         string `toml:"name" json:"name"`
	MatchName    string `toml:"match_name" json:"match_name"`
	MatchCmdline string `toml:"match_cmdline" json:"match_cmdline"`

	MatchUID  *int   `toml:"match_uid" json:"match_uid"`
	Anomaly   string `toml:"anomaly" json:"anomaly"`
	Action    string `toml:"action" json:"action"`
	NiceDelta int    `toml:"nice_delta" json:"nice_delta"`

	KillTree    bool  `toml:"kill_tree" json:"kill_tree"`
	MaxTimes    int   `toml:"max_times" json:"max_times"`
	CooldownSec int   `toml:"cooldown_sec" json:"cooldown_sec"`
	Enabled     *bool `toml:"enabled" json:"enabled"`

	reName *regexp.Regexp
	reCmd  *regexp.Regexp
	kind   anomaly.Kind
}

func (r *Rule) DisplayName() string {
	if strings.TrimSpace(r.Name) == "" {
		return "(unnamed)"
	}
	return r.Name
}

func (r *Rule) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

func (r *Rule) Compile() error {
	if strings.TrimSpace(r.MatchName) != "" {
		re, err := regexp.Compile(r.MatchName)
		if err != nil {
			return fmt.Errorf("rule %q: match_name %q: %w", r.DisplayName(), r.MatchName, err)
		}
		r.reName = re
	}
	if strings.TrimSpace(r.MatchCmdline) != "" {
		re, err := regexp.Compile(r.MatchCmdline)
		if err != nil {
			return fmt.Errorf("rule %q: match_cmdline %q: %w", r.DisplayName(), r.MatchCmdline, err)
		}
		r.reCmd = re
	}

	switch strings.ToLower(strings.TrimSpace(r.Action)) {
	case "renice", "kill", "log", "ignore":
	default:
		return fmt.Errorf("rule %q: unknown action %q (expected renice, kill, log or ignore)",
			r.DisplayName(), r.Action)
	}
	k, ok := anomaly.ParseKind(r.Anomaly)
	if !ok {
		return fmt.Errorf("rule %q: unknown anomaly kind %q", r.DisplayName(), r.Anomaly)
	}
	r.kind = k
	if r.MaxTimes < 0 {
		return fmt.Errorf("rule %q: max_times cannot be negative", r.DisplayName())
	}
	if r.CooldownSec < 0 {
		return fmt.Errorf("rule %q: cooldown_sec cannot be negative", r.DisplayName())
	}
	return nil
}

func (r *Rule) ActionName() string { return strings.ToLower(strings.TrimSpace(r.Action)) }

func (r *Rule) Matches(s proc.Snapshot, a anomaly.Anomaly) bool {
	if !r.IsEnabled() {
		return false
	}
	if r.kind != "" && r.kind != a.Kind {
		return false
	}
	if r.reName != nil && !r.reName.MatchString(s.Name) {
		return false
	}
	if r.reCmd != nil && !r.reCmd.MatchString(s.Cmdline) {
		return false
	}
	if r.MatchUID != nil && s.UID != *r.MatchUID {
		return false
	}
	return true
}

func (r *Rule) Cooldown() time.Duration {
	return time.Duration(r.CooldownSec) * time.Second
}

func Default() *Config {
	rules := anomaly.DefaultRules()
	act := actions.DefaultConfig()
	mon := monitor.DefaultOptions()
	return &Config{
		AI:       ai.DefaultConfig(),
		Hung:     hung.DefaultRules(),
		Security: security.DefaultConfig(),
		General: General{
			IntervalMs:    int(mon.Interval / time.Millisecond),
			History:       mon.History,
			Workers:       mon.Workers,
			DeepEvery:     mon.DeepEvery,
			IncludeKernel: false,
			UIDFilter:     -1,
		},
		Anomaly: AnomalyConfig{
			HungCPUPercent:        rules.HungCPUPercent,
			HungSeconds:           rules.HungSeconds,
			HungMaxIOBytesPerSec:  rules.HungMaxIOBytesPerSec,
			LeakWindow:            rules.LeakWindow,
			LeakMinSlopeKiBPerSec: rules.LeakMinSlopeKiBPerSec,
			LeakMaxDropRatio:      rules.LeakMaxDropRatio,
			LeakMinRSSKiB:         rules.LeakMinRSSKiB,
			LeakMinR2:             rules.LeakMinR2,
			FDWarnRatio:           rules.FDWarnRatio,
			ZombieSeconds:         rules.ZombieSeconds,
			IOStormMBPerSec:       rules.IOStormMBPerSec,
		},
		Actions: ActionsConfig{
			ReniceStep:        act.ReniceStep,
			GracefulTimeoutMs: int(act.GracefulTimeout / time.Millisecond),
			CoreDump:          act.CoreDump,
			CoreWaitMs:        int(act.CoreWait / time.Millisecond),
			FinalWaitMs:       int(act.FinalWait / time.Millisecond),
		},
		Daemon: DaemonConfig{
			LogFile:          "",
			LogLevel:         "info",
			PIDFile:          "",
			MaxLogMB:         10,
			AutoRenice:       false,
			AutoReniceDelta:  10,
			AutoKillAfterSec: 0,
			AutoKillKinds:    []string{},
			OwnProcessesOnly: true,
		},
		UI: UIConfig{
			FPS:          60,
			SortColumn:   "total",
			SortDesc:     true,
			ShowCmdline:  false,
			MaxLogLines:  200,
			MouseSupport: true,
			TreeView:     true,
			UserFirst:    true,
			SmoothSort:   true,
			SortSettleMs: 2000,
			TransparentNames: []string{
				"hyprland", "start-hyprland",
			},
		},
	}
}

func Load(path string) (*Config, error) {
	cfg := Default()
	if strings.TrimSpace(path) == "" {
		return cfg, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read config %s: %w", path, err)
	}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		if err := json.Unmarshal(b, cfg); err != nil {
			return nil, fmt.Errorf("config %s: JSON error: %w", path, err)
		}
	default:
		if _, err := toml.Decode(string(b), cfg); err != nil {
			return nil, fmt.Errorf("config %s: TOML error: %w", path, err)
		}
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

func DefaultPaths() []string {
	paths := []string{
		"deadeye.toml",
		"deadeye.json",
	}
	cfgHome := os.Getenv("XDG_CONFIG_HOME")
	if cfgHome == "" {
		if home, err := os.UserHomeDir(); err == nil {
			cfgHome = filepath.Join(home, ".config")
		}
	}
	if cfgHome != "" {
		paths = append(paths,
			filepath.Join(cfgHome, "deadeye", "config.toml"),
			filepath.Join(cfgHome, "deadeye.toml"),
		)
	}
	paths = append(paths,
		"/etc/deadeye/config.toml", "/etc/deadeye.toml",
	)
	return paths
}

func FindDefault() string {
	for _, p := range DefaultPaths() {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func (c *Config) Validate() error {
	if c.General.DeepEvery < 1 {
		c.General.DeepEvery = 1
	}
	if err := c.Security.Validate(); err != nil {
		return err
	}
	if err := c.Security.DeepSeek.Validate(); err != nil {
		return err
	}
	if c.General.DeepEvery > 1000 {
		return fmt.Errorf("general.deep_every = %d: a full sweep rarer than once per 1000 snapshots makes no sense",
			c.General.DeepEvery)
	}
	if c.General.IntervalMs < 100 {
		return fmt.Errorf("general.interval_ms = %d: polling /proc faster than every 100 ms is pointless", c.General.IntervalMs)
	}
	if c.General.IntervalMs > 60000 {
		return fmt.Errorf("general.interval_ms = %d: more than 60 s is not supported", c.General.IntervalMs)
	}
	if c.General.History < 8 || c.General.History > 8192 {
		return fmt.Errorf("general.history = %d: expected between 8 and 8192", c.General.History)
	}
	if c.General.Workers < 1 || c.General.Workers > 128 {
		return fmt.Errorf("general.workers = %d: expected between 1 and 128", c.General.Workers)
	}
	if c.UI.FPS < 1 || c.UI.FPS > 240 {
		return fmt.Errorf("ui.fps = %d: expected between 1 and 240", c.UI.FPS)
	}
	if c.UI.MaxLogLines < 10 {
		c.UI.MaxLogLines = 10
	}
	if c.UI.SortSettleMs < 0 {
		c.UI.SortSettleMs = 0
	}
	if c.UI.SortSettleMs > 60000 {
		return fmt.Errorf("ui.sort_settle_ms = %d: keeping the order frozen for more than 60 s makes no sense", c.UI.SortSettleMs)
	}
	if lvl := strings.ToLower(c.Daemon.LogLevel); lvl != "info" && lvl != "warn" && lvl != "error" {
		return fmt.Errorf("daemon.log_level = %q: expected info, warn or error", c.Daemon.LogLevel)
	}
	if c.Daemon.MaxLogMB < 0 {
		c.Daemon.MaxLogMB = 0
	}
	if c.Daemon.AutoKillAfterSec < 0 {
		return fmt.Errorf("daemon.auto_kill_after_sec cannot be negative")
	}
	if !c.isValidSortColumn() {
		return fmt.Errorf("ui.sort_column = %q: expected total, pid, name, cpu, mem, delta, io, fd, age, user or none", c.UI.SortColumn)
	}

	for i := range c.Rules {
		if err := c.Rules[i].Compile(); err != nil {
			return err
		}
	}
	for _, k := range c.Daemon.AutoKillKinds {
		if _, ok := anomaly.ParseKind(k); !ok {
			return fmt.Errorf("daemon.auto_kill_kinds: unknown anomaly kind %q", k)
		}
	}
	return nil
}

func (c *Config) isValidSortColumn() bool {
	switch strings.ToLower(strings.TrimSpace(c.UI.SortColumn)) {
	case "total", "pid", "user", "name", "cpu", "mem", "delta", "io", "fd", "age", "nice", "state", "none", "":
		return true
	}
	return false
}

func (c *Config) MonitorOptions() monitor.Options {
	return monitor.Options{
		Interval:      time.Duration(c.General.IntervalMs) * time.Millisecond,
		DeepEvery:     c.General.DeepEvery,
		History:       c.General.History,
		Workers:       c.General.Workers,
		IncludeKernel: c.General.IncludeKernel,
		UIDFilter:     c.General.UIDFilter,
	}
}

func (c *Config) SecurityConfig() security.Config {
	cfg := c.Security
	_ = cfg.Validate()
	_ = cfg.DeepSeek.Validate()
	return cfg
}

func (c *Config) HungRules() hung.Rules {
	r := c.Hung
	r.Normalize()
	return r
}

func (c *Config) DetectorRules() anomaly.Rules {
	return anomaly.Rules{
		HungCPUPercent:        c.Anomaly.HungCPUPercent,
		HungSeconds:           c.Anomaly.HungSeconds,
		HungMaxIOBytesPerSec:  c.Anomaly.HungMaxIOBytesPerSec,
		LeakWindow:            c.Anomaly.LeakWindow,
		LeakMinSlopeKiBPerSec: c.Anomaly.LeakMinSlopeKiBPerSec,
		LeakMaxDropRatio:      c.Anomaly.LeakMaxDropRatio,
		LeakMinRSSKiB:         c.Anomaly.LeakMinRSSKiB,
		LeakMinR2:             c.Anomaly.LeakMinR2,
		FDWarnRatio:           c.Anomaly.FDWarnRatio,
		ZombieSeconds:         c.Anomaly.ZombieSeconds,
		IOStormMBPerSec:       c.Anomaly.IOStormMBPerSec,
	}
}

func (c *Config) ActionsConfigValue() actions.Config {
	return actions.Config{
		ReniceStep:      c.Actions.ReniceStep,
		GracefulTimeout: time.Duration(c.Actions.GracefulTimeoutMs) * time.Millisecond,
		CoreDump:        c.Actions.CoreDump,
		CoreWait:        time.Duration(c.Actions.CoreWaitMs) * time.Millisecond,
		FinalWait:       time.Duration(c.Actions.FinalWaitMs) * time.Millisecond,
	}
}

func (c *Config) KillKindsSet() map[anomaly.Kind]bool {
	out := make(map[anomaly.Kind]bool, len(c.Daemon.AutoKillKinds))
	for _, k := range c.Daemon.AutoKillKinds {
		if kind, ok := anomaly.ParseKind(k); ok && kind != "" {
			out[kind] = true
		}
	}
	return out
}

func (c *Config) LogLevel() actions.Level {
	switch strings.ToLower(c.Daemon.LogLevel) {
	case "error":
		return actions.LevelError
	case "warn":
		return actions.LevelWarn
	default:
		return actions.LevelInfo
	}
}

func (c *Config) EncodeTOML(w *os.File) error {
	enc := toml.NewEncoder(w)
	return enc.Encode(c)
}

func WriteExample(path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("no path specified for the example config")
	}
	if st, err := os.Stat(path); err == nil && st.Size() > 0 {
		return fmt.Errorf("file %s already exists and is not empty — refusing to overwrite", path)
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create directory %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, []byte(ExampleTOML), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func (c *Config) Summary() string {
	return fmt.Sprintf("interval %d ms, history %d, workers %d, rules %d, hung>%s CPU/%s, leak>%.0f KiB/s",
		c.General.IntervalMs, c.General.History, c.General.Workers, len(c.Rules),
		human.Percent(c.Anomaly.HungCPUPercent),
		human.Duration(time.Duration(c.Anomaly.HungSeconds*float64(time.Second))),
		c.Anomaly.LeakMinSlopeKiBPerSec)
}
