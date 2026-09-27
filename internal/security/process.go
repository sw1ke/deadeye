package security

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"deadeye/internal/human"
	"deadeye/internal/proc"
)

type Config struct {
	Enabled bool `toml:"enabled" json:"enabled"`

	ScanAutostart bool `toml:"scan_autostart" json:"scan_autostart"`

	ScanNetwork bool `toml:"scan_network" json:"scan_network"`

	HashFiles bool `toml:"hash_files" json:"hash_files"`

	MaxHashBytes int64 `toml:"max_hash_bytes" json:"max_hash_bytes"`

	CheckPackages bool `toml:"check_packages" json:"check_packages"`

	SuspiciousDirs []string `toml:"suspicious_dirs" json:"suspicious_dirs"`

	MinerPorts []int `toml:"miner_ports" json:"miner_ports"`

	DeepSeek DeepSeekConfig `toml:"deepseek" json:"deepseek"`
}

func DefaultConfig() Config {
	return Config{
		Enabled:       true,
		ScanAutostart: true,
		ScanNetwork:   true,
		HashFiles:     true,
		MaxHashBytes:  32 << 20,
		CheckPackages: true,
		SuspiciousDirs: []string{
			"/tmp", "/var/tmp", "/dev/shm", "/run/user", "/mnt", "/media",
		},
		MinerPorts: []int{3333, 4444, 5555, 7777, 14444, 14433, 45700, 8080},
	}
}

func (c *Config) Validate() error {
	if c.MaxHashBytes < 0 {
		c.MaxHashBytes = 0
	}
	if c.MaxHashBytes > 1<<32 {
		return fmt.Errorf("security.max_hash_bytes = %d: hashing over 4 GiB is unreasonable",
			c.MaxHashBytes)
	}
	if len(c.SuspiciousDirs) == 0 {
		c.SuspiciousDirs = DefaultConfig().SuspiciousDirs
	}
	if len(c.MinerPorts) == 0 {
		c.MinerPorts = DefaultConfig().MinerPorts
	}
	return c.DeepSeek.Validate()
}

type Scanner struct {
	cfg      Config
	procRoot string
	fsRoot   string

	runCmd func(name string, args []string, timeout time.Duration) (string, error)
	now    func() time.Time
	cache  *HashCache
	client *DeepSeekClient
}

func NewScanner(cfg Config) *Scanner {
	cfg.Validate()
	return &Scanner{
		cfg:      cfg,
		procRoot: "/proc",
		fsRoot:   "/",
		runCmd:   runCommand,
		now:      time.Now,
		cache:    NewHashCache(defaultCachePath()),
		client:   NewDeepSeekClient(cfg.DeepSeek),
	}
}

func (s *Scanner) SetRoots(procRoot, fsRoot string) {
	s.procRoot = procRoot
	s.fsRoot = strings.TrimSuffix(fsRoot, "/") + "/"
}

func (s *Scanner) resolve(path string) string {
	if s.fsRoot == "/" || s.fsRoot == "" {
		return path
	}
	root := strings.TrimSuffix(s.fsRoot, "/")

	if path == root || strings.HasPrefix(path, root+"/") {
		return path
	}
	return filepath.Join(root, strings.TrimPrefix(path, "/"))
}

func (s *Scanner) procPath(parts ...string) string {
	return filepath.Join(append([]string{s.procRoot}, parts...)...)
}

func (s *Scanner) Findings(procs []proc.Snapshot) []Finding {
	if !s.cfg.Enabled {
		return nil
	}
	out := make([]Finding, 0, 8)
	for _, p := range procs {
		out = append(out, s.checkProcess(p)...)
	}
	SortFindings(out)
	return out
}

func (s *Scanner) checkProcess(p proc.Snapshot) []Finding {
	var out []Finding
	exe := s.exePath(p.PID)
	subject := fmt.Sprintf("PID %d (%s)", p.PID, p.DisplayName())

	switch {
	case exe == "":

		if p.UID != os.Getuid() && p.PID != 1 {
			break
		}
		out = append(out, Finding{
			Level: LevelLow, Kind: "no access to exe", Subject: subject, PID: p.PID,
			Detail: "the process executable could not be read",
			Evidence: []string{
				"the process belongs to the same user, but its exe is not readable",
				"processes that changed uid and some sandboxes behave this way",
			},
			Action: "check manually: sudo readlink /proc/" + strconv.Itoa(p.PID) + "/exe (you will see the file path)",
		})

	case strings.HasSuffix(exe, "(deleted)"):
		clean := strings.TrimSuffix(exe, " (deleted)")
		out = append(out, Finding{
			Level: LevelHigh, Kind: "deleted binary", Subject: subject, PID: p.PID,
			Path:   clean,
			Detail: "the executable was deleted from disk, but the process keeps running",
			Evidence: []string{
				"process " + strconv.Itoa(p.PID) + " executable → " + exe,
				"the file is deleted but the inode is alive: its contents remain only in memory",
				"packers and malware do this to make analysis harder",
				"the same happens on package upgrades: the old file was removed, the process was not restarted",
			},
			Action: "restart the process; if this is not a package upgrade — save a dump and kill it",
			AskAPI: false,
		})

	case s.suspiciousDir(exe):
		f := Finding{
			Level: LevelMedium, Kind: "launched from a temp directory", Subject: subject,
			PID: p.PID, Path: exe,
			Detail: "the executable was launched from " + filepath.Dir(exe),
			Evidence: []string{
				"process " + strconv.Itoa(p.PID) + " executable → " + exe,
				"the directory is writable by everyone or almost everyone",
				"normal software is not launched from here: it belongs in /usr/bin",
			},
			Action: "check where the file came from and kill the process if it is not yours",
			AskAPI: s.cfg.HashFiles,
		}
		if p.UID == 0 {
			f.Level = LevelCritical
			f.Detail = "a root process was launched from " + filepath.Dir(exe)
			f.Evidence = append(f.Evidence,
				"root rights + launch from a temp directory — the highest-risk combination")
		}
		if s.cfg.HashFiles {
			if h, size, err := s.hashFile(exe); err == nil {
				f.SHA256, f.Size = h, size
			} else {
				f.AskAPI = false
				f.Evidence = append(f.Evidence, "hash not obtained: "+err.Error())
			}
		}
		out = append(out, f)

	case p.UID != 0 && s.worldWritable(exe):
		out = append(out, Finding{
			Level: LevelMedium, Kind: "file writable by everyone", Subject: subject,
			PID: p.PID, Path: exe,
			Detail: "any user on the system can modify the executable",
			Evidence: []string{
				exe + " has the write bit for everyone",
				"by swapping the file, any local user can run their code as you",
			},
			Action: "chmod o-w " + exe + " and check the owner",
		})
	}

	out = append(out, s.checkCmdline(p, subject)...)
	out = append(out, s.checkEnviron(p, subject)...)
	return out
}

func (s *Scanner) exePath(pid int) string {
	p, err := os.Readlink(s.procPath(strconv.Itoa(pid), "exe"))
	if err != nil {
		return ""
	}
	return p
}

func (s *Scanner) suspiciousDir(path string) bool {
	for _, d := range s.cfg.SuspiciousDirs {
		if path == d || strings.HasPrefix(path, strings.TrimSuffix(d, "/")+"/") {
			return true
		}
	}

	if home, err := os.UserHomeDir(); err == nil && strings.HasPrefix(path, home+"/.") {
		rest := strings.TrimPrefix(path, home+"/")
		if parts := strings.Split(rest, "/"); len(parts) > 1 && strings.HasPrefix(parts[0], ".") {
			switch parts[0] {
			case ".local", ".config", ".cache":

			default:
				return true
			}
		}
	}
	return false
}

func (s *Scanner) worldWritable(path string) bool {
	st, err := os.Stat(s.resolve(path))
	if err != nil {
		return false
	}
	return st.Mode().Perm()&0o002 != 0
}

func (s *Scanner) checkCmdline(p proc.Snapshot, subject string) []Finding {
	cmd := p.Cmdline
	if cmd == "" {
		return nil
	}
	lower := strings.ToLower(cmd)

	pipeShell := (strings.Contains(lower, "curl") || strings.Contains(lower, "wget")) &&
		(strings.Contains(lower, "| sh") || strings.Contains(lower, "|sh") ||
			strings.Contains(lower, "| bash") || strings.Contains(lower, "|bash") ||
			strings.Contains(lower, "| sudo"))
	decodedShell := strings.Contains(lower, "base64") &&
		(strings.Contains(lower, "-d") || strings.Contains(lower, "--decode")) &&
		(strings.Contains(lower, "sh") || strings.Contains(lower, "bash") ||
			strings.Contains(lower, "python"))
	netcatShell := strings.Contains(lower, "nc ") &&
		(strings.Contains(lower, "-e ") || strings.Contains(lower, "-c "))
	stratum := strings.Contains(lower, "stratum+tcp://") ||
		strings.Contains(lower, "stratum+ssl://") ||
		strings.Contains(lower, "--donate-level") ||
		strings.Contains(lower, "xmrig")
	pythonSocket := strings.Contains(lower, "python") && strings.Contains(lower, "socket.socket") &&
		strings.Contains(lower, "subprocess")

	var kind, detail string
	var level Level
	switch {
	case stratum:
		kind, level = "signs of a miner", LevelCritical
		detail = "command line contains a pool protocol or miner flags"
	case pipeShell:
		kind, level = "code downloaded into a shell", LevelHigh
		detail = "content from the network is piped straight into sh/bash, bypassing the disk and any checks"
	case decodedShell:
		kind, level = "code decoded and executed", LevelHigh
		detail = "data is decoded from base64 and piped into a shell"
	case netcatShell:
		kind, level = "reverse shell", LevelCritical
		detail = "netcat with -e/-c gives a remote host a command shell"
	case pythonSocket:
		kind, level = "python reverse shell", LevelHigh
		detail = "connects to a remote host and runs subprocess"
	default:
		return nil
	}

	ev := []string{human.TruncateMiddle(cmd, 160)}
	for _, port := range s.cfg.MinerPorts {
		if strings.Contains(cmd, ":"+strconv.Itoa(port)) {
			ev = append(ev, fmt.Sprintf("port %d is a typical mining pool port", port))
			if level < LevelCritical {
				level = LevelCritical
			}
		}
	}
	return []Finding{{
		Level: level, Kind: kind, Subject: subject, PID: p.PID, Detail: detail,
		Evidence: ev,
		Action:   "do not let the process keep running: save its command line and kill it",
	}}
}

func (s *Scanner) checkEnviron(p proc.Snapshot, subject string) []Finding {
	data, err := os.ReadFile(s.procPath(strconv.Itoa(p.PID), "environ"))
	if err != nil {
		return nil
	}

	var preloads, audits []string
	for _, b := range bytes.Split(data, []byte{0}) {
		line := string(b)
		switch {
		case strings.HasPrefix(line, "LD_PRELOAD="):
			v := strings.TrimPrefix(line, "LD_PRELOAD=")
			if strings.TrimSpace(v) != "" {
				preloads = append(preloads, v)
			}
		case strings.HasPrefix(line, "LD_AUDIT="):
			v := strings.TrimPrefix(line, "LD_AUDIT=")
			if strings.TrimSpace(v) != "" {
				audits = append(audits, v)
			}
		}
	}
	if len(preloads) == 0 && len(audits) == 0 {
		return nil
	}

	out := make([]Finding, 0, 2)
	if len(preloads) > 0 {
		level, detail := LevelMedium, "a library was injected into the process via LD_PRELOAD"
		ev := make([]string, 0, len(preloads)+1)
		for _, v := range preloads {
			ev = append(ev, "LD_PRELOAD="+v)
			for _, lib := range strings.FieldsFunc(v, func(r rune) bool { return r == ':' }) {
				if s.suspiciousDir(lib) {
					level = LevelCritical
					detail = "LD_PRELOAD points to a library in a temp directory"
				}
			}
		}
		ev = append(ev, "some programs legitimately use LD_PRELOAD: steam, "+
			"game launchers, wrappers like gamescope")
		out = append(out, Finding{
			Level: level, Kind: "library injection", Subject: subject, PID: p.PID,
			Detail: detail, Evidence: ev,
			Action: "find out who started the process and why it needs library injection",
		})
	}
	if len(audits) > 0 {
		out = append(out, Finding{
			Level: LevelHigh, Kind: "LD_AUDIT", Subject: subject, PID: p.PID,
			Detail:   "the process runs with LD_AUDIT: the library sees every call",
			Evidence: append([]string{}, "LD_AUDIT="+strings.Join(audits, " ")),
			Action:   "check where it came from: LD_AUDIT is almost never used in normal operation",
		})
	}
	return out
}

func (s *Scanner) hashFile(path string) (string, int64, error) {
	full := s.resolve(path)
	st, err := os.Stat(full)
	if err != nil {
		return "", 0, err
	}
	if !st.Mode().IsRegular() {
		return "", 0, fmt.Errorf("not a regular file (%s)", st.Mode().Type())
	}
	if s.cfg.MaxHashBytes > 0 && st.Size() > s.cfg.MaxHashBytes {
		return "", st.Size(), fmt.Errorf("file %s exceeds the %s limit — hash skipped",
			human.Bytes(float64(st.Size())), human.Bytes(float64(s.cfg.MaxHashBytes)))
	}
	f, err := os.Open(full)
	if err != nil {
		return "", st.Size(), err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", st.Size(), err
	}
	return hex.EncodeToString(h.Sum(nil)), st.Size(), nil
}
