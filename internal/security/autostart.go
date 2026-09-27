package security

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"deadeye/internal/human"
)

func runCommand(name string, args []string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return strings.TrimSpace(stdout.String()), fmt.Errorf("%s: %s", name, msg)
	}
	return strings.TrimSpace(stdout.String()), nil
}

type Autostart struct {
	Path     string
	Kind     string
	Command  string
	User     bool
	Packed   bool
	Checked  bool
	Owner    string
	Writable bool
	Mode     os.FileMode
}

func (s *Scanner) ScanAutostart() ([]Finding, []Autostart) {
	if !s.cfg.Enabled || !s.cfg.ScanAutostart {
		return nil, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, nil
	}

	type target struct {
		path, kind string
		user       bool
		exts       []string
		deep       bool
	}
	targets := []target{
		{filepath.Join(home, ".config/autostart"), "desktop", true, []string{".desktop"}, false},
		{filepath.Join(home, ".config/systemd/user"), "systemd user", true, []string{".service", ".timer"}, true},
		{filepath.Join(home, ".config/hypr"), "hypr", true, []string{".conf", ".lua", ".sh"}, true},
		{filepath.Join(home, ".config/fish"), "rc file", true, []string{".fish"}, true},
		{filepath.Join(home, ".bashrc"), "rc file", true, nil, false},
		{filepath.Join(home, ".profile"), "rc file", true, nil, false},
		{"/etc/systemd/system", "systemd system", false, []string{".service", ".timer"}, true},
		{"/etc/xdg/autostart", "desktop", false, []string{".desktop"}, false},
		{"/etc/cron.d", "cron", false, nil, false},
		{"/etc/cron.daily", "cron", false, nil, false},
	}

	var items []Autostart
	for _, t := range targets {
		root := s.resolve(t.path)
		st, err := os.Stat(root)
		if err != nil {
			continue
		}
		if !st.IsDir() {
			if a, ok := s.readAutostart(t.path, t.kind, t.user); ok {
				items = append(items, a)
			}
			continue
		}
		count := 0
		_ = filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if !t.deep && p != root {
					return filepath.SkipDir
				}
				if strings.Count(strings.TrimPrefix(p, root), string(os.PathSeparator)) > 2 {
					return filepath.SkipDir
				}
				return nil
			}
			if count >= 400 {
				return filepath.SkipDir
			}
			if len(t.exts) > 0 {
				ok := false
				for _, e := range t.exts {
					if strings.HasSuffix(d.Name(), e) {
						ok = true
						break
					}
				}
				if !ok {
					return nil
				}
			}
			count++

			orig := t.path + strings.TrimPrefix(p, root)
			if a, ok := s.readAutostart(orig, t.kind, t.user); ok {
				items = append(items, a)
			}
			return nil
		})
	}

	findings := make([]Finding, 0, 8)
	for _, a := range items {
		findings = append(findings, s.checkAutostart(a)...)
	}
	findings = collapseUnowned(findings)
	SortFindings(findings)
	return findings, items
}

func (s *Scanner) readAutostart(path, kind string, user bool) (Autostart, bool) {
	full := s.resolve(path)
	st, err := os.Stat(full)
	if err != nil || st.IsDir() {
		return Autostart{}, false
	}
	if st.Size() > 512*1024 {
		return Autostart{}, false
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return Autostart{}, false
	}
	a := Autostart{
		Path: path, Kind: kind, User: user, Mode: st.Mode(),
		Command: extractCommand(string(data), kind),
	}
	a.Writable = st.Mode().Perm()&0o002 != 0
	if s.cfg.CheckPackages && !user && s.runCmd != nil {
		out, err := s.runCmd("pacman", []string{"-Qo", full}, 5*time.Second)
		a.Checked = true
		if err != nil {
			a.Owner = "not owned by any package"
		} else {
			a.Packed = true
			a.Owner = packageName(out)
		}
	}
	return a, true
}

func (s *Scanner) checkAutostart(a Autostart) []Finding {
	var out []Finding

	if cmd := a.Command; cmd != "" {
		lower := strings.ToLower(cmd)
		if strings.Contains(lower, "curl") || strings.Contains(lower, "wget") {
			level := LevelMedium
			detail := "autostart entry downloads something from the network"
			if strings.Contains(lower, "| sh") || strings.Contains(lower, "|sh") ||
				strings.Contains(lower, "| bash") || strings.Contains(lower, "|bash") {
				level = LevelCritical
				detail = "autostart entry pipes what it downloaded straight into a shell"
			}
			out = append(out, Finding{
				Level: level, Kind: "network in autostart", Subject: a.Path, Path: a.Path,
				Detail: detail, Evidence: []string{human.TruncateMiddle(cmd, 200)},
				Action: "remove the line from " + a.Path + " if you did not add it",
			})
		}
		if strings.Contains(lower, "base64") && (strings.Contains(lower, "sh") || strings.Contains(lower, "bash")) {
			out = append(out, Finding{
				Level: LevelHigh, Kind: "decoding in autostart", Subject: a.Path, Path: a.Path,
				Detail:   "startup decodes base64 straight into a shell",
				Evidence: []string{human.TruncateMiddle(cmd, 200)},
				Action:   "inspect the file and remove the line if it is not yours",
			})
		}
		if s.suspiciousDir(strings.TrimSpace(cmd)) {
			out = append(out, Finding{
				Level: LevelHigh, Kind: "startup from a temp directory", Subject: a.Path,
				Path:     a.Path,
				Detail:   "startup runs a file from a writable directory",
				Evidence: []string{human.TruncateMiddle(cmd, 200)},
				Action:   "remove the line and find out who created the file",
			})
		}
	}

	if a.Checked && !a.Packed && !a.User {
		out = append(out, Finding{
			Level: LevelNote, Kind: "file not from a package", Subject: a.Path, Path: a.Path,
			Detail: "system autostart entry is not owned by any package",
			Evidence: []string{
				"pacman -Qo " + a.Path + " found no owner",
				"this is what systemctl enable and manual installs do — usually it is fine",
			},
			Action: "recall what you enabled; look closer only if the command points outside /usr",
		})
	}

	if cmd := strings.TrimSpace(a.Command); cmd != "" && !a.User {
		if exe := firstPathOf(cmd); exe != "" && !inSystemDirs(exe) {
			level := LevelMedium
			detail := "startup runs a file outside system directories"
			if s.suspiciousDir(exe) {
				level = LevelHigh
				detail = "startup runs a file from a writable directory"
			}
			out = append(out, Finding{
				Level: level, Kind: "command outside /usr", Subject: a.Path, Path: a.Path,
				Detail:   detail,
				Evidence: []string{"runs " + exe, "packaged programs live in /usr, /usr/lib or /opt"},
				Action:   "find out who created " + exe + " and why it is in autostart",
			})
		}
	}

	if a.Writable {
		out = append(out, Finding{
			Level: LevelHigh, Kind: "startup entry is world-writable", Subject: a.Path,
			Path:     a.Path,
			Detail:   "any user on the system can modify this file",
			Evidence: []string{fmt.Sprintf("mode %s", a.Mode.Perm())},
			Action:   "chmod o-w " + a.Path,
		})
	}
	return out
}

func collapseUnowned(in []Finding) []Finding {
	const keep = 5
	out := make([]Finding, 0, len(in))
	var skipped []string
	for _, f := range in {
		if f.Kind == "file not from a package" {
			if len(skipped) >= keep {
				skipped = append(skipped, f.Path)
				continue
			}
			skipped = append(skipped, f.Path)
		}
		out = append(out, f)
	}
	if len(skipped) > keep {
		out = append(out, Finding{
			Level: LevelNote, Kind: "files not from packages",
			Subject: strconv.Itoa(len(skipped)) + " files",
			Detail: fmt.Sprintf("another %d system autostart entries are not owned by packages",
				len(skipped)-keep),
			Evidence: append([]string{
				"this is normal on Arch: systemctl enable creates units outside packages",
			}, skipped[keep:]...),
			Action: "look only at those whose command points outside /usr",
		})
	}
	return out
}

func extractCommand(data, kind string) string {
	lines := strings.Split(data, "\n")
	switch kind {
	case "desktop":
		for _, ln := range lines {
			ln = strings.TrimSpace(ln)
			if strings.HasPrefix(ln, "Exec=") {
				return strings.TrimSpace(strings.TrimPrefix(ln, "Exec="))
			}
		}
	case "systemd user", "systemd system":
		var cmds []string
		for _, ln := range lines {
			ln = strings.TrimSpace(ln)
			for _, key := range []string{"ExecStart=", "ExecStartPre=", "ExecStartPost=", "ExecReload="} {
				if strings.HasPrefix(ln, key) {
					v := strings.TrimSpace(strings.TrimPrefix(ln, key))
					v = strings.TrimPrefix(v, "-")
					v = strings.TrimPrefix(v, "@")
					cmds = append(cmds, v)
				}
			}
		}
		return strings.Join(cmds, " | ")
	case "hypr":
		var cmds []string
		for _, ln := range lines {
			ln = strings.TrimSpace(ln)
			if ln == "" || strings.HasPrefix(ln, "#") {
				continue
			}
			if strings.HasPrefix(ln, "exec-once") || strings.HasPrefix(ln, "exec ") ||
				strings.HasPrefix(ln, "exec=") || strings.HasPrefix(ln, "exec-once=") {
				cmds = append(cmds, ln)
			}
		}
		return strings.Join(cmds, " | ")
	case "rc file":
		var cmds []string
		for _, ln := range lines {
			t := strings.TrimSpace(ln)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}

			l := strings.ToLower(t)
			if strings.Contains(l, "curl") || strings.Contains(l, "wget") ||
				strings.Contains(l, "base64") || strings.Contains(l, "/tmp/") ||
				strings.Contains(l, "/dev/shm") {
				cmds = append(cmds, t)
			}
		}
		return strings.Join(cmds, " | ")
	default:
		var cmds []string
		for _, ln := range lines {
			t := strings.TrimSpace(ln)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			fields := strings.Fields(t)

			if len(fields) < 6 {
				if strings.Contains(fields[0], "=") {
					continue
				}
				cmds = append(cmds, t)
				continue
			}
			cmds = append(cmds, strings.Join(fields[5:], " "))
		}
		return strings.Join(cmds, " | ")
	}
	return ""
}

func firstPathOf(cmd string) string {
	for _, f := range splitCommand(cmd) {
		if strings.HasPrefix(f, "/") {
			return f
		}
	}
	return ""
}

func splitCommand(cmd string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range cmd {
		switch {
		case r == '"':
			inQuote = !inQuote
		case (r == ' ' || r == '\t') && !inQuote:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

func inSystemDirs(path string) bool {
	for _, d := range []string{"/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/etc/"} {
		if strings.HasPrefix(path, d) {
			return true
		}
	}

	return path == "/usr" || path == "/bin" || path == "/sbin"
}

func packageName(out string) string {
	if i := strings.Index(out, "owned by"); i >= 0 {
		rest := strings.TrimSpace(out[i+len("owned by"):])
		rest = strings.TrimSuffix(rest, "which is")
		return strings.TrimSpace(strings.SplitN(rest, " ", 2)[0])
	}
	return ""
}
