package launch

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

type Entry struct {
	File    string
	Line    int
	Command string
	Enabled bool
	Format  string
}

func ReadEntries(files ...string) []Entry {
	var out []Entry
	for _, path := range files {
		if path == "" {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64*1024), 64*1024)
		line := 0
		for sc.Scan() {
			line++
			text := sc.Text()
			trim := strings.TrimSpace(text)
			if trim == "" || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, "--") {

				if cmd, ok := disabledCommand(trim); ok {
					out = append(out, Entry{File: path, Line: line, Command: cmd,
						Enabled: false, Format: formatOf(path)})
				}
				continue
			}
			if cmd, ok := activeCommand(trim); ok {
				out = append(out, Entry{File: path, Line: line, Command: cmd,
					Enabled: true, Format: formatOf(path)})
			}
		}
		f.Close()
	}
	return out
}

func formatOf(path string) string {
	if strings.HasSuffix(path, ".lua") {
		return "lua"
	}
	return "hypr"
}

func activeCommand(trim string) (string, bool) {

	if strings.HasPrefix(trim, "hl.exec_cmd(") {
		if cmd, ok := luaString(trim); ok {
			return cmd, true
		}
	}

	for _, p := range []string{"exec-once = ", "exec-once=", "exec = ", "exec="} {
		if strings.HasPrefix(trim, p) {
			cmd := strings.TrimSpace(strings.TrimPrefix(trim, p))
			if cmd != "" {
				return cmd, true
			}
		}
	}
	return "", false
}

func disabledCommand(trim string) (string, bool) {
	rest := trim
	if strings.HasPrefix(trim, "--") {
		rest = strings.TrimSpace(strings.TrimPrefix(trim, "--"))
	} else if strings.HasPrefix(trim, "#") {
		rest = strings.TrimSpace(strings.TrimPrefix(trim, "#"))
	} else {
		return "", false
	}
	if cmd, ok := activeCommand(rest); ok {
		return cmd, true
	}

	if strings.HasPrefix(rest, "hl.exec_cmd(") {
		return luaString(rest)
	}
	return "", false
}

func luaString(trim string) (string, bool) {
	open := strings.Index(trim, "hl.exec_cmd(")
	if open < 0 {
		return "", false
	}
	rest := trim[open+len("hl.exec_cmd("):]
	if !strings.HasPrefix(rest, "\"") {
		return "", false
	}
	var b strings.Builder
	esc := false
	for i := 1; i < len(rest); i++ {
		c := rest[i]
		if esc {
			b.WriteByte(c)
			esc = false
			continue
		}
		if c == '\\' {
			esc = true
			continue
		}
		if c == '"' {
			return b.String(), true
		}
		b.WriteByte(c)
	}
	return "", false
}

func Toggle(path string, line int) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	f.Close()
	if line < 1 || line > len(lines) {
		return fmt.Errorf("line %d is outside the file", line)
	}
	idx := line - 1
	trim := strings.TrimSpace(lines[idx])
	switch {
	case strings.HasPrefix(trim, "--"):
		lines[idx] = strings.TrimSpace(strings.TrimPrefix(trim, "--"))
	case strings.HasPrefix(trim, "#"):
		lines[idx] = strings.TrimSpace(strings.TrimPrefix(trim, "#"))
	default:
		if formatOf(path) == "lua" {
			lines[idx] = "-- " + lines[idx]
		} else {
			lines[idx] = "# " + lines[idx]
		}
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}

func Add(path, command string) error {
	if formatOf(path) == "lua" {
		return addToLua(path, command)
	}
	return addToHypr(path, command)
}

func addToHypr(path, command string) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "exec-once = %s\n", command)
	return err
}

func addToLua(path, command string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	insertAt := -1
	for i, ln := range lines {
		trim := strings.TrimSpace(ln)
		if strings.HasPrefix(trim, "hl.on(") || strings.HasPrefix(trim, "end)") {
			insertAt = i
			if strings.HasPrefix(trim, "end)") {
				break
			}
		}
	}
	escaped := strings.ReplaceAll(command, "\\", "\\\\")
	escaped = strings.ReplaceAll(escaped, "\"", "\\\"")
	newLine := "    hl.exec_cmd(\"" + escaped + "\")"
	if insertAt >= 0 && strings.TrimSpace(lines[insertAt]) == "end)" {
		lines = append(lines[:insertAt], append([]string{newLine}, lines[insertAt:]...)...)
	} else {
		lines = append(lines, newLine)
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644)
}

func Launch(command string) error {
	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err == nil {
		cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, devnull, devnull
		defer devnull.Close()
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait()
	return nil
}

type App struct {
	Name string
	Exec string
}

func InstalledApps() []App {
	home, _ := os.UserHomeDir()
	dirs := []string{
		filepath.Join(home, ".local/share/applications"),
		"/usr/share/applications",
		filepath.Join(home, ".local/share/flatpak/exports/share/applications"),
		"/var/lib/flatpak/exports/share/applications",
	}
	seen := map[string]bool{}
	var out []App
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".desktop") {
				continue
			}
			app, ok := parseDesktop(filepath.Join(dir, e.Name()))
			if !ok || seen[app.Name] {
				continue
			}
			seen[app.Name] = true
			out = append(out, app)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name)
	})
	return out
}

func parseDesktop(path string) (App, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return App{}, false
	}
	var name, execCmd string
	inDesktop := false
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case line == "[Desktop Entry]":
			inDesktop = true
		case strings.HasPrefix(line, "["):
			inDesktop = false
		case !inDesktop:
			continue
		case strings.HasPrefix(line, "Name=") && name == "":
			name = strings.TrimSpace(strings.TrimPrefix(line, "Name="))
		case strings.HasPrefix(line, "Exec=") && execCmd == "":
			execCmd = strings.TrimSpace(strings.TrimPrefix(line, "Exec="))
		case line == "NoDisplay=true" || line == "Hidden=true" || line == "Terminal=true":
			return App{}, false
		}
	}
	if name == "" || execCmd == "" {
		return App{}, false
	}
	execCmd = cleanExec(execCmd)
	if execCmd == "" {
		return App{}, false
	}
	return App{Name: name, Exec: execCmd}, true
}

func cleanExec(execCmd string) string {
	var b strings.Builder
	for i := 0; i < len(execCmd); i++ {
		if execCmd[i] == '%' && i+1 < len(execCmd) {
			i++
			continue
		}
		b.WriteByte(execCmd[i])
	}
	return strings.TrimSpace(b.String())
}

func DefaultFiles() []string {
	home, _ := os.UserHomeDir()
	candidates := []string{
		filepath.Join(home, ".config/hypr/custom/execs.lua"),
		filepath.Join(home, ".config/hypr/hyprland.conf"),
	}
	var out []string
	for _, c := range candidates {
		if st, err := os.Stat(c); err == nil && st.Mode().IsRegular() {
			out = append(out, c)
		}
	}
	return out
}
