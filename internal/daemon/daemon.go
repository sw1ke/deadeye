package daemon

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const childEnv = "DAEMONEYE_DAEMONIZED"

func IsChild() bool { return os.Getenv(childEnv) == "1" }

func DefaultLogPath() string {
	if p := os.Getenv("XDG_STATE_HOME"); strings.TrimSpace(p) != "" {
		return filepath.Join(p, "deadeye", "daemon.log")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".local", "state", "deadeye", "daemon.log")
	}
	return filepath.Join(os.TempDir(), "deadeye.log")
}

func Daemonize(logPath string) (int, error) {
	exe, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("cannot determine executable path: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return 0, fmt.Errorf("create log directory %s: %w", filepath.Dir(logPath), err)
	}
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return 0, fmt.Errorf("open log %s: %w", logPath, err)
	}
	defer logFile.Close()

	devNull, err := os.OpenFile(os.DevNull, os.O_RDONLY, 0)
	if err != nil {
		return 0, fmt.Errorf("open %s: %w", os.DevNull, err)
	}
	defer devNull.Close()

	cwd, err := os.Getwd()
	if err != nil {
		cwd = "/"
	}

	env := append(os.Environ(), childEnv+"=1")

	cmd := exec.Command(exe, os.Args[1:]...)
	cmd.Dir = cwd
	cmd.Env = env
	cmd.Stdin = devNull
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("cannot start daemon: %w", err)
	}
	pid := cmd.Process.Pid

	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	select {
	case err := <-exited:
		if err != nil {
			return 0, fmt.Errorf("daemon exited right after start: %v (details in %s)", err, logPath)
		}
		return 0, fmt.Errorf("daemon exited right after start (details in %s)", logPath)
	case <-time.After(700 * time.Millisecond):

	}

	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Release()
	}
	return pid, nil
}

func WritePIDFile(path string, pid int) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create PID file directory %s: %w", dir, err)
		}
	}
	content := strconv.Itoa(pid) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write PID file %s: %w", path, err)
	}
	return nil
}

func RemovePIDFile(path string) {
	if strings.TrimSpace(path) == "" {
		return
	}
	if b, err := os.ReadFile(path); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid != os.Getpid() {
			return
		}
	}
	_ = os.Remove(path)
}

func ReadPIDFile(path string) (int, error) {
	if strings.TrimSpace(path) == "" {
		return 0, fmt.Errorf("PID file path not set")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0, fmt.Errorf("PID file %s contains garbage: %q", path, strings.TrimSpace(string(b)))
	}
	if pid <= 0 {
		return 0, fmt.Errorf("PID file %s contains invalid PID %d", path, pid)
	}
	return pid, nil
}
