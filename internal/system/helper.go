package system

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type request struct {
	Ping bool `json:"ping,omitempty"`
	Spec Spec `json:"spec"`
}

type response struct {
	Stdout string `json:"stdout,omitempty"`
	Stderr string `json:"stderr,omitempty"`
	Code   int    `json:"code"`
	Err    string `json:"err,omitempty"`
}

const (
	helperStartTimeout = 30 * time.Second
)

func RunHelperStart(uid int, socketPath string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("the helper must run as root (current euid=%d)", os.Geteuid())
	}
	if uid <= 0 {
		return fmt.Errorf("invalid client uid: %d", uid)
	}
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("socket directory: %w", err)
	}

	if err := os.Chown(dir, uid, os.Getegid()); err != nil {
		return fmt.Errorf("socket directory owner: %w", err)
	}

	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		return fmt.Errorf("cannot determine own path: %w", err)
	}
	devnull, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer devnull.Close()

	cmd := exec.Command(exe, "--system-helper",
		"--system-helper-uid", strconv.Itoa(uid),
		"--system-helper-socket", socketPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, devnull, devnull
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start the helper: %w", err)
	}
	go cmd.Wait()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := os.Lstat(socketPath); err == nil && st.Mode()&os.ModeSocket != 0 {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return errors.New("the helper did not come up within 5 seconds")
}

func RunHelper(uid int, socketPath string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("the helper must run as root (current euid=%d)", os.Geteuid())
	}
	if uid <= 0 {
		return fmt.Errorf("invalid client uid: %d", uid)
	}
	if err := os.MkdirAll(filepath.Dir(socketPath), 0o700); err != nil {
		return fmt.Errorf("socket directory: %w", err)
	}

	if st, err := os.Lstat(socketPath); err == nil && st.Mode()&os.ModeSocket != 0 {
		os.Remove(socketPath)
	}

	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listen on the socket: %w", err)
	}
	defer ln.Close()
	// Remove the socket file on exit: the client decides whether the helper
	// is alive by its presence.
	defer os.Remove(socketPath)
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return fmt.Errorf("socket mode: %w", err)
	}
	if err := os.Chown(socketPath, uid, os.Getegid()); err != nil {
		return fmt.Errorf("socket owner: %w", err)
	}

	// One-shot helper: it serves exactly one request (the command the user
	// just entered the password for) and exits. Every privileged action in
	// the System tab therefore asks for the password again via pkexec —
	// no long-lived root process for an antivirus to trip over.
	_ = ln.(*net.UnixListener).SetDeadline(time.Now().Add(helperStartTimeout))
	conn, err := ln.Accept()
	if err != nil {
		return fmt.Errorf("accept connection: %w", err)
	}
	serveConnection(conn, uid)
	return nil
}

func serveConnection(conn net.Conn, wantUID int) {
	defer conn.Close()
	un, ok := conn.(*net.UnixConn)
	if !ok {
		writeResponse(conn, response{Err: "not a local socket"})
		return
	}
	raw, err := un.SyscallConn()
	if err != nil {
		writeResponse(conn, response{Err: err.Error()})
		return
	}
	var peerUID int
	rawErr := raw.Control(func(fd uintptr) {
		u, e := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if e == nil {
			peerUID = int(u.Uid)
		}
	})
	if rawErr != nil || peerUID != wantUID {
		writeResponse(conn, response{Err: fmt.Sprintf("connection is not from uid %d", wantUID)})
		return
	}

	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 64*1024), 64*1024)
	if !sc.Scan() {
		return
	}
	var req request
	if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
		writeResponse(conn, response{Err: "unreadable request: " + err.Error()})
		return
	}
	if req.Ping {
		writeResponse(conn, response{Stdout: "pong", Code: 0})
		return
	}

	writeResponse(conn, runCommand(req.Spec))
}

func runCommand(spec Spec) response {
	if err := spec.Validate(); err != nil {
		return response{Err: err.Error(), Code: -1}
	}

	switch spec.Program {
	case "deadeye-blacklist":
		return blacklistModule(spec.Args, true)
	case "deadeye-unblacklist":
		return blacklistModule(spec.Args, false)
	}

	ctx, cancel := context.WithTimeout(context.Background(), spec.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, spec.Program, spec.Args...)

	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8"}
	cmd.Dir = "/"

	var out, errb limitedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &errb

	runErr := cmd.Run()
	code := 0
	if runErr != nil {
		if ee, ok := runErr.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else if ctx.Err() != nil {
			return response{Err: "timed out: " + ctx.Err().Error(), Code: -1}
		} else {
			return response{Err: runErr.Error(), Code: -1}
		}
	}
	return response{
		Stdout: strings.TrimRight(out.String(), "\n"),
		Stderr: strings.TrimRight(errb.String(), "\n"),
		Code:   code,
	}
}

func validModuleName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

func blacklistModule(args []string, enable bool) response {
	if len(args) != 1 || !validModuleName(args[0]) {
		return response{Err: "need a valid module name (letters, digits, - and _)", Code: -1}
	}
	mod := args[0]
	path := "/etc/modprobe.d/blacklist-" + mod + ".conf"

	if !enable {
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				return response{Stdout: "module " + mod + " was not blacklisted", Code: 0}
			}
			return response{Err: err.Error(), Code: -1}
		}
		return response{Stdout: "module " + mod + " removed from the blacklist (" + path + ")", Code: 0}
	}

	content := "# created by Deadeye (System tab)\nblacklist " + mod + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return response{Err: err.Error(), Code: -1}
	}
	return response{
		Stdout: "driver " + mod + " added to the blacklist: " + path +
			". Takes effect after a reboot (or modprobe -r " + mod + " now).",
		Code: 0,
	}
}

func writeResponse(conn net.Conn, resp response) {
	enc := json.NewEncoder(conn)
	_ = enc.Encode(resp)
}

type limitedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
	n  int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	orig := len(p)
	if l.n >= maxOutBytes {
		return orig, nil
	}
	room := maxOutBytes - l.n
	if len(p) > room {
		p = p[:room]
	}
	l.n += len(p)
	l.b.Write(p)
	return orig, nil
}

func (l *limitedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.b.String()
	if l.n >= maxOutBytes {
		s += "\n…output trimmed to " + strconv.Itoa(maxOutBytes/1024) + " KiB"
	}
	return s
}
