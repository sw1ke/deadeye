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
	"sync"
	"time"
)

var ErrNotAuthorized = errors.New("root rights have not been granted yet")

type Runner struct {
	uid        int
	socketPath string
	selfExe    string
	logf       func(action, detail string)

	mu         sync.Mutex
	authorized bool
}

func NewRunner(socketPath string, logf func(action, detail string)) *Runner {
	r := &Runner{uid: os.Getuid(), socketPath: socketPath, logf: logf}
	if r.uid == 0 {
		r.socketPath = "/run/deadeye-helper.sock"
	} else if r.socketPath == "" {
		base := os.Getenv("XDG_RUNTIME_DIR")
		if base == "" {
			base = "/run/user/" + strconv.Itoa(r.uid)
		}
		r.socketPath = filepath.Join(base, "deadeye-helper.sock")
	}
	r.selfExe, _ = os.Readlink("/proc/self/exe")
	return r
}

func (r *Runner) Authorized() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.authorized
}

func (r *Runner) StartCmd() *exec.Cmd {
	return exec.Command("pkexec", r.selfExe, "--system-helper-start",
		"--system-helper-uid", strconv.Itoa(r.uid),
		"--system-helper-socket", r.socketPath)
}

func (r *Runner) FinishStart(runErr error) error {
	if runErr != nil {
		return fmt.Errorf("pkexec did not run: %w", runErr)
	}
	if !r.socketAlive() {
		return errors.New("the helper did not come up after entering root")
	}
	r.mu.Lock()
	r.authorized = true
	r.mu.Unlock()
	return nil
}

// Refresh re-reads the helper state: with a one-shot helper the socket file
// exists only while the helper is waiting for a command.
func (r *Runner) Refresh() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.authorized = r.socketAlive()
}

func (r *Runner) socketAlive() bool {
	st, err := os.Lstat(r.socketPath)
	return err == nil && st.Mode()&os.ModeSocket != 0
}

func (r *Runner) Run(ctx context.Context, spec Spec) (Result, error) {
	if err := spec.Validate(); err != nil {
		return Result{}, err
	}
	r.mu.Lock()
	authed := r.authorized
	r.mu.Unlock()
	if !authed && !r.socketAlive() {
		return Result{}, ErrNotAuthorized
	}
	res, err := r.request(ctx, spec)
	if err == nil {
		// The helper serves exactly one command and exits; the next
		// privileged action will prompt for the password again.
		r.mu.Lock()
		r.authorized = false
		r.mu.Unlock()
	}
	return res, err
}

func (r *Runner) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.authorized = false
}

func (r *Runner) request(ctx context.Context, spec Spec) (Result, error) {
	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(ctx, "unix", r.socketPath)
	if err != nil {
		return Result{}, fmt.Errorf("connection to the helper: %w", err)
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	} else {
		_ = conn.SetDeadline(time.Now().Add(spec.Timeout + 5*time.Second))
	}

	req := request{Spec: spec}
	if spec.Program == "systemctl" && spec.Title == "ping" {
		req = request{Ping: true}
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Result{}, err
	}
	var resp response
	if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&resp); err != nil {
		return Result{}, fmt.Errorf("helper response: %w", err)
	}
	if resp.Err != "" {
		return Result{Err: resp.Err}, errors.New(resp.Err)
	}
	if r.logf != nil && spec.HasSideEffects() {
		r.logf(spec.Title, fmt.Sprintf("%s %s", spec.Program, joinArgs(spec.Args)))
	}
	return Result{
		Spec:   spec,
		Stdout: resp.Stdout,
		Stderr: resp.Stderr,
		Code:   resp.Code,
	}, nil
}

func joinArgs(args []string) string {
	out := ""
	for i, a := range args {
		if i > 0 {
			out += " "
		}
		out += a
	}
	return out
}
